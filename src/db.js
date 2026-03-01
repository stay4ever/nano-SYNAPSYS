/**
 * src/db.js — SQLCipher local database for SYNAPTYC
 * Uses @op-engineering/op-sqlite with SQLCipher encryption.
 * DB key is derived independently from Signal keys and stored in SecureStore.
 */

// eslint-disable-next-line import/no-commonjs
const { open } = require('@op-engineering/op-sqlite');
const SecureStore = require('expo-secure-store');

const DB_KEY_STORE = 'synaptyc_db_key_v1';

async function getDbKey() {
  let raw = await SecureStore.getItemAsync(DB_KEY_STORE);
  if (!raw) {
    const bytes = new Uint8Array(32);
    // Use global crypto (Hermes supports it since RN 0.73+)
    global.crypto.getRandomValues(bytes);
    raw = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    await SecureStore.setItemAsync(DB_KEY_STORE, raw);
  }
  return raw; // 64-char hex string used as SQLCipher passphrase
}

let _db = null;

/**
 * Open (or return cached) the encrypted SQLite database.
 * Creates all tables on first run.
 */
async function openDb() {
  if (_db) return _db;

  const key = await getDbKey();
  _db = open({ name: 'synaptyc.db', encryptionKey: key });

  // Core messages table
  await _db.executeAsync(`
    CREATE TABLE IF NOT EXISTS messages (
      id          INTEGER PRIMARY KEY,
      convo_key   TEXT    NOT NULL,
      from_id     TEXT    NOT NULL,
      content     TEXT,
      is_media    INTEGER DEFAULT 0,
      media_url   TEXT,
      created_at  TEXT    NOT NULL
    )
  `);

  // Index for fast per-conversation load
  await _db.executeAsync(`
    CREATE INDEX IF NOT EXISTS idx_msg_convo
    ON messages(convo_key, created_at)
  `);

  // Full-text search index on content column (LIKE-based; no FTS5 required)
  await _db.executeAsync(`
    CREATE INDEX IF NOT EXISTS idx_msg_content
    ON messages(content)
  `);

  // Sync cursors — track last seen message ID per conversation
  await _db.executeAsync(`
    CREATE TABLE IF NOT EXISTS sync_cursors (
      convo_key   TEXT    PRIMARY KEY,
      last_msg_id INTEGER DEFAULT 0
    )
  `);

  return _db;
}

/**
 * Bulk-insert messages for a conversation (OR IGNORE duplicate IDs).
 * msgs: array of objects with { id, from_id|from_user, content, created_at }
 */
async function upsertMessages(convoKey, msgs) {
  if (!msgs || msgs.length === 0) return;
  const db = await openDb();
  await db.executeAsync('BEGIN');
  try {
    for (const m of msgs) {
      const fromId = String(m.from_id ?? m.from_user?.id ?? m.from_user ?? m.from ?? '');
      const content = m.content ?? null;
      const isMedia = typeof content === 'string' && content.startsWith('{"type":"media"') ? 1 : 0;
      const mediaUrl = isMedia ? (() => {
        try { return JSON.parse(content).url ?? null; } catch { return null; }
      })() : null;
      await db.executeAsync(
        `INSERT OR IGNORE INTO messages
           (id, convo_key, from_id, content, is_media, media_url, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [m.id, convoKey, fromId, content, isMedia, mediaUrl, m.created_at ?? new Date().toISOString()]
      );
    }
    await db.executeAsync('COMMIT');
  } catch (e) {
    await db.executeAsync('ROLLBACK');
    throw e;
  }
}

/**
 * Get the last synced message ID for a conversation.
 * Returns 0 if no cursor exists yet.
 */
async function getLastMsgId(convoKey) {
  const db = await openDb();
  const result = await db.executeAsync(
    'SELECT last_msg_id FROM sync_cursors WHERE convo_key = ?',
    [convoKey]
  );
  const rows = result?.rows?._array ?? result?.rows ?? [];
  return rows[0]?.last_msg_id ?? 0;
}

/**
 * Update the sync cursor for a conversation to a new high-water mark.
 */
async function updateCursor(convoKey, maxMsgId) {
  const db = await openDb();
  await db.executeAsync(
    `INSERT INTO sync_cursors(convo_key, last_msg_id) VALUES (?, ?)
     ON CONFLICT(convo_key) DO UPDATE SET last_msg_id = excluded.last_msg_id
     WHERE excluded.last_msg_id > sync_cursors.last_msg_id`,
    [convoKey, maxMsgId]
  );
}

/**
 * Search messages using LIKE (no FTS5 required).
 * Returns array of { id, convo_key, content, from_id, created_at } ordered by date.
 */
async function searchMessages(query) {
  if (!query || !query.trim()) return [];
  const db = await openDb();
  const pattern = `%${query.trim().replace(/[%_]/g, '\\$&')}%`;
  const result = await db.executeAsync(
    `SELECT id, convo_key, content, from_id, created_at
     FROM messages
     WHERE content LIKE ? ESCAPE '\\'
     ORDER BY created_at DESC
     LIMIT 50`,
    [pattern]
  );
  return result?.rows?._array ?? result?.rows ?? [];
}

/**
 * Load local messages for a conversation (newest-first, then reversed for display).
 */
async function getLocalMessages(convoKey, limit = 100) {
  const db = await openDb();
  const result = await db.executeAsync(
    `SELECT id, convo_key, from_id, content, is_media, media_url, created_at
     FROM messages
     WHERE convo_key = ?
     ORDER BY created_at DESC
     LIMIT ?`,
    [convoKey, limit]
  );
  const rows = result?.rows?._array ?? result?.rows ?? [];
  return rows.reverse(); // chronological order for display
}

/**
 * Persist a single incoming WS message (after it's been decrypted).
 */
async function persistMessage(convoKey, msgId, fromId, plaintext, createdAt) {
  const db = await openDb();
  const isMedia = typeof plaintext === 'string' && plaintext.startsWith('{"type":"media"') ? 1 : 0;
  const mediaUrl = isMedia ? (() => {
    try { return JSON.parse(plaintext).url ?? null; } catch { return null; }
  })() : null;
  await db.executeAsync(
    `INSERT INTO messages
       (id, convo_key, from_id, content, is_media, media_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       content   = excluded.content,
       is_media  = excluded.is_media,
       media_url = excluded.media_url`,
    [msgId, convoKey, String(fromId), plaintext, isMedia, mediaUrl, createdAt ?? new Date().toISOString()]
  );
  // Update cursor if this is a new high-water mark
  await updateCursor(convoKey, msgId);
}

/**
 * Get a single message by convo_key and msg_id.
 * Returns { id, content, from_id, created_at } or null.
 */
async function getMessage(convoKey, msgId) {
  const db = await openDb();
  const result = await db.executeAsync(
    `SELECT id, content, from_id, created_at FROM messages WHERE convo_key = ? AND id = ? LIMIT 1`,
    [convoKey, String(msgId)]
  );
  const rows = result?.rows?._array ?? result?.rows ?? [];
  return rows.length > 0 ? rows[0] : null;
}

/**
 * Delete all messages and sync cursor for a conversation.
 */
async function deleteConversation(convoKey) {
  const db = await openDb();
  await db.executeAsync(`DELETE FROM messages WHERE convo_key = ?`, [convoKey]);
  await db.executeAsync(`DELETE FROM sync_cursors WHERE convo_key = ?`, [convoKey]);
}

module.exports = {
  openDb,
  upsertMessages,
  getLastMsgId,
  updateCursor,
  searchMessages,
  getLocalMessages,
  persistMessage,
  getMessage,
  deleteConversation,
};
