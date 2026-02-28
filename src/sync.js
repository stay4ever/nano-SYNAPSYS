/**
 * src/sync.js — Delta sync layer for SYNAPTYC
 * Fetches messages since the last stored cursor from the Elixir backend,
 * decrypts them, and persists them to the local SQLCipher database.
 */

const { upsertMessages, getLastMsgId, updateCursor, persistMessage } = require('./db');

const BASE_URL = 'https://nano-synapsys-server.fly.dev';

async function apiFetch(path, token) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return [];
  return res.json().catch(() => []);
}

/**
 * Sync new DM messages since the last cursor.
 * decryptFn: async (envelopeStr, senderId, token) => plaintext | null
 */
async function syncDM(peerId, token, decryptFn) {
  try {
    const lastId = await getLastMsgId(`dm_${peerId}`);
    const msgs = await apiFetch(`/api/messages/${peerId}?after_id=${lastId}`, token);
    if (!Array.isArray(msgs) || msgs.length === 0) return;

    const decrypted = await Promise.all(msgs.map(async (m) => {
      let content = m.content;
      try {
        const sid = String(m.from_user?.id ?? m.from_user ?? m.from ?? '');
        const plain = await decryptFn(m.content, sid, token);
        if (plain !== null) content = plain;
      } catch {}
      return { ...m, content };
    }));

    await upsertMessages(`dm_${peerId}`, decrypted);
    const maxId = Math.max(...msgs.map(m => m.id));
    if (maxId > 0) await updateCursor(`dm_${peerId}`, maxId);
  } catch (e) {
    console.warn('[Sync] syncDM error:', e?.message);
  }
}

/**
 * Sync new group messages since the last cursor.
 * decryptFn: async (envelopeStr, _unused, senderId, groupId) => plaintext | null
 */
async function syncGroup(groupId, token, decryptFn) {
  try {
    const lastId = await getLastMsgId(`group_${groupId}`);
    const msgs = await apiFetch(`/api/groups/${groupId}/messages?after_id=${lastId}`, token);
    if (!Array.isArray(msgs) || msgs.length === 0) return;

    const decrypted = await Promise.all(msgs.map(async (m) => {
      let content = m.content;
      try {
        const sid = String(m.from_user?.id ?? m.from_user ?? m.from ?? '');
        const plain = await decryptFn(m.content, null, sid, groupId);
        if (plain !== null) content = plain;
      } catch {}
      return { ...m, content };
    }));

    await upsertMessages(`group_${groupId}`, decrypted);
    const maxId = Math.max(...msgs.map(m => m.id));
    if (maxId > 0) await updateCursor(`group_${groupId}`, maxId);
  } catch (e) {
    console.warn('[Sync] syncGroup error:', e?.message);
  }
}

/**
 * Run a full sync pass for a set of DM peers and group IDs.
 * Called on WS connect/reconnect.
 */
async function syncOnConnect(token, dmPeerIds, groupIds, decryptDM, decryptGroup) {
  await Promise.allSettled([
    ...dmPeerIds.map(pid => syncDM(pid, token, decryptDM)),
    ...groupIds.map(gid => syncGroup(gid, token, decryptGroup)),
  ]);
}

/**
 * Persist a single incoming WS message after it has been decrypted in App.js.
 * convoKey: 'dm_{peerId}' | 'group_{groupId}'
 */
async function persistIncomingMessage(convoKey, msg, plaintext) {
  try {
    const fromId = String(msg.from_user?.id ?? msg.from_user ?? msg.from ?? '');
    await persistMessage(convoKey, msg.id, fromId, plaintext, msg.created_at);
  } catch (e) {
    console.warn('[Sync] persistIncomingMessage error:', e?.message);
  }
}

module.exports = {
  syncDM,
  syncGroup,
  syncOnConnect,
  persistIncomingMessage,
};
