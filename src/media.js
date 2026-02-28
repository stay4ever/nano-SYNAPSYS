/**
 * src/media.js — Cloudflare R2 encrypted media upload for SYNAPTYC
 *
 * Flow:
 *   1. Pick image → base64 from expo-image-picker
 *   2. Encrypt with AES-256-GCM (WebCrypto / Hermes SubtleCrypto)
 *   3. Request presigned PUT URL from Elixir backend
 *   4. PUT encrypted bytes directly to R2
 *   5. Share { url, key, iv } JSON payload, which is then Signal-encrypted
 *
 * Receiving:
 *   1. Signal-decrypt message → parse { type:"media", url, key, iv }
 *   2. Fetch R2 URL → AES-GCM decrypt → render as data URI
 *
 * Encrypted media is opaque to anyone without the AES key (even Cloudflare).
 */

const BASE_URL = 'https://nano-synapsys-server.fly.dev';

/**
 * Encrypt raw image bytes with AES-256-GCM.
 * Returns { cipherBytes: Uint8Array, key: base64, iv: base64 }
 */
async function encryptMedia(base64Data) {
  // Decode base64 → bytes
  const binaryStr = atob(base64Data);
  const raw = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) raw[i] = binaryStr.charCodeAt(i);

  // Generate random AES-256 key and 96-bit IV
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, raw);

  // Export key to base64
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const k64 = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
  const iv64 = btoa(String.fromCharCode(...iv));

  return { cipherBytes: new Uint8Array(cipherBuf), key: k64, iv: iv64 };
}

/**
 * Decrypt AES-256-GCM encrypted media fetched from R2.
 * Returns a data URI string (e.g. 'data:image/jpeg;base64,...').
 */
async function decryptMedia(url, key64, iv64) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`R2 fetch failed: ${res.status}`);
  const cipherBuf = await res.arrayBuffer();

  // Import key
  const rawKey = Uint8Array.from(atob(key64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);

  // Decrypt
  const iv = Uint8Array.from(atob(iv64), c => c.charCodeAt(0));
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBuf);

  // Convert to data URI (assume JPEG; actual type is stored in the URL extension if needed)
  const b64 = btoa(String.fromCharCode(...new Uint8Array(plainBuf)));
  return `data:image/jpeg;base64,${b64}`;
}

/**
 * Encrypt an image and upload it directly to Cloudflare R2.
 *
 * @param {string} base64Data - raw base64 image data (no prefix)
 * @param {string} mimeType   - e.g. 'image/jpeg'
 * @param {string} token      - Elixir JWT token for presign endpoint
 * @returns {{ url: string, key: string, iv: string }}
 */
async function uploadEncryptedMedia(base64Data, mimeType, token) {
  // 1. Get presigned PUT URL from Elixir backend
  const presignRes = await fetch(`${BASE_URL}/api/media/presign`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ mime: mimeType }),
  });
  if (!presignRes.ok) throw new Error(`Presign failed: ${presignRes.status}`);
  const { upload_url, public_url } = await presignRes.json();

  // 2. Encrypt locally
  const { cipherBytes, key, iv } = await encryptMedia(base64Data);

  // 3. Upload encrypted bytes directly to R2 (no auth needed — presigned)
  const uploadRes = await fetch(upload_url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: cipherBytes,
  });
  if (!uploadRes.ok) throw new Error(`R2 upload failed: ${uploadRes.status}`);

  return { url: public_url, key, iv };
}

/**
 * Build the JSON payload string for an encrypted media message.
 * This string is then passed to sendMessage(), which Signal-encrypts it.
 */
function mediaPayload(url, key, iv) {
  return JSON.stringify({ type: 'media', url, key, iv });
}

/**
 * Detect if a message content string is an encrypted media payload.
 */
function isMediaPayload(content) {
  if (typeof content !== 'string') return false;
  try {
    const obj = JSON.parse(content);
    return obj?.type === 'media' && typeof obj.url === 'string';
  } catch { return false; }
}

/**
 * Parse a media payload JSON string.
 * Returns { url, key, iv } or null.
 */
function parseMediaPayload(content) {
  try {
    const obj = JSON.parse(content);
    if (obj?.type === 'media' && obj.url && obj.key && obj.iv) return obj;
  } catch {}
  return null;
}

module.exports = {
  encryptMedia,
  decryptMedia,
  uploadEncryptedMedia,
  mediaPayload,
  isMediaPayload,
  parseMediaPayload,
};
