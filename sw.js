/* Northwind gate - streaming decryption Service Worker.
 *
 * Every request for a protected path is served by pulling ciphertext parts,
 * decrypting them one 4 MiB chunk at a time and piping the plaintext out
 * through a ReadableStream. Peak memory is therefore a couple of chunks
 * rather than the whole file, which is what makes 60-100 MB games survive
 * on a low-end Chromebook.
 *
 * The master key is held as a non-extractable CryptoKey. It is persisted in
 * IndexedDB because a Service Worker is terminated whenever it goes idle;
 * without that the session would drop every time the browser reclaimed it.
 * Non-extractable means script can use the key but can never read its bytes.
 */

const TAG = 16;
const DB_NAME = 'northwind';
const STORE = 'session';

let state = null;          // { key: CryptoKey, manifest: {...} }
let loading = null;

/* ---------------------------------------------------------------- storage */

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(k, v) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(v, k);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function idbGet(k) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(k);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbClear() {
  const db = await idb();
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    tx.oncomplete = resolve;
  });
}

/** Rehydrate after the browser has terminated and restarted this worker. */
function restore() {
  if (state) return Promise.resolve(state);
  if (!loading) {
    loading = (async () => {
      const key = await idbGet('key');
      const manifest = await idbGet('manifest');
      if (key && manifest) state = { key, manifest };
      loading = null;
      return state;
    })();
  }
  return loading;
}

/* ------------------------------------------------------------------ crypto */

/** 12-byte GCM nonce: 8 per-file bytes then a big-endian chunk counter. */
function nonceFor(fid, index) {
  const n = new Uint8Array(12);
  n.set(fid, 0);
  new DataView(n.buffer).setUint32(8, index, false);
  return n;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/* ------------------------------------------------------------ part reading */

/**
 * Read a byte range of the logical ciphertext stream, which is stored as a
 * sequence of part files. Yields Uint8Arrays in order.
 */
async function* readCipher(parts, from, to) {
  let cursor = 0;
  for (const [name, size] of parts) {
    const partStart = cursor;
    const partEnd = cursor + size;
    cursor = partEnd;
    if (partEnd <= from) continue;
    if (partStart >= to) break;

    const lo = Math.max(from, partStart) - partStart;
    const hi = Math.min(to, partEnd) - partStart;

    const headers = {};
    const whole = lo === 0 && hi === size;
    if (!whole) headers.Range = `bytes=${lo}-${hi - 1}`;

    const res = await fetch('/' + name, { headers, cache: 'force-cache' });
    if (!res.ok && res.status !== 206) throw new Error(`part ${name}: HTTP ${res.status}`);

    // If the host ignored the Range header, trim client-side.
    if (!whole && res.status !== 206) {
      const buf = new Uint8Array(await res.arrayBuffer());
      yield buf.subarray(lo, hi);
      continue;
    }
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      yield value;
    }
  }
}

/**
 * Decrypt a plaintext byte range of a file into a ReadableStream.
 * `chunk` is the plaintext chunk size the bundle was built with.
 */
function decryptStream(meta, key, chunkSize, start, end, onProgress) {
  const encChunk = chunkSize + TAG;
  const fid = hexToBytes(meta.f);

  const first = Math.floor(start / chunkSize);
  const last = Math.floor((end - 1) / chunkSize);
  const from = first * encChunk;
  const to = Math.min((last + 1) * encChunk, totalCipherBytes(meta));

  const src = readCipher(meta.p, from, to);
  let pending = new Uint8Array(0);
  let index = first;
  let emitted = 0;               // plaintext bytes produced so far
  let skip = start - first * chunkSize;   // trim head of the first chunk
  let remaining = end - start;

  return new ReadableStream({
    async pull(controller) {
      for (;;) {
        // Enough buffered for one whole chunk?
        const isLast = index === last;
        const need = isLast ? Math.min(encChunk, to - from - (index - first) * encChunk)
                            : encChunk;
        if (pending.length >= need) {
          const slice = pending.subarray(0, need);
          pending = pending.subarray(need);
          let plain;
          try {
            plain = new Uint8Array(await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: nonceFor(fid, index), tagLength: TAG * 8 },
              key, slice
            ));
          } catch (e) {
            controller.error(new Error('decryption failed (wrong key or corrupt data)'));
            return;
          }
          index++;
          let out = plain;
          if (skip) { out = out.subarray(skip); skip = 0; }
          if (out.length > remaining) out = out.subarray(0, remaining);
          remaining -= out.length;
          emitted += out.length;
          if (onProgress) onProgress(emitted);
          controller.enqueue(out);
          if (remaining <= 0 || index > last) controller.close();
          return;
        }

        const { done, value } = await src.next();
        if (done) {
          if (pending.length === 0) { controller.close(); return; }
          // Trailing short chunk.
          const slice = pending;
          pending = new Uint8Array(0);
          try {
            const plain = new Uint8Array(await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: nonceFor(fid, index), tagLength: TAG * 8 },
              key, slice
            ));
            let out = plain;
            if (skip) { out = out.subarray(skip); skip = 0; }
            if (out.length > remaining) out = out.subarray(0, remaining);
            controller.enqueue(out);
          } catch (e) {
            controller.error(new Error('decryption failed'));
            return;
          }
          controller.close();
          return;
        }
        const merged = new Uint8Array(pending.length + value.length);
        merged.set(pending, 0);
        merged.set(value, pending.length);
        pending = merged;
      }
    }
  });
}

function totalCipherBytes(meta) {
  return meta.p.reduce((a, [, size]) => a + size, 0);
}

/* ------------------------------------------------------------- resolution */

/** Map a URL path onto a manifest entry, handling directory indexes. */
function resolve(manifest, pathname) {
  let p = decodeURIComponent(pathname).replace(/^\/+/, '');
  const files = manifest.files;
  if (files[p]) return p;
  if (p === '' || p.endsWith('/')) {
    const idx = p + 'index.html';
    if (files[idx]) return idx;
  } else if (files[p + '/index.html']) {
    return p + '/index.html';
  }
  return null;
}

async function broadcast(msg) {
  const clients = await self.clients.matchAll({ includeUncontrolled: true });
  for (const c of clients) c.postMessage(msg);
}

/* -------------------------------------------------------------- lifecycle */

self.addEventListener('install', (e) => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (e) => {
  const msg = e.data || {};
  const reply = (payload) => e.source && e.source.postMessage(payload);

  if (msg.type === 'unlock') {
    state = { key: msg.key, manifest: msg.manifest };
    const persist = msg.remember
      ? Promise.all([idbSet('key', msg.key), idbSet('manifest', msg.manifest)])
      : Promise.resolve();
    e.waitUntil(persist.then(() => reply({ type: 'unlocked', count: Object.keys(msg.manifest.files).length })));
  } else if (msg.type === 'lock') {
    state = null;
    e.waitUntil(idbClear().then(() => reply({ type: 'locked' })));
  } else if (msg.type === 'status') {
    e.waitUntil(restore().then((s) => reply({
      type: 'status',
      unlocked: !!s,
      count: s ? Object.keys(s.manifest.files).length : 0,
      files: s ? Object.keys(s.manifest.files) : []
    })));
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  // The gate's own assets and the raw blobs must never be intercepted.
  if (/^\/(sw\.js|__nw\/|d\/)/.test(url.pathname)) return;

  event.respondWith((async () => {
    const s = await restore();
    if (!s) return fetch(event.request);       // locked: fall through to the Northwind page

    const rel = resolve(s.manifest, url.pathname);
    if (!rel) return fetch(event.request);

    const meta = s.manifest.files[rel];
    const chunkSize = s.manifest.chunk;
    const size = meta.s;

    // Honour Range requests: the fixed plaintext chunk size makes the
    // required ciphertext window directly computable.
    const range = event.request.headers.get('range');
    let start = 0, end = size, status = 200;
    const headers = {
      'Content-Type': meta.t,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store',
    };

    if (range) {
      const m = /bytes=(\d*)-(\d*)/.exec(range);
      if (m) {
        start = m[1] ? parseInt(m[1], 10) : 0;
        end = m[2] ? Math.min(parseInt(m[2], 10) + 1, size) : size;
        if (start >= size || start >= end) {
          return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}` } });
        }
        status = 206;
        headers['Content-Range'] = `bytes ${start}-${end - 1}/${size}`;
      }
    }
    headers['Content-Length'] = String(end - start);

    const big = size > 8 * 1024 * 1024;
    let lastPost = 0;
    const onProgress = big ? (done) => {
      const now = Date.now();
      if (now - lastPost > 120) {
        lastPost = now;
        broadcast({ type: 'progress', path: rel, done, total: end - start });
      }
    } : null;

    if (big) broadcast({ type: 'decrypt-start', path: rel, total: end - start });

    try {
      const stream = decryptStream(meta, s.key, chunkSize, start, end, onProgress);

      // Game pages are the original site's HTML and carry none of our script,
      // so the loading screen is injected here. Only small documents are
      // buffered for this; anything large streams through untouched.
      if (!range && meta.t.indexOf('text/html') === 0 && size < 2 * 1024 * 1024) {
        const text = await new Response(stream).text();
        const tag = '<script src="/__nw/loader.js"></script>';
        let html;
        const head = text.match(/<head[^>]*>/i);
        if (head) {
          const at = head.index + head[0].length;
          html = text.slice(0, at) + tag + text.slice(at);
        } else {
          html = tag + text;
        }
        delete headers['Content-Length'];
        return new Response(html, { status: 200, headers });
      }

      return new Response(stream, { status, headers });
    } catch (err) {
      return new Response('gate error: ' + err.message, { status: 500 });
    }
  })());
});
