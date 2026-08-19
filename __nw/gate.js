/* Northwind gate - passphrase unlock.
 *
 * Derives a key-encryption-key from the passphrase, unwraps the random
 * AES-256 master key, decrypts the manifest, and hands the master key to the
 * Service Worker as a non-extractable CryptoKey. Nothing here ever sees the
 * master key as raw bytes after import, and the passphrase never leaves the
 * page.
 */

(function () {
  'use strict';

  var TAG = 16;
  var KEY_URL = '/__nw/key.json';

  var el = function (id) { return document.getElementById(id); };

  /* ------------------------------------------------------------- helpers */

  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function nonceFor(fid, index) {
    var n = new Uint8Array(12);
    n.set(fid, 0);
    new DataView(n.buffer).setUint32(8, index, false);
    return n;
  }

  /** Decrypt a small chunked payload held entirely in memory. */
  async function decryptAll(bytes, key, fid, chunkSize) {
    var encChunk = chunkSize + TAG;
    var out = [];
    var index = 0;
    var pos = 0;
    while (pos < bytes.length) {
      var take = Math.min(encChunk, bytes.length - pos);
      var plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonceFor(fid, index), tagLength: TAG * 8 },
        key, bytes.subarray(pos, pos + take)
      );
      out.push(new Uint8Array(plain));
      pos += take;
      index++;
    }
    var total = out.reduce(function (a, b) { return a + b.length; }, 0);
    var merged = new Uint8Array(total);
    var off = 0;
    out.forEach(function (b) { merged.set(b, off); off += b.length; });
    return merged;
  }

  /** Inflate the manifest, which is gzipped before encryption. */
  async function gunzip(bytes) {
    if (typeof DecompressionStream !== 'function') {
      throw new Error('this browser cannot decompress the catalogue');
    }
    var stream = new Response(bytes).body.pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function fetchParts(parts) {
    var buffers = [];
    for (var i = 0; i < parts.length; i++) {
      var res = await fetch('/' + parts[i][0], { cache: 'force-cache' });
      if (!res.ok) throw new Error('missing data part');
      buffers.push(new Uint8Array(await res.arrayBuffer()));
    }
    var total = buffers.reduce(function (a, b) { return a + b.length; }, 0);
    var merged = new Uint8Array(total);
    var off = 0;
    buffers.forEach(function (b) { merged.set(b, off); off += b.length; });
    return merged;
  }

  /* ---------------------------------------------------------------- state */

  var swReg = null;
  var lastFiles = [];

  /**
   * Show what the desk can reach. If the library carries its own homepage,
   * hand straight over to it - from this point the worker serves the real
   * site at the same URLs the Northwind page was occupying.
   */
  function reveal(files) {
    if (files.indexOf('index.html') !== -1) {
      location.replace('/');
      return;
    }
    markUnlocked(files.length);
    var grid = el('lib-grid');
    if (!grid) return;

    // Treat "<section>/<title>/index.html" as a launchable entry point.
    var entries = [];
    files.forEach(function (p) {
      var m = /^([^/]+)\/([^/]+)\/index\.html$/.exec(p);
      if (m) entries.push({ href: '/' + p, name: m[2], group: m[1] });
    });
    if (!entries.length) {
      files.forEach(function (p) {
        if (/\.html$/.test(p)) entries.push({ href: '/' + p, name: p, group: '' });
      });
    }
    entries.sort(function (a, b) { return a.name.localeCompare(b.name); });

    grid.innerHTML = '';
    entries.forEach(function (it) {
      var a = document.createElement('a');
      a.className = 'lib-item';
      a.href = it.href;
      a.textContent = it.name;
      var s = document.createElement('span');
      s.textContent = it.group;
      a.appendChild(s);
      grid.appendChild(a);
    });
  }

  function post(msg, transfer) {
    var target = (swReg && swReg.active) || navigator.serviceWorker.controller;
    if (target) target.postMessage(msg, transfer || []);
  }

  /* --------------------------------------------------------------- unlock */

  async function unlock(passphrase, remember) {
    Loader.begin();

    Loader.stage('Establishing session');
    var keyDoc = await (await fetch(KEY_URL, { cache: 'no-store' })).json();

    // PBKDF2 is deliberately slow; this is the wall an offline guesser hits.
    Loader.stage('Verifying counterparty signature');
    await Loader.paint();

    var base = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveBits']
    );
    var kekBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: hexToBytes(keyDoc.salt),
        iterations: keyDoc.iters,
        hash: 'SHA-256'
      },
      base, 256
    );
    var kek = await crypto.subtle.importKey(
      'raw', kekBits, 'AES-GCM', false, ['decrypt']
    );

    Loader.stage('Unwrapping desk credentials');
    var masterRaw;
    try {
      masterRaw = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBytes(keyDoc.nonce), tagLength: TAG * 8 },
        kek, hexToBytes(keyDoc.wrapped)
      );
    } catch (e) {
      Loader.fail();
      throw new Error('bad-passphrase');
    }

    // Non-extractable: from here on the key can be used but never read out.
    var master = await crypto.subtle.importKey(
      'raw', masterRaw, 'AES-GCM', false, ['decrypt']
    );
    masterRaw = null;

    Loader.stage('Loading instrument catalogue');
    var md = keyDoc.manifest;
    var manifestBytes = await fetchParts(md.p);
    var manifestJson = await decryptAll(
      manifestBytes, master, hexToBytes(md.f), keyDoc.chunk
    );
    if (md.z === 'gzip') manifestJson = await gunzip(manifestJson);
    var manifest = JSON.parse(new TextDecoder().decode(manifestJson));

    Loader.stage('Opening terminal');
    lastFiles = Object.keys(manifest.files);
    post({ type: 'unlock', key: master, manifest: manifest, remember: remember });

    return manifest;
  }

  /* -------------------------------------------------------------- lockout */

  /* Rate limit on repeated failures: three free attempts, then 15s, doubling
   * each further failure.
   *
   * Scope note, so this is not mistaken for more than it is: an offline
   * attacker works from the downloaded ciphertext and never runs this code,
   * so the delay does nothing against them - only passphrase strength does.
   * What this does stop is someone sitting at an unlocked-looking browser
   * trying passwords by hand.
   */
  var FREE_ATTEMPTS = 3;
  var BASE_DELAY = 15;          // seconds
  var MAX_DELAY = 3600;         // an hour is already past any practical point
  var LS_FAILS = 'nw.fails';
  var LS_UNTIL = 'nw.until';
  var tickTimer = null;

  function store(k, v) {
    try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); }
    catch (e) { /* private mode: fall back to in-memory only */ }
  }

  function read(k) {
    try { return localStorage.getItem(k); } catch (e) { return null; }
  }

  function fails() { return parseInt(read(LS_FAILS) || '0', 10) || 0; }
  function lockedUntil() { return parseInt(read(LS_UNTIL) || '0', 10) || 0; }
  function secondsLeft() { return Math.max(0, Math.ceil((lockedUntil() - Date.now()) / 1000)); }

  function noteFailure() {
    var n = fails() + 1;
    store(LS_FAILS, String(n));
    if (n > FREE_ATTEMPTS) {
      var delay = Math.min(MAX_DELAY, BASE_DELAY * Math.pow(2, n - FREE_ATTEMPTS - 1));
      store(LS_UNTIL, String(Date.now() + delay * 1000));
    }
    refreshLock();
  }

  function clearFailures() {
    store(LS_FAILS, null);
    store(LS_UNTIL, null);
    refreshLock();
  }

  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

  /** Disable the form while locked and count down in place. */
  function refreshLock() {
    var btn = el('gate-btn');
    var input = el('code');
    var left = secondsLeft();

    if (left > 0) {
      if (btn) {
        btn.disabled = true;
        btn.textContent = left >= 60
          ? 'Locked - ' + plural(Math.ceil(left / 60), 'minute')
          : 'Locked - ' + plural(left, 'second');
      }
      if (input) input.disabled = true;
      showError('Too many failed attempts. Try again in ' +
        (left >= 60 ? plural(Math.ceil(left / 60), 'minute') : plural(left, 'second')) + '.');
      if (!tickTimer) tickTimer = setInterval(refreshLock, 1000);
    } else {
      if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
      if (btn) { btn.disabled = false; btn.textContent = 'Sign in'; }
      if (input) input.disabled = false;
    }
  }

  /* ----------------------------------------------------------------- boot */

  async function boot() {
    if (!('serviceWorker' in navigator)) {
      showError('This browser cannot open the terminal (no Service Worker support).');
      return;
    }
    if (!window.isSecureContext) {
      showError('The terminal requires a secure (https) connection.');
      return;
    }

    try {
      swReg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
      await navigator.serviceWorker.ready;
    } catch (e) {
      showError('Session worker failed to start: ' + e.message);
      return;
    }

    navigator.serviceWorker.addEventListener('message', function (e) {
      var msg = e.data || {};
      if (msg.type === 'unlocked') {
        Loader.done(msg.count);
        reveal(lastFiles);
      } else if (msg.type === 'status' && msg.unlocked) {
        markUnlocked(msg.count);
        reveal(msg.files || []);
      } else if (msg.type === 'decrypt-start') {
        Loader.assetStart(msg.path, msg.total);
      } else if (msg.type === 'progress') {
        Loader.assetProgress(msg.done, msg.total);
      }
    });

    post({ type: 'status' });

    refreshLock();

    var form = el('gate-form');
    form.addEventListener('submit', async function (ev) {
      ev.preventDefault();
      if (secondsLeft() > 0) { refreshLock(); return; }

      var pass = el('code').value;
      if (!pass) return;
      hideError();
      try {
        await unlock(pass, el('remember').checked);
        clearFailures();
      } catch (err) {
        if (err.message === 'bad-passphrase') {
          noteFailure();
          if (secondsLeft() === 0) {
            var left = FREE_ATTEMPTS - fails();
            showError('Those credentials were not recognised.' +
              (left > 0 ? ' ' + plural(left, 'attempt') + ' remaining.' : ''));
          }
        } else {
          showError('Terminal unavailable: ' + err.message);
        }
        el('code').value = '';
        if (!el('code').disabled) el('code').focus();
      }
    });

    var lock = el('lock-btn');
    if (lock) {
      lock.addEventListener('click', function () {
        post({ type: 'lock' });
        setTimeout(function () { location.reload(); }, 150);
      });
    }
  }

  function showError(text) {
    var n = el('err');
    n.textContent = text;
    n.classList.remove('hide');
  }

  function hideError() { el('err').classList.add('hide'); }

  function markUnlocked(count) {
    document.body.classList.add('is-unlocked');
    var n = el('unlocked-count');
    if (n) n.textContent = count;
  }

  window.NWGate = { markUnlocked: markUnlocked };

  // Do not wait on DOMContentLoaded unconditionally: if this script is served
  // from cache it can execute after that event has already fired, and the
  // sign-in handler would then never be attached.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
