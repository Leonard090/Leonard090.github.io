/* Northwind gate - settlement blotter loading screen.
 *
 * Self-contained on purpose: the Service Worker injects this into decrypted
 * game pages, which have no stylesheet of ours, so it carries its own CSS and
 * touches no globals beyond window.Loader.
 *
 * The numbers on screen are real. The meter tracks bytes actually decrypted
 * and the throughput figure is measured, not decorative - which is what makes
 * it useful as well as on-theme.
 */

(function () {
  'use strict';
  if (window.Loader) return;

  var CSS = [
    '.nwl{position:fixed;inset:0;z-index:2147483600;display:none;',
    'background:radial-gradient(1200px 600px at 50% -10%,#101a2c 0%,#080b11 60%);',
    'color:#e8eef6;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Arial,sans-serif;}',
    '.nwl.on{display:flex;align-items:center;justify-content:center;}',
    '.nwl-box{width:min(560px,92vw);background:#131a26;border:1px solid #222d40;',
    'border-radius:10px;box-shadow:0 24px 80px rgba(0,0,0,.6);overflow:hidden}',
    '.nwl-head{display:flex;align-items:center;gap:10px;padding:14px 18px;',
    'border-bottom:1px solid #222d40;background:#0e131c}',
    '.nwl-mark{width:22px;height:22px;border-radius:5px;background:#3d7dff;color:#fff;',
    'display:grid;place-items:center;font-weight:700;font-size:13px}',
    '.nwl-title{font-weight:600;letter-spacing:.01em}',
    '.nwl-sub{margin-left:auto;color:#64748b;font-size:12px;',
    'font-family:"SF Mono","Cascadia Mono",Consolas,monospace}',
    '.nwl-body{padding:16px 18px}',
    '.nwl-rows{font-family:"SF Mono","Cascadia Mono",Consolas,monospace;font-size:12px;',
    'min-height:104px;margin-bottom:14px}',
    '.nwl-row{display:flex;gap:10px;align-items:center;padding:3px 0;color:#9aa9bd;',
    'opacity:0;transform:translateY(4px);animation:nwl-in .28s ease forwards}',
    '@keyframes nwl-in{to{opacity:1;transform:none}}',
    '.nwl-id{color:#64748b;min-width:74px}',
    '.nwl-sym{color:#e8eef6;min-width:46px}',
    '.nwl-txt{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
    '.nwl-ok{color:#00c853;min-width:52px;text-align:right}',
    '.nwl-run{color:#ffb020;min-width:52px;text-align:right}',
    '.nwl-meter{height:6px;border-radius:3px;background:#182131;overflow:hidden}',
    '.nwl-fill{height:100%;width:0;border-radius:3px;background:linear-gradient(90deg,#3d7dff,#5b93ff);',
    'transition:width .18s linear}',
    '.nwl-fill.ind{width:34%;animation:nwl-slide 1.05s ease-in-out infinite}',
    '@keyframes nwl-slide{0%{margin-left:-36%}100%{margin-left:104%}}',
    '.nwl-foot{display:flex;justify-content:space-between;margin-top:9px;font-size:12px;',
    'color:#64748b;font-family:"SF Mono","Cascadia Mono",Consolas,monospace}',
    '.nwl-err .nwl-fill{background:#ff4d4f}'
  ].join('');

  var SYMS = ['NWX', 'ALDR', 'BRGN', 'CTHM', 'DVSR', 'EKRN', 'FLTB', 'GRDN', 'HLYX', 'MRDN'];

  var root, rows, fill, meter, sub, foot1, foot2;
  var orderId = 4400 + Math.floor(Math.random() * 90);
  var started = 0;
  var assetTotal = 0;
  var assetStarted = 0;

  function build() {
    if (root) return;
    var style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    root = document.createElement('div');
    root.className = 'nwl';
    root.innerHTML =
      '<div class="nwl-box">' +
        '<div class="nwl-head">' +
          '<div class="nwl-mark">N</div>' +
          '<div class="nwl-title">Northwind Markets</div>' +
          '<div class="nwl-sub" id="nwl-sub">session</div>' +
        '</div>' +
        '<div class="nwl-body">' +
          '<div class="nwl-rows" id="nwl-rows"></div>' +
          '<div class="nwl-meter"><div class="nwl-fill" id="nwl-fill"></div></div>' +
          '<div class="nwl-foot"><span id="nwl-f1">awaiting instruction</span>' +
          '<span id="nwl-f2"></span></div>' +
        '</div>' +
      '</div>';
    (document.body || document.documentElement).appendChild(root);
    rows = root.querySelector('#nwl-rows');
    fill = root.querySelector('#nwl-fill');
    meter = fill.parentNode;
    sub = root.querySelector('#nwl-sub');
    foot1 = root.querySelector('#nwl-f1');
    foot2 = root.querySelector('#nwl-f2');
  }

  function mb(n) { return (n / 1048576).toFixed(1) + ' MB'; }

  function addRow(text, pending) {
    build();
    orderId++;
    var sym = SYMS[Math.floor(Math.random() * SYMS.length)];
    var div = document.createElement('div');
    div.className = 'nwl-row';
    div.innerHTML =
      '<span class="nwl-id">ORD-' + orderId + '</span>' +
      '<span class="nwl-sym">' + sym + '</span>' +
      '<span class="nwl-txt"></span>' +
      '<span class="' + (pending ? 'nwl-run' : 'nwl-ok') + '">' +
      (pending ? 'ROUTING' : 'FILLED') + '</span>';
    div.querySelector('.nwl-txt').textContent = text;
    rows.appendChild(div);
    while (rows.children.length > 5) rows.removeChild(rows.firstChild);

    // Settle the previous line so the blotter reads as a live queue.
    var prev = div.previousSibling;
    if (prev) {
      var badge = prev.querySelector('.nwl-run');
      if (badge) { badge.className = 'nwl-ok'; badge.textContent = 'FILLED'; }
    }
    return div;
  }

  var Loader = {
    begin: function () {
      build();
      root.classList.add('on');
      root.classList.remove('nwl-err');
      rows.innerHTML = '';
      started = Date.now();
      fill.classList.add('ind');
      fill.style.width = '';
      sub.textContent = 'connecting';
      foot2.textContent = '';
    },

    /** Yield a frame so a stage renders before a blocking crypto call.
     *
     * A backgrounded or hidden tab does not composite, and its animation
     * frames never fire, so this must never be the only way the promise can
     * settle - otherwise unlocking would hang until the tab was looked at.
     */
    paint: function () {
      return new Promise(function (resolve) {
        var done = false;
        var finish = function () { if (!done) { done = true; resolve(); } };
        if (typeof requestAnimationFrame === 'function') {
          requestAnimationFrame(function () { requestAnimationFrame(finish); });
        }
        setTimeout(finish, 60);
      });
    },

    stage: function (text) {
      addRow(text, true);
      if (foot1) foot1.textContent = text.toLowerCase();
    },

    assetStart: function (path, total) {
      build();
      root.classList.add('on');
      if (!started) started = Date.now();
      assetTotal = total;
      assetStarted = Date.now();
      fill.classList.remove('ind');
      fill.style.width = '0%';
      var name = String(path).split('/').filter(Boolean).slice(-1)[0] || path;
      addRow('Block transfer ' + name, true);
      sub.textContent = 'settling';
    },

    assetProgress: function (done, total) {
      build();
      assetTotal = total || assetTotal;
      var pct = assetTotal ? Math.min(100, done / assetTotal * 100) : 0;
      fill.classList.remove('ind');
      fill.style.width = pct.toFixed(1) + '%';
      var secs = (Date.now() - assetStarted) / 1000;
      var rate = secs > 0 ? done / 1048576 / secs : 0;
      foot1.textContent = mb(done) + ' / ' + mb(assetTotal);
      foot2.textContent = rate.toFixed(0) + ' MB/s';
    },

    done: function (count) {
      build();
      fill.classList.remove('ind');
      fill.style.width = '100%';
      addRow('Terminal ready', false);
      var last = rows.lastChild && rows.lastChild.querySelector('.nwl-run');
      if (last) { last.className = 'nwl-ok'; last.textContent = 'FILLED'; }
      sub.textContent = 'ready';
      foot1.textContent = (count || 0) + ' instruments cleared';
      foot2.textContent = ((Date.now() - started) / 1000).toFixed(1) + 's';
      setTimeout(function () { root.classList.remove('on'); }, 520);
    },

    hide: function () { if (root) root.classList.remove('on'); },

    fail: function () {
      build();
      root.classList.add('nwl-err');
      fill.classList.remove('ind');
      fill.style.width = '100%';
      foot1.textContent = 'order rejected';
      foot2.textContent = '';
      setTimeout(function () { root.classList.remove('on'); }, 900);
    }
  };

  window.Loader = Loader;

  // When injected into a game page there is no gate script to drive us, so
  // listen for the worker's progress broadcasts directly.
  if (navigator.serviceWorker) {
    navigator.serviceWorker.addEventListener('message', function (e) {
      var m = e.data || {};
      if (m.type === 'decrypt-start') Loader.assetStart(m.path, m.total);
      else if (m.type === 'progress') {
        Loader.assetProgress(m.done, m.total);
        if (m.done >= m.total) setTimeout(Loader.hide, 260);
      }
    });
  }
  window.addEventListener('load', function () { setTimeout(Loader.hide, 400); });
})();
