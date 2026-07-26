/**
 * help.js — shared "How it works" modal widget for pktPCAP's vanilla-JS pages.
 * Mirrors the look and behavior of the React HelpButton component used
 * across the rest of the pkt* suite, since this app has no React/build step.
 *
 * Usage:
 *   <button class="pkt-help-btn" title="How this works" onclick="openPktHelp('Title', helpHtml)">?</button>
 * where helpHtml is a template-literal string of <p> tags built in a <script> block.
 */
(function () {
  'use strict';

  var STYLE = [
    '.pkt-help-btn{display:inline-flex;align-items:center;justify-content:center;',
    'width:16px;height:16px;border-radius:50%;border:1px solid #3b82f6;color:#60a5fa;',
    'background:none;font-size:10px;font-weight:600;line-height:1;cursor:pointer;',
    'flex-shrink:0;transition:all .15s;font-family:inherit;padding:0}',
    '.pkt-help-btn:hover{color:#fff;border-color:#60a5fa;background:#3b82f6}',
    '.pkt-help-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);',
    'align-items:center;justify-content:center;z-index:9999}',
    '.pkt-help-overlay.open{display:flex}',
    '.pkt-help-modal{background:#111827;border:1px solid #374151;border-radius:12px;',
    'width:100%;max-width:560px;max-height:80vh;overflow-y:auto;padding:24px;',
    "font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}",
    '.pkt-help-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}',
    '.pkt-help-title{font-size:16px;font-weight:600;color:#f9fafb;margin:0}',
    '.pkt-help-close{background:none;border:none;color:#6b7280;font-size:20px;',
    'line-height:1;cursor:pointer;padding:0}',
    '.pkt-help-close:hover{color:#f9fafb}',
    '.pkt-help-body{font-size:13px;color:#9ca3af;line-height:1.6}',
    '.pkt-help-body p{margin:0 0 12px}',
    '.pkt-help-body p:last-child{margin-bottom:0}',
    '.pkt-help-body strong,.pkt-help-body code{color:#d1d5db}',
    '.pkt-help-body code{font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:12px}',
  ].join('');

  var styleEl = document.createElement('style');
  styleEl.textContent = STYLE;
  document.head.appendChild(styleEl);

  var overlay, titleEl, bodyEl;

  function ensureDom() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'pkt-help-overlay';
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) closePktHelp();
    });

    var modal = document.createElement('div');
    modal.className = 'pkt-help-modal';
    modal.addEventListener('click', function (e) { e.stopPropagation(); });

    var hdr = document.createElement('div');
    hdr.className = 'pkt-help-hdr';

    titleEl = document.createElement('h2');
    titleEl.className = 'pkt-help-title';

    var closeBtn = document.createElement('button');
    closeBtn.className = 'pkt-help-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = closePktHelp;

    hdr.appendChild(titleEl);
    hdr.appendChild(closeBtn);

    bodyEl = document.createElement('div');
    bodyEl.className = 'pkt-help-body';

    modal.appendChild(hdr);
    modal.appendChild(bodyEl);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closePktHelp();
    });
  }

  window.openPktHelp = function (title, html) {
    ensureDom();
    titleEl.textContent = title;
    bodyEl.innerHTML = html;
    overlay.classList.add('open');
  };

  window.closePktHelp = function () {
    if (overlay) overlay.classList.remove('open');
  };
})();
