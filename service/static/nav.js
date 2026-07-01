/**
 * nav.js — shared sidebar navigation component for pktPCAP
 *
 * Usage:
 *   Place <nav id="sidebar-nav" data-active="<item-id>"></nav> in your sidebar.
 *   Add <script src="/static/nav.js"></script> at the bottom of <body>,
 *   AFTER any page-level scripts (so SPA functions are already defined).
 *
 * Item IDs: dashboard | analyzer | feeds | logs | settings
 *
 * SPA detection: if window.showDashboard is defined (index.html), nav items
 * use onclick handlers. Otherwise (settings.html), plain hrefs are used.
 */
(function () {
  'use strict';

  var STYLE_ACTIVE   = 'display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;text-decoration:none;font-size:14px;cursor:pointer;background:rgba(37,99,235,.2);color:#93c5fd;font-weight:500';
  var STYLE_INACTIVE = 'display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;text-decoration:none;font-size:14px;cursor:pointer;color:#ffffff;font-weight:400';
  var HOVER_ON  = "this.style.background='#1f2937'";
  var HOVER_OFF = "this.style.background='none'";

  var ICONS = {
    dashboard: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
    analyzer:  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    feeds:     '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
    logs:      '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
    settings:  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>',
  };

  // Item definition: [id, href, label, spaFn]
  // spaFn is the JS expression to call on the SPA page (null = always use href)
  var ITEMS = [
    ['dashboard', '/',         'Dashboard',  'showDashboard()'],
    ['analyzer',  '/',         'Analyzer',   'showAnalyzer()'],
    ['feeds',     '/#feeds',   'Live Feeds', 'showLiveFeeds()'],
    ['logs',      '/#logs',    'Logs',       'showLogs()'],
    ['settings',  '/settings', 'Settings',   null],
  ];

  function buildNav(el, role) {
    var active = el.dataset ? el.dataset.active : (el.getAttribute('data-active') || 'dashboard');
    var isSpa  = typeof window.showDashboard === 'function';
    var isAdmin = role === 'admin';

    el.innerHTML = ITEMS.filter(function(item) {
      // Hide Settings from non-admins
      return item[0] !== 'settings' || isAdmin;
    }).map(function (item) {
      var id = item[0], href = item[1], label = item[2], spaFn = item[3];
      var isActive = id === active;
      var style    = isActive ? STYLE_ACTIVE : STYLE_INACTIVE;
      var hover    = isActive ? '' : ('onmouseover="' + HOVER_ON + '" onmouseout="' + HOVER_OFF + '"');
      var onclick  = (!isActive && isSpa && spaFn)
        ? ('onclick="' + spaFn + '; return false;"')
        : '';

      return '<a id="nav-' + id + '" href="' + href + '" style="' + style + '" ' + hover + ' ' + onclick + '>'
           + ICONS[id] + '<span>' + label + '</span></a>';
    }).join('\n');
  }

  // Fetch current user then build nav (hides Settings for non-admins)
  var el = document.getElementById('sidebar-nav');
  if (el) {
    fetch('/api/auth/current-user').then(function(r) {
      return r.ok ? r.json() : null;
    }).then(function(u) {
      buildNav(el, u ? u.role : null);
    }).catch(function() {
      buildNav(el, null);
    });
  }
})();
