/* RiskDesk front end. Plain JS on purpose -- no build step, no toolchain to
   keep current. Open index.html through the server and it runs. */

const state = {
  meta: null,
  view: 'findings',
  page: 1,
  pageSize: 50,
  filter: {
    status: ['open'], source: [], severity: [], category: [], disposition: [],
    bucket: [], quick: null, q: '', sort: 'risk',
    // Exact-match drill-downs (set by clicking a group row).
    asset_id: null, component: '', component_version: '',
    owner: '', business_unit: '', asset_type: '', asset_group_id: null, ecosystem: '',
  },
  groupBy: '',    // '' = list view; 'cve' | 'asset' | 'component' | ...
  groupResults: null,
  results: null,
  selected: new Set(),
  allMatchingIds: null,     // set when "select all matching" is used
  register: { state: '', q: '', due: false, mine: false, selected: new Set() },
  decideDraft: null,
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------------------------------------------------------------- api

async function api(path, opts = {}) {
  const headers = Object.assign(
    { 'Content-Type': 'application/json', 'X-RiskDesk-User': currentUser() },
    opts.headers || {});
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 422) {
    const body = await res.json();
    const err = new Error('policy');
    err.problems = body.problems || [body.detail].flat();
    throw err;
  }
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

function currentUser() {
  return $('userSelect').value || (state.meta ? state.meta.current_user : 'admin1');
}

function toast(message, isError) {
  const el = $('toast');
  el.textContent = message;
  el.className = 'toast' + (isError ? ' is-error' : '');
  el.hidden = false;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.hidden = true; }, isError ? 6000 : 3000);
}

// ---------------------------------------------------------------- formatting

const DISP_SHORT = {
  fix_immediately: 'Fix now', complex_resolution: 'Complex', developer_review: 'Dev review',
  routine_fix: 'Routine', accept_risk: 'Accepted', adjust_risk: 'Adjusted',
  false_positive: 'Not affected',
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_ORDER = ['open', 'fixed', 'stale', 'verified_fixed', 'suppressed_at_source'];
const STATUS_LABEL = {
  open: 'Open', fixed: 'Fixed — awaiting verification',
  stale: 'Stale — no longer reported', verified_fixed: 'Verified fixed',
  suppressed_at_source: 'Suppressed at source',
};
const STATUS_SHORT = {
  fixed: 'Fixed', stale: 'Stale', verified_fixed: 'Verified', suppressed_at_source: 'Suppressed',
};
const isClosed = (s) => s && s !== 'open';

function dispLabel(v) {
  const m = (state.meta?.dispositions || []).find((d) => d.value === v);
  return m ? m.label : v;
}
function fmtDate(iso) {
  if (!iso) return null;
  return new Date(iso).toISOString().slice(0, 10);
}
function daysFrom(iso) {
  if (!iso) return null;
  return Math.round((Date.now() - new Date(iso).getTime()) / 86400000);
}
function daysBetween(fromIso, toIso) {
  if (!fromIso || !toIso) return null;
  return Math.round((new Date(toIso).getTime() - new Date(fromIso).getTime()) / 86400000);
}
function daysUntil(iso) {
  if (!iso) return null;
  return Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
}
function gauge(sev) {
  return `<span class="gauge sev-${sev}"><i></i><i></i><i></i><i></i></span>`;
}

// ---------------------------------------------------------------- boot

async function boot() {
  state.meta = await api('/api/meta');
  $('orgName').textContent = `${state.meta.org} vulnerability adjudication`;

  const sel = $('userSelect');
  sel.innerHTML = state.meta.users.map((u) =>
    `<option value="${esc(u)}"${u === state.meta.current_user ? ' selected' : ''}>${esc(u)}${state.meta.approvers.includes(u) ? ' \u00b7 approver' : ''}</option>`
  ).join('');
  sel.onchange = () => { refresh(); toast(`Acting as ${currentUser()}`); };

  if (state.meta.demo_findings > 0) {
    $('demoBanner').hidden = false;
    $('demoCount').textContent = state.meta.demo_findings.toLocaleString();
  }

  $('tabs').onclick = (e) => {
    const b = e.target.closest('.tab');
    if (!b) return;
    switchView(b.dataset.view);
  };

  $('qInput').oninput = debounce(() => {
    state.filter.q = $('qInput').value.trim();
    state.page = 1; loadFindings();
  }, 300);

  $('sortSelect').onchange = () => { state.filter.sort = $('sortSelect').value; state.page = 1; loadFindings(); };
  $('groupBy').onchange = () => {
    state.groupBy = $('groupBy').value;
    state.page = 1;
    state.selected.clear();
    state.allMatchingIds = null;
    loadFindings();
  };
  $('quickViews').onclick = (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    applyQuick(b.dataset.quick);
  };

  $('selectPage').onchange = (e) => {
    const ids = (state.results?.findings || []).map((f) => f.id);
    if (e.target.checked) ids.forEach((i) => state.selected.add(i));
    else ids.forEach((i) => state.selected.delete(i));
    state.allMatchingIds = null;
    renderFindings();
  };
  $('selectAllMatching').onclick = selectAllMatching;
  $('clearSelection').onclick = () => { state.selected.clear(); state.allMatchingIds = null; renderFindings(); };
  $('prevPage').onclick = () => { if (state.page > 1) { state.page--; loadFindings(); } };
  $('nextPage').onclick = () => { state.page++; loadFindings(); };

  $('scrim').onclick = closeDrawers;
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawers(); });

  $('regState').onclick = (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    state.register.state = b.dataset.state;
    [...$('regState').children].forEach((c) => c.classList.toggle('is-active', c === b));
    loadRegister();
  };
  $('regSearch').oninput = debounce(() => { state.register.q = $('regSearch').value.trim(); loadRegister(); }, 300);
  $('regDue').onclick = () => {
    state.register.due = !state.register.due;
    $('regDue').classList.toggle('is-active', state.register.due);
    loadRegister();
  };
  $('regMine').onchange = () => {
    state.register.mine = $('regMine').checked;
    state.register.selected.clear();
    loadRegister();
  };
  $('regBulkApprove').onclick = () => bulkDecide(true);
  $('regBulkReject').onclick = () => bulkDecide(false);
  $('regBulkClear').onclick = () => { state.register.selected.clear(); loadRegister(); };

  await loadFindings();
  startSyncWatcher();
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function switchView(view) {
  state.view = view;
  [...$('tabs').children].forEach((t) => t.classList.toggle('is-active', t.dataset.view === view));
  ['findings', 'register', 'activity', 'compliance', 'exceptions', 'rules', 'sources', 'tickets', 'settings'].forEach((v) => { $(`view-${v}`).hidden = v !== view; });
  if (view === 'findings') clearFindingsBadge();
  if (view === 'register') loadRegister();
  if (view === 'activity') loadActivity();
  if (view === 'compliance') loadCompliance();
  if (view === 'exceptions') loadExceptions();
  if (view === 'rules') loadRules();
  if (view === 'sources') loadSources();
  if (view === 'tickets') loadTickets();
  if (view === 'settings') loadSettings();
}

// --- Background sync watcher ------------------------------------------------
// Poll /api/sync/runs so the user knows a sync is happening (or just finished)
// without being on the Sources tab. Shows:
//   - pulsing dot on "Sources" while any run is in-flight
//   - "N new" badge on "Findings" when a sync completes with new findings
// Click Findings to clear the badge.

const SYNC_POLL_FOCUSED_MS = 5_000;
const SYNC_POLL_HIDDEN_MS  = 30_000;
const LAST_SEEN_KEY = 'riskdesk:lastSeenRunId';

let _newSinceLastVisit = 0;
let _syncPollTimer = null;
let _lastSeenRunId = null;

function loadLastSeenRunId() {
  try {
    const v = localStorage.getItem(LAST_SEEN_KEY);
    return v ? Number(v) : null;
  } catch (_) { return null; }
}
function saveLastSeenRunId(id) {
  try { localStorage.setItem(LAST_SEEN_KEY, String(id)); } catch (_) {}
}

function setTabBadge(tabKey, html) {
  const tab = document.querySelector(`.tab[data-view="${tabKey}"]`);
  if (!tab) return;
  const existing = tab.querySelector('.tab-dot, .tab-badge');
  if (existing) existing.remove();
  if (html) tab.insertAdjacentHTML('beforeend', html);
}

function clearFindingsBadge() {
  _newSinceLastVisit = 0;
  setTabBadge('findings', '');
}

async function pollSyncRuns() {
  try {
    const runs = await api('/api/sync/runs?limit=10');
    // Any run currently in-flight -> pulsing dot on Sources
    const running = runs.some((r) => !r.finished_at || r.status === 'running');
    setTabBadge('sources', running ? '<span class="tab-dot is-running" title="Sync in progress"></span>' : '');

    if (_lastSeenRunId === null) {
      // First poll of this session -- seed from localStorage or the current max,
      // so we don't fire notifications for history on first load.
      const saved = loadLastSeenRunId();
      _lastSeenRunId = saved !== null ? saved : (runs[0] ? runs[0].id : 0);
    }

    // Any completed run newer than what we've seen -> toast + findings badge
    const fresh = runs.filter(
      (r) => r.id > _lastSeenRunId && r.finished_at && r.status === 'ok'
    );
    if (fresh.length) {
      const newFindings = fresh.reduce((s, r) => s + (r.new || 0), 0);
      if (newFindings > 0 && state.view !== 'findings') {
        _newSinceLastVisit += newFindings;
        setTabBadge('findings',
          `<span class="tab-badge" title="${_newSinceLastVisit} new findings since you last viewed the list">${_newSinceLastVisit}</span>`);
      }
      // Toast per finished source (dedup if multiple)
      const bySource = {};
      fresh.forEach((r) => {
        bySource[r.source] = (bySource[r.source] || { new: 0, findings: 0, closed: 0 });
        bySource[r.source].new += r.new || 0;
        bySource[r.source].findings += r.findings || 0;
        bySource[r.source].closed += r.closed || 0;
      });
      for (const [src, s] of Object.entries(bySource)) {
        toast(`${src} sync done: ${s.new} new, ${s.closed} closed, ${s.findings} total`);
      }
      // Refresh the view the user is currently on if it depends on findings data
      if (state.view === 'findings') loadFindings();
      if (state.view === 'sources') loadSources();
    }

    // Advance the pointer to the newest completed run we saw
    const maxCompletedId = runs
      .filter((r) => r.finished_at)
      .reduce((m, r) => Math.max(m, r.id), _lastSeenRunId);
    if (maxCompletedId > _lastSeenRunId) {
      _lastSeenRunId = maxCompletedId;
      saveLastSeenRunId(maxCompletedId);
    }
  } catch (_) {
    // Network blips are fine -- try again next tick.
  } finally {
    scheduleSyncPoll();
  }
}

function scheduleSyncPoll() {
  if (_syncPollTimer) clearTimeout(_syncPollTimer);
  const delay = document.hidden ? SYNC_POLL_HIDDEN_MS : SYNC_POLL_FOCUSED_MS;
  _syncPollTimer = setTimeout(pollSyncRuns, delay);
}

function startSyncWatcher() {
  pollSyncRuns();
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) pollSyncRuns();
  });
}

function refresh() {
  if (state.view === 'findings') loadFindings();
  if (state.view === 'register') loadRegister();
  if (state.view === 'activity') loadActivity();
  if (state.view === 'sources') loadSources();
}

// ---------------------------------------------------------------- findings

function filterParams() {
  const p = new URLSearchParams();
  (state.filter.status.length ? state.filter.status : STATUS_ORDER).forEach((v) => p.append('status', v));
  state.filter.source.forEach((v) => p.append('source', v));
  state.filter.severity.forEach((v) => p.append('severity', v));
  state.filter.category.forEach((v) => p.append('category', v));
  state.filter.disposition.forEach((v) => p.append('disposition', v));
  (state.filter.bucket || []).forEach((v) => p.append('bucket', String(v)));
  if (state.filter.q) p.set('q', state.filter.q);
  if (state.filter.sort) p.set('sort', state.filter.sort);
  // Exact-match drill-down filters from a clicked group row.
  if (state.filter.asset_id != null) p.set('asset_id', state.filter.asset_id);
  if (state.filter.component) p.set('component', state.filter.component);
  if (state.filter.component_version) p.set('component_version', state.filter.component_version);
  if (state.filter.owner) p.set('owner', state.filter.owner);
  if (state.filter.business_unit) p.set('business_unit', state.filter.business_unit);
  if (state.filter.asset_type) p.set('asset_type', state.filter.asset_type);
  if (state.filter.asset_group_id != null) p.set('asset_group_id', state.filter.asset_group_id);
  if (state.filter.ecosystem) p.set('ecosystem', state.filter.ecosystem);
  const q = state.filter.quick;
  if (q === 'kev') p.set('kev', 'true');
  if (q === 'overdue') p.set('overdue', 'true');
  if (q === 'fixable') p.set('fixable', 'true');
  if (q === 'undecided') p.set('undecided', 'true');
  if (q === 'accepted') p.append('disposition', 'accept_risk');
  return p;
}

async function loadFindings() {
  $('findingsList').innerHTML = '<div class="spin">Loading\u2026</div>';
  $('exportFindings').href = `/api/export/findings.csv?${filterParams()}`;
  const [fac, dash] = await Promise.all([
    api(`/api/facets?${filterParams()}`),
    api('/api/dashboard'),
  ]);
  renderFacets(fac);
  renderStats(dash);
  renderActiveDrillDowns();
  if (state.groupBy) {
    const p = filterParams();
    p.set('by', state.groupBy);
    p.set('page', state.page);
    p.set('page_size', state.pageSize);
    state.groupResults = await api(`/api/findings/grouped?${p}`);
    state.results = null;
    renderGroupedFindings();
  } else {
    const p = filterParams();
    p.set('page', state.page);
    p.set('page_size', state.pageSize);
    state.results = await api(`/api/findings?${p}`);
    state.groupResults = null;
    renderFindings();
  }
}

function renderStats(d) {
  const items = [
    ['Open findings', d.open_findings.toLocaleString(), '', null],
    ['Not adjudicated', d.undecided.toLocaleString(), '', 'undecided'],
    ['Past SLA', d.overdue.toLocaleString(), 'is-notice', 'overdue'],
    ['On KEV', d.kev_open.toLocaleString(), 'is-seal', 'kev'],
    ['Awaiting approval', d.pending_approvals.toLocaleString(), '', null],
    ['Lapsing in 30d', d.expiring_30d.toLocaleString(), 'is-notice', null],
  ];
  const stats = items.map(([label, val, cls, quick]) =>
    `<div class="stat ${cls} ${quick ? 'is-clickable' : ''}" ${quick ? `data-quick="${quick}"` : ''}>
       <b>${val}</b><span>${label}</span></div>`).join('');
  const bucketMeta = state.meta?.buckets || [];
  const breach = d.bucket_aging_breach || {};
  const buckets = (d.by_bucket)
    ? bucketMeta.map((b) => {
        const n = (d.by_bucket[String(b.number)] || 0);
        const over = breach[String(b.number)] || 0;
        const notice = over > 0 ? 'is-notice' : '';
        const tag = over > 0 ? ` <span class="bucket-breach" title="${over} over ${b.max_days}-day cap">${over}!</span>` : '';
        return `<div class="stat bucket-stat is-clickable ${notice}" data-bucket="${b.number}" title="${esc(b.summary)}">
          <b>${n.toLocaleString()}${tag}</b><span>B${b.number} · ${esc(b.title)}</span></div>`;
      }).join('')
    : '';
  $('statStrip').innerHTML = stats + buckets;
  $('statStrip').onclick = (e) => {
    const b = e.target.closest('[data-bucket]');
    if (b) {
      state.filter.bucket = [parseInt(b.dataset.bucket, 10)];
      state.page = 1;
      state.selected.clear();
      loadFindings();
      return;
    }
    const s = e.target.closest('[data-quick]');
    if (s) applyQuick(s.dataset.quick);
  };
}

function applyQuick(kind) {
  if (kind === 'clear') {
    state.filter = { status: ['open'], source: [], severity: [], category: [], disposition: [], bucket: [], quick: null, q: '', sort: state.filter.sort };
    $('qInput').value = '';
  } else {
    state.filter.quick = state.filter.quick === kind ? null : kind;
    if (state.filter.quick !== 'accepted') state.filter.disposition = [];
  }
  [...$('quickViews').children].forEach((b) =>
    b.classList.toggle('is-active', b.dataset.quick === state.filter.quick));
  state.page = 1;
  state.selected.clear();
  state.allMatchingIds = null;
  loadFindings();
}

function renderFacets(fac) {
  const block = (elId, title, dimension, entries, labeller, decorate) => {
    const rows = entries.map(([value, n]) => {
      const on = state.filter[dimension].includes(value);
      return `<div class="facet ${on ? 'is-on' : ''}" data-dim="${dimension}" data-value="${esc(value)}">
        <span class="facet-name">${decorate ? decorate(value) : ''}${esc(labeller(value))}</span>
        <span class="facet-n">${n.toLocaleString()}</span></div>`;
    }).join('');
    $(elId).innerHTML = `<div class="micro-label">${title}</div>${rows || '<div class="hint">Nothing matches.</div>'}`;
  };

  const statusCounts = fac.status || {};
  const statusEntries = STATUS_ORDER
    .filter((s) => s === 'open' || statusCounts[s] || state.filter.status.includes(s))
    .map((s) => [s, statusCounts[s] || 0]);
  block('facetStatus', 'Lifecycle status', 'status', statusEntries, (v) => STATUS_LABEL[v] || v);

  const sevEntries = SEV_ORDER.filter((s) => fac.severity[s]).map((s) => [s, fac.severity[s]]);
  block('facetSeverity', 'Effective severity', 'severity', sevEntries,
    (v) => v[0].toUpperCase() + v.slice(1), (v) => gauge(v));

  block('facetSource', 'Source', 'source',
    Object.entries(fac.source).sort((a, b) => b[1] - a[1]),
    (v) => ({ wiz: 'Wiz', falcon: 'CrowdStrike Falcon', github: 'GitHub' }[v] || v));

  const dispEntries = Object.entries(fac.disposition).sort((a, b) => b[1] - a[1]);
  block('facetDisposition', 'Disposition', 'disposition', dispEntries,
    (v) => (v === 'none' ? 'Not yet adjudicated' : dispLabel(v)));

  block('facetCategory', 'Finding type', 'category',
    Object.entries(fac.category).sort((a, b) => b[1] - a[1]),
    (v) => ({
      os_vuln: 'Operating system', cloud_vuln: 'Cloud workload', container: 'Container image',
      misconfiguration: 'Cloud misconfiguration', dependency: 'Dependency',
      code_scanning: 'Source code', secret: 'Exposed secret', detection: 'EDR detection',
    }[v] || v));

  ['facetStatus', 'facetSeverity', 'facetSource', 'facetDisposition', 'facetCategory'].forEach((id) => {
    $(id).onclick = (e) => {
      const f = e.target.closest('.facet');
      if (!f) return;
      const arr = state.filter[f.dataset.dim];
      const i = arr.indexOf(f.dataset.value);
      if (i >= 0) arr.splice(i, 1); else arr.push(f.dataset.value);
      state.page = 1;
      state.selected.clear();
      state.allMatchingIds = null;
      loadFindings();
    };
  });
}

function renderFindings() {
  const r = state.results;
  if (!r) return;

  $('resultCount').innerHTML = state.selected.size
    ? `<b>${state.selected.size.toLocaleString()}</b> selected of <b>${r.total.toLocaleString()}</b>`
    : `<b>${r.total.toLocaleString()}</b> findings`;

  const pageIds = r.findings.map((f) => f.id);
  $('selectPage').checked = pageIds.length > 0 && pageIds.every((i) => state.selected.has(i));

  const bar = $('selectAllBar');
  if (state.selected.size > 0) {
    bar.hidden = false;
    const covered = state.allMatchingIds ? r.total : state.selected.size;
    $('selectAllText').innerHTML = state.allMatchingIds
      ? `All <b>${r.total.toLocaleString()}</b> matching findings are selected.`
      : `<b>${state.selected.size}</b> selected on this page.`;
    $('selectAllMatching').hidden = !!state.allMatchingIds || r.total <= state.results.total;
    bar.insertAdjacentElement('beforeend', decideButton());
    bar.insertAdjacentElement('beforeend', ticketButton());
    renderScopePromotion();
  } else {
    bar.hidden = true;
    const hint = document.getElementById('scopePromotionHint');
    if (hint) hint.remove();
  }

  if (!r.findings.length) {
    $('findingsList').innerHTML = `<div class="empty"><b>Nothing matches these filters.</b>
      Widen the search, or clear the filters in the rail.</div>`;
    renderPager();
    return;
  }

  $('findingsList').innerHTML = r.findings.map(rowHtml).join('');
  $('findingsList').onclick = (e) => {
    const cb = e.target.closest('.row-check');
    const row = e.target.closest('.row');
    if (!row) return;
    const id = Number(row.dataset.id);
    if (cb) {
      if (state.selected.has(id)) state.selected.delete(id); else state.selected.add(id);
      state.allMatchingIds = null;
      renderFindings();
      return;
    }
    openDetail(id);
  };
  renderPager();
}

function decideButton() {
  let b = document.getElementById('bulkDecide');
  if (b) b.remove();
  b = document.createElement('button');
  b.id = 'bulkDecide';
  b.className = 'btn btn-seal';
  b.style.marginLeft = 'auto';
  b.textContent = `Record a decision on ${(state.allMatchingIds ? state.results.total : state.selected.size).toLocaleString()} findings`;
  b.onclick = () => openDecide([...(state.allMatchingIds || state.selected)]);
  return b;
}

async function renderScopePromotion() {
  const ids = [...(state.allMatchingIds || state.selected)];
  if (ids.length < 2) {
    const h = document.getElementById('scopePromotionHint');
    if (h) h.remove();
    return;
  }
  // Mount a hint block just under the select-all bar so it reads as a tip,
  // not a separate action. Keep it quiet when nothing useful is found.
  const bar = $('selectAllBar');
  let host = document.getElementById('scopePromotionHint');
  if (!host) {
    host = document.createElement('div');
    host.id = 'scopePromotionHint';
    host.className = 'scope-hint';
    bar.insertAdjacentElement('afterend', host);
  }
  host.innerHTML = '<span class="hint">Checking for broader scope…</span>';

  let data;
  try {
    data = await api('/api/review/scope-promotion', {
      method: 'POST', body: JSON.stringify({ finding_ids: ids.slice(0, 5000) }),
    });
  } catch (e) {
    host.remove();
    return;
  }

  const best = (data.suggestions || []).find(
    (s) => s.scope_type !== 'finding' && s.key_count < ids.length
  );
  if (!best) {
    host.remove();
    return;
  }
  const warn = best.warnings.length ? ` <span class="scope-warn" title="${esc(best.warnings.join('\n'))}">${best.warnings.length} warning${best.warnings.length > 1 ? 's' : ''}</span>` : '';
  const extras = best.extra_beyond_selection
    ? ` <span class="hint">(+${best.extra_beyond_selection.toLocaleString()} other open findings covered)</span>` : '';
  host.innerHTML = `
    <span class="scope-hint-icon">↗</span>
    <span>${esc(best.summary)}${warn}${extras}</span>
    <button class="btn-ghost" id="scopePromoteApply" style="margin-left:auto">Use this scope</button>
    <button class="btn-ghost" id="scopePromoteShow" style="margin-left:6px">Show options</button>
  `;
  document.getElementById('scopePromoteApply').onclick = () => {
    openDecideWithScope(ids, best.scope_type);
  };
  document.getElementById('scopePromoteShow').onclick = () => {
    showScopePromotionOptions(ids, data.suggestions);
  };
}

function openDecideWithScope(ids, scopeType) {
  // openDecide's `suggested` arg seeds the draft; we route the promoted
  // scope through there rather than mutating state ourselves.
  openDecide(ids, { scope: scopeType });
}

function showScopePromotionOptions(ids, suggestions) {
  const host = document.getElementById('scopePromotionHint');
  if (!host) return;
  // Toggle an expanded options panel inline rather than open a modal.
  let panel = document.getElementById('scopePromotionPanel');
  if (panel) { panel.remove(); return; }
  panel = document.createElement('div');
  panel.id = 'scopePromotionPanel';
  panel.className = 'scope-panel';
  panel.innerHTML = suggestions.map((s) => {
    const warns = s.warnings.length
      ? `<ul class="scope-warn-list">${s.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>`
      : '';
    const badge = s.clean ? '<span class="tag tag-ok">clean</span>' : '<span class="tag tag-warn">has extras</span>';
    const extras = s.extra_beyond_selection
      ? ` <span class="hint">+${s.extra_beyond_selection.toLocaleString()} beyond selection</span>` : '';
    return `<div class="scope-option">
      <div class="scope-option-head">
        <b>${esc(s.summary)}</b> ${badge}${extras}
      </div>
      ${warns}
      <button class="btn btn-seal" data-scope-apply="${s.scope_type}">Use ${esc(s.scope_type)} scope</button>
    </div>`;
  }).join('');
  host.insertAdjacentElement('afterend', panel);
  panel.querySelectorAll('[data-scope-apply]').forEach((b) => {
    b.onclick = () => {
      panel.remove();
      openDecideWithScope(ids, b.dataset.scopeApply);
    };
  });
}

function ticketButton() {
  let b = document.getElementById('bulkTicket');
  if (b) b.remove();
  b = document.createElement('button');
  b.id = 'bulkTicket';
  b.className = 'btn-ghost';
  b.style.marginLeft = '8px';
  const count = state.allMatchingIds ? state.results.total : state.selected.size;
  b.textContent = `Create ticket for ${count.toLocaleString()} findings`;
  b.onclick = () => openCreateTicket([...(state.allMatchingIds || state.selected)]);
  return b;
}

function rowHtml(f) {
  const d = f.decision;
  const sev = f.risk.effective_severity;
  const closed = isClosed(f.status);
  const age = closed ? daysBetween(f.first_detected, f.closed_at) : daysFrom(f.first_detected);
  const tags = [];
  if (closed) tags.push(`<span class="tag tag-closed">${esc(STATUS_SHORT[f.status] || f.status)}</span>`);
  if (f.reopened_count) tags.push(`<span class="tag tag-reopened">Reopened${f.reopened_count > 1 ? ' ×' + f.reopened_count : ''}</span>`);
  if (f.vuln.kev) tags.push('<span class="tag tag-kev">KEV</span>');
  if (f.risk.sla_overdue) tags.push('<span class="tag tag-overdue">Past SLA</span>');
  if (f.has_pending && !d) tags.push('<span class="tag tag-pending">Awaiting approval</span>');
  if (d) {
    const cls = d.disposition === 'accept_risk' || d.disposition === 'false_positive'
      ? 'tag-muted' : 'tag-decided';
    tags.push(`<span class="tag ${cls}">${esc(DISP_SHORT[d.disposition] || d.disposition)}</span>`);
  }

  const sevCell = f.risk.adjusted
    ? `${gauge(sev)} <span class="strike">${f.risk.base_severity}</span> \u2192 <em>${sev}</em>`
    : `${gauge(sev)} <em>${sev}</em>`;

  return `<div class="row ${state.selected.has(f.id) ? 'is-selected' : ''}" data-id="${f.id}">
    <div class="edge sev-${sev}"></div>
    <div class="row-check"><label class="checkbox"><input type="checkbox" ${state.selected.has(f.id) ? 'checked' : ''} tabindex="-1"><span></span></label></div>
    <div class="row-main">
      <div class="row-id">${esc(f.vuln.canonical_id)}</div>
      <div class="row-title">${esc(f.vuln.title || '')}</div>
      <div class="row-meta">
        <span>${sevCell}</span>
        <span>${esc(f.source)}</span>
        ${f.component ? `<span>${esc(f.component)}${f.component_version ? ' ' + esc(f.component_version) : ''}</span>` : ''}
        ${age !== null ? `<span>${closed ? `closed after ${age}d` : `${age}d open`}</span>` : ''}
        ${f.fix_available ? '<span>fix published</span>' : ''}
      </div>
    </div>
    <div class="row-asset">${esc(f.asset.name)}
      <small>${esc(f.asset.type || '')}${f.asset.environment && f.asset.environment !== 'unknown' ? ' \u00b7 ' + esc(f.asset.environment) : ''}</small>
    </div>
    <div class="row-risk">
      <div class="pri pri-${f.risk.priority}">${f.risk.priority}</div>
      <div class="score">${f.risk.score}</div>
    </div>
    <div class="row-state">${tags.join('')}</div>
  </div>`;
}

function renderPager() {
  const r = state.results || state.groupResults;
  if (!r) return;
  $('pageLabel').textContent = `Page ${r.page} of ${r.pages}`;
  $('prevPage').disabled = r.page <= 1;
  $('nextPage').disabled = r.page >= r.pages;
}


// ---------------------------------------------------------------- grouped view

const GROUP_BY_LABEL = {
  cve: 'CVE', asset: 'Asset', component: 'Component',
  component_version: 'Component + version', asset_type: 'Asset type',
  owner: 'Owner', business_unit: 'Business unit', ecosystem: 'Ecosystem',
};

const DRILLDOWN_KEYS = [
  'asset_id', 'component', 'component_version', 'owner',
  'business_unit', 'asset_type', 'asset_group_id', 'ecosystem',
];

function renderGroupedFindings() {
  const r = state.groupResults;
  if (!r) return;
  $('resultCount').innerHTML = `<b>${r.total_groups.toLocaleString()}</b> groups ` +
    `· <span class="hint">${r.total_findings.toLocaleString()} findings grouped by ${esc(GROUP_BY_LABEL[r.group_by] || r.group_by)}</span>`;
  $('selectPage').checked = false;
  $('selectAllBar').hidden = true;

  if (!r.groups.length) {
    $('findingsList').innerHTML = `<div class="empty"><b>Nothing to group.</b>
      Widen the filters, or switch grouping off.</div>`;
    renderPager();
    return;
  }
  $('findingsList').innerHTML = r.groups.map((g) => groupRowHtml(g, r.group_by)).join('');
  $('findingsList').onclick = (e) => {
    const b = e.target.closest('[data-action]');
    if (!b) return;
    const row = b.closest('.row');
    const key = row.dataset.groupKey;
    const g = r.groups.find((x) => x.key === key);
    if (!g) return;
    if (b.dataset.action === 'drill') drillIntoGroup(g, r.group_by);
    if (b.dataset.action === 'decide') actOnGroup(g, r.group_by, 'decide');
    if (b.dataset.action === 'ticket') actOnGroup(g, r.group_by, 'ticket');
  };
  renderPager();
}

function groupRowHtml(g, by) {
  const sev = g.max_severity;
  const sevChips = Object.entries(g.severity_counts)
    .sort((a, b) => SEV_ORDER.indexOf(a[0]) - SEV_ORDER.indexOf(b[0]))
    .map(([k, v]) => `<span class="tag" style="font-size:9px">${esc(k)}: ${v}</span>`)
    .join(' ');
  const statusChips = Object.entries(g.status_counts)
    .filter(([k]) => k !== 'open')
    .map(([k, v]) => `<span class="tag tag-closed" style="font-size:9px">${esc(STATUS_SHORT[k] || k)}: ${v}</span>`)
    .join(' ');
  const kev = g.kev_count ? `<span class="tag tag-kev">KEV ${g.kev_count}</span>` : '';
  const fix = g.fix_available_count ? `<span class="tag">fix in ${g.fix_available_count}/${g.finding_count}</span>` : '';
  const age = g.oldest_open_detected ? daysFrom(g.oldest_open_detected) : null;
  const subtitle = by === 'cve'
    ? esc(g.title || '')
    : by === 'asset'
      ? esc(g.asset_type || '')
      : by === 'component_version'
        ? esc(g.component + ' @ ' + (g.component_version || '(no version)'))
        : (g.sample_titles && g.sample_titles.length
            ? esc(g.sample_titles[0]) + (g.sample_titles.length > 1 ? ', +more' : '')
            : '');

  return `<div class="row" data-group-key="${esc(g.key)}">
    <div class="edge sev-${sev}"></div>
    <div class="row-check"></div>
    <div class="row-main">
      <div class="row-id">${esc(g.label)} <span class="hint" style="font-size:11px">${esc(GROUP_BY_LABEL[by])}</span></div>
      <div class="row-title">${subtitle}</div>
      <div class="row-meta">
        <span>${gauge(sev)} <em>${sev}</em></span>
        <span><b>${g.finding_count.toLocaleString()}</b> findings on <b>${g.asset_count.toLocaleString()}</b> assets</span>
        ${g.sources.length ? `<span>${g.sources.map(esc).join(', ')}</span>` : ''}
        ${age !== null ? `<span>oldest ${age}d open</span>` : ''}
        ${g.fix_versions && g.fix_versions.length ? `<span>fix: ${g.fix_versions.map(esc).join(', ')}</span>` : ''}
      </div>
      <div class="row-meta" style="margin-top:4px">${sevChips} ${statusChips} ${kev} ${fix}</div>
    </div>
    <div class="row-asset">${g.suggested_scope === 'vuln' ? 'Scope: vuln (all assets)' : g.suggested_scope === 'component' ? 'Scope: component (future too)' : 'Scope: per-finding'}
      <small>${g.max_score ? 'max score ' + g.max_score : ''}</small>
    </div>
    <div class="row-risk">
      <div class="score">${g.finding_count}</div>
    </div>
    <div class="row-state" style="display:flex;flex-direction:column;gap:4px;align-items:flex-end">
      <button class="btn-ghost" style="font-size:11px;padding:3px 8px" data-action="drill" title="Show findings in this group">Open</button>
      <button class="btn" style="font-size:11px;padding:3px 8px" data-action="decide" title="Record a decision for the whole group">Decide</button>
      <button class="btn-ghost" style="font-size:11px;padding:3px 8px" data-action="ticket" title="Create a ticket for the whole group">Ticket</button>
    </div>
  </div>`;
}

function drillIntoGroup(g, by) {
  // Clear existing drill-downs so they don't compound.
  DRILLDOWN_KEYS.forEach((k) => { state.filter[k] = (k.endsWith('_id') ? null : ''); });
  if (by === 'cve') state.filter.cve = g.canonical_id || g.key;
  else if (by === 'asset') { state.filter.asset_id = parseInt(g.key); state.filter.cve = ''; }
  else if (by === 'component') state.filter.component = g.key;
  else if (by === 'component_version') {
    state.filter.component = g.component || '';
    state.filter.component_version = g.component_version || '';
  } else if (by === 'asset_type') state.filter.asset_type = g.key;
  else if (by === 'owner') state.filter.owner = g.key;
  else if (by === 'business_unit') state.filter.business_unit = g.key;
  else if (by === 'ecosystem') state.filter.ecosystem = g.key;
  state.groupBy = '';
  $('groupBy').value = '';
  state.page = 1;
  state.selected.clear();
  state.allMatchingIds = null;
  loadFindings().then(() => { selectAllMatching(); });
}

async function actOnGroup(g, by, action) {
  // Pre-fill the selection with every finding in the group, then open the
  // appropriate dialog. We call /api/findings/ids with the same drill-down
  // we'd use to open the list, so the scope matches the group exactly.
  const saved = { ...state.filter };
  drillIntoGroup(g, by);
  // drillIntoGroup already queues loadFindings + selectAllMatching; wait a
  // tick for the ids call, then open the dialog.
  setTimeout(() => {
    if (action === 'decide') openDecide([...state.selected]);
    else if (action === 'ticket') openCreateTicket([...state.selected]);
  }, 600);
}

function renderActiveDrillDowns() {
  let host = document.getElementById('drillDownChips');
  if (!host) {
    host = document.createElement('div');
    host.id = 'drillDownChips';
    host.style.cssText = 'padding:4px 18px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;border-bottom:1px solid var(--rule-soft)';
    $('findingsList').parentElement.insertBefore(host, $('findingsList'));
  }
  const labels = {
    asset_id: 'asset id', component: 'component', component_version: 'version',
    owner: 'owner', business_unit: 'BU', asset_type: 'asset type',
    asset_group_id: 'asset group', ecosystem: 'ecosystem',
  };
  const chips = [];
  for (const k of DRILLDOWN_KEYS) {
    const v = state.filter[k];
    if (v !== null && v !== '' && v !== undefined) {
      chips.push(`<span class="tag" style="font-size:11px" data-drill="${k}">
        ${labels[k]}: ${esc(String(v))} <a href="#" class="link" style="margin-left:4px" data-clear="${k}">×</a>
      </span>`);
    }
  }
  if ((state.filter.bucket || []).length) {
    for (const n of state.filter.bucket) {
      const meta = (state.meta?.buckets || []).find((b) => b.number === n);
      const title = meta ? meta.title : `Bucket ${n}`;
      chips.push(`<span class="tag" style="font-size:11px" data-drill="bucket">
        bucket: ${n} · ${esc(title)} <a href="#" class="link" style="margin-left:4px" data-clear="bucket">×</a>
      </span>`);
    }
  }
  if (!chips.length) { host.innerHTML = ''; return; }
  host.innerHTML = '<span class="hint" style="font-size:11px">Drilled down:</span>' +
    chips.join('') +
    `<a href="#" class="link" style="font-size:11px" id="clearAllDrills">clear all</a>`;
  host.onclick = (e) => {
    const c = e.target.closest('[data-clear]');
    if (c) {
      e.preventDefault();
      const k = c.dataset.clear;
      state.filter[k] = (k === 'bucket') ? [] : (k.endsWith('_id') ? null : '');
      state.page = 1;
      loadFindings();
      return;
    }
    if (e.target.id === 'clearAllDrills') {
      e.preventDefault();
      DRILLDOWN_KEYS.forEach((k) => { state.filter[k] = (k.endsWith('_id') ? null : ''); });
      state.page = 1;
      loadFindings();
    }
  };
}

async function selectAllMatching() {
  const res = await api(`/api/findings/ids?${filterParams()}`);
  state.allMatchingIds = res.ids;
  res.ids.forEach((i) => state.selected.add(i));
  renderFindings();
  toast(`Selected all ${res.total.toLocaleString()} matching findings`);
}

// ---------------------------------------------------------------- detail

function closeDrawers() {
  $('detail').hidden = true;
  $('decide').hidden = true;
  $('scrim').hidden = true;
}
function openDrawer(el) {
  $('scrim').hidden = false;
  el.hidden = false;
  el.scrollTop = 0;
}

async function openDetail(id) {
  const el = $('detail');
  openDrawer(el);
  el.innerHTML = '<div class="spin">Loading\u2026</div>';
  const f = await api(`/api/findings/${id}`);

  const kv = (label, value, mono = true) => value === null || value === undefined || value === ''
    ? `<dt>${label}</dt><dd class="na">not recorded</dd>`
    : `<dt>${label}</dt><dd${mono ? '' : ' style="font-family:var(--sans)"'}>${esc(value)}</dd>`;

  const ledger = f.risk.factors.map((x) => `
    <div class="ledger-row ${x.applied ? '' : 'is-unapplied'}">
      <div>${esc(x.name)}<small>${esc(x.note)}${x.applied ? '' : ' \u2014 no data'}</small></div>
      <div class="ledger-pts">${x.applied ? (x.points > 0 ? '+' + x.points : '0') : '\u2014'}</div>
    </div>`).join('');

  const caveat = f.risk.unknown_inputs.length
    ? `<div class="caveat"><strong>This score is incomplete.</strong> ${esc(f.risk.unknown_inputs.join(', '))}
       ${f.risk.unknown_inputs.length === 1 ? 'is' : 'are'} not available for this asset, so
       ${f.risk.unknown_inputs.length === 1 ? 'that factor' : 'those factors'} contributed nothing.
       Treat the number as a floor, not a measurement.</div>`
    : '';

  el.innerHTML = `
    <div class="drawer-head">
      <div>
        <h2>${esc(f.vuln.canonical_id)}</h2>
        <p>${esc(f.vuln.title || '')}</p>
      </div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      ${f.decision ? stampHtml(f.decision) : `
        <div class="stamp is-lapsed">
          <div class="stamp-disp">No decision on record</div>
          <div class="stamp-meta">This finding has not been adjudicated. It counts fully toward the backlog.</div>
          <div class="stamp-actions">
            <button class="btn btn-seal" onclick="openDecide([${f.id}])">Record a decision</button>
            ${submitExceptionButton([f.id])}
          </div>
        </div>`}

      <div class="sec" style="margin-top:24px">
        <h3>Risk</h3>
        <div class="kv" style="margin-bottom:14px">
          ${kv('Effective severity', f.risk.adjusted
            ? `${f.risk.effective_severity} (adjusted from ${f.risk.base_severity})`
            : f.risk.effective_severity)}
          ${kv('Priority', `${f.risk.priority} \u00b7 score ${f.risk.score}`)}
          ${kv('Remediation due', f.risk.sla_due ? fmtDate(f.risk.sla_due) + (f.risk.sla_overdue ? '  (overdue)' : '') : null)}
          ${kv('CVSS', f.vuln.cvss_score ? `${f.vuln.cvss_score}${f.vuln.cvss_vector ? ' \u00b7 ' + f.vuln.cvss_vector : ''}` : null)}
          ${kv('EPSS', f.vuln.epss_score !== null && f.vuln.epss_score !== undefined ? f.vuln.epss_score : null)}
          ${kv('CISA KEV', f.vuln.kev ? 'listed' : 'not listed')}
        </div>
        <div class="ledger">${ledger}
          <div class="ledger-total"><span>Score</span><span>${f.risk.score}</span></div>
        </div>
        ${caveat}
      </div>

      <div class="sec">
        <h3>Where it is</h3>
        <dl class="kv">
          ${kv('Asset', f.asset.name)}
          ${kv('Type', f.asset.type)}
          ${kv('Operating system', f.asset.os)}
          ${kv('Address', f.asset.ip)}
          ${kv('Cloud account', f.asset.cloud_account)}
          ${kv('Region', f.asset.region)}
          ${kv('Environment', f.asset.environment === 'unknown' ? null : f.asset.environment)}
          ${kv('Internet facing', f.asset.internet_facing === null ? null : (f.asset.internet_facing ? 'yes' : 'no'))}
          ${kv('Data classification', f.asset.data_classification)}
          ${kv('Component', f.component ? `${f.component}${f.component_version ? ' ' + f.component_version : ''}` : null)}
          ${kv('Location', f.location)}
        </dl>
      </div>

      <div class="sec">
        <h3>Source record</h3>
        <dl class="kv">
          ${kv('Reported by', f.source)}
          ${kv('Source identifier', f.source_finding_id)}
          ${kv('Source severity', f.source_severity)}
          ${kv('First detected', fmtDate(f.first_detected))}
          ${kv('Last seen', fmtDate(f.last_seen))}
          ${kv('Status', f.status)}
        </dl>
        ${f.source_url ? `<p style="margin-top:10px"><a href="${esc(f.source_url)}" target="_blank" rel="noopener">Open in ${esc(f.source)}</a></p>` : ''}
      </div>

      ${f.vuln.description ? `<div class="sec"><h3>Description</h3><div class="prose">${esc(f.vuln.description)}</div></div>` : ''}
      ${f.vuln.remediation ? `<div class="sec"><h3>Remediation</h3><div class="prose">${esc(f.vuln.remediation)}</div></div>` : ''}

      ${f.decision_history.length ? `<div class="sec"><h3>Decision history</h3>
        ${f.decision_history.map(historyHtml).join('')}</div>` : ''}

      ${lifecycleHtml(f)}

      <div class="sec" id="findingTickets" data-finding-id="${f.id}">
        <h3>Tickets</h3>
        <div id="findingTicketList"><span class="na">Loading…</span></div>
        <button class="btn-ghost" style="margin-top:8px;font-size:12px" onclick="openCreateTicket([${f.id}])">Create ticket</button>
      </div>
    </div>`;
  loadFindingTickets(f.id);
}

function lifecycleHtml(f) {
  const kv = (label, value) => value === null || value === undefined || value === ''
    ? `<dt>${label}</dt><dd class="na">not recorded</dd>` : `<dt>${label}</dt><dd>${esc(value)}</dd>`;
  const ageDays = daysBetween(f.first_detected, f.closed_at);
  const closedNote = f.closed_at
    ? `${fmtDate(f.closed_at)}${ageDays !== null ? ` (${ageDays} days after detection${
        f.risk.sla_due ? (new Date(f.closed_at) <= new Date(f.risk.sla_due) ? ', within SLA' : ', after SLA') : ''})` : ''}`
    : null;
  let action = '';
  if (f.status === 'fixed' || f.status === 'stale') {
    action = `<p class="hint" style="margin:10px 0 8px">${f.status === 'stale'
      ? 'The source stopped reporting this finding, so it is presumed remediated. Confirm the fix before treating it as closed.'
      : 'The source reports this resolved. Confirm the fix is effective.'}</p>
      <button class="btn btn-seal" onclick="verifyFinding(${f.id})">Verify fix</button>`;
  } else if (f.status === 'verified_fixed') {
    action = `<p style="margin-top:10px">Verified fixed${f.verified_by ? ' by ' + esc(f.verified_by) : ''}${f.verified_at ? ' on ' + fmtDate(f.verified_at) : ''}.</p>`;
  }
  const events = f.timeline || [];
  const timeline = events.length ? `<ul class="timeline" style="margin-top:14px">${events.map((e) => `
      <li class="tl-item k-${esc(e.kind)} e-${esc(e.event)}">
        ${esc(e.summary)}
        <span class="tl-meta">${fmtDate(e.ts)} · ${esc(e.kind)}${e.actor ? ' · ' + esc(e.actor) : ''}${e.note && e.kind === 'status' && e.event !== 'verified' ? ' · ' + esc(e.note) : ''}</span>
      </li>`).join('')}</ul>` : '';
  return `<div class="sec">
    <h3>Lifecycle</h3>
    <dl class="kv">
      ${kv('Status', STATUS_LABEL[f.status] || f.status)}
      ${kv('Closed', closedNote)}
      ${kv('Times reopened', String(f.reopened_count || 0))}
      ${kv('Last reported by source', f.last_synced_at ? fmtDate(f.last_synced_at) : null)}
    </dl>
    ${action}
    ${timeline}
  </div>`;
}

function stampHtml(d) {
  const lapsed = ['expired', 'revoked', 'rejected'].includes(d.state);
  const pending = d.state === 'pending_approval';
  const until = d.expires_at ? daysUntil(d.expires_at) : null;
  return `<div class="stamp ${lapsed ? 'is-lapsed' : ''} ${pending ? 'is-pending' : ''}">
    <div class="stamp-disp">${esc(dispLabel(d.disposition))}${pending ? ' \u2014 awaiting approval' : ''}${lapsed ? ' \u2014 ' + esc(d.state) : ''}</div>
    <div class="stamp-meta">
      Scope: ${esc(d.scope_label || d.scope_key)}<br>
      Requested by ${esc(d.requested_by)} on ${fmtDate(d.requested_at)}${d.approved_by ? `, ${d.state === 'rejected' ? 'rejected' : 'approved'} by ${esc(d.approved_by)} on ${fmtDate(d.decided_at)}` : ''}<br>
      ${d.expires_at ? `Expires ${fmtDate(d.expires_at)}${until !== null ? ` (${until} days)` : ''}` : 'No expiry'}
      ${d.review_due ? ` \u00b7 review due ${fmtDate(d.review_due)}` : ''}<br>
      Covered ${d.applied_count} findings when recorded
      ${d.adjusted_severity ? `<br>Severity set to ${esc(d.adjusted_severity)}` : ''}
      ${d.assigned_to ? `<br>Assigned to ${esc(d.assigned_to)}` : ''}
    </div>
    <div class="prose" style="margin-top:10px;font-size:12.5px">${esc(d.justification)}</div>
    ${d.compensating_controls ? `<div class="prose" style="margin-top:8px;font-size:12px;color:var(--slate)"><strong>Compensating controls:</strong> ${esc(d.compensating_controls)}</div>` : ''}
    <div class="stamp-actions">${decisionActions(d)}</div>
  </div>`;
}

function decisionActions(d) {
  const me = currentUser();
  const isApprover = (state.meta?.approvers || []).includes(me);
  const out = [];
  if (d.state === 'pending_approval' && isApprover && d.requested_by !== me) {
    out.push(`<button class="btn btn-seal" onclick="decideOn(${d.id}, true)">Approve</button>`);
    out.push(`<button class="btn-ghost" onclick="decideOn(${d.id}, false)">Reject</button>`);
  } else if (d.state === 'pending_approval') {
    out.push(`<span class="hint">Waiting on ${esc(d.approver || 'an approver')}. You cannot approve your own request.</span>`);
  }
  if (d.state === 'approved') out.push(`<button class="btn-ghost" onclick="revokeDecision(${d.id})">Revoke</button>`);
  if (d.state === 'expired') out.push(`<button class="btn-ghost" onclick="renewDecision(${d.id})">Renew</button>`);
  return out.join('');
}

function historyHtml(d) {
  return `<div class="ledger-row" style="grid-template-columns:1fr">
    <div><strong>${esc(dispLabel(d.disposition))}</strong> \u00b7 <span class="tag">${esc(d.state)}</span>
      <small>${esc(d.requested_by)} on ${fmtDate(d.requested_at)}${d.expires_at ? ` \u00b7 expires ${fmtDate(d.expires_at)}` : ''}</small>
      <small style="color:var(--slate);margin-top:4px">${esc(d.justification.slice(0, 220))}${d.justification.length > 220 ? '\u2026' : ''}</small>
    </div></div>`;
}

async function decideOn(id, approve) {
  const note = prompt(approve ? 'Approval note (optional)' : 'Reason for rejecting');
  if (approve === false && !note) return;
  try {
    await api(`/api/adjudications/${id}/decision`, {
      method: 'POST', body: JSON.stringify({ approve, note }),
    });
    toast(approve ? 'Approved. The decision is now in force.' : 'Rejected.');
    closeDrawers();
    refresh();
  } catch (e) { showProblems(e); }
}

async function revokeDecision(id) {
  const reason = prompt('Why is this being revoked? (recorded in the audit trail)');
  if (!reason) return;
  try {
    await api(`/api/adjudications/${id}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) });
    toast('Revoked. The risk is live again.');
    closeDrawers();
    refresh();
  } catch (e) { showProblems(e); }
}

async function renewDecision(id) {
  const justification = prompt('Justification for renewing (this is re-argued, not copied)');
  if (!justification) return;
  const expires = prompt('New expiry date (YYYY-MM-DD)');
  if (!expires) return;
  const approver = prompt(`Approver (${(state.meta.approvers || []).join(', ')})`);
  try {
    await api(`/api/adjudications/${id}/renew`, {
      method: 'POST', body: JSON.stringify({ justification, expires_at: expires, approver }),
    });
    toast('Renewal submitted for approval.');
    closeDrawers();
    refresh();
  } catch (e) { showProblems(e); }
}

function showProblems(e) {
  if (e.problems) toast(e.problems.join('  '), true);
  else toast(e.message, true);
}

// ---------------------------------------------------------------- decide

async function openDecide(findingIds, suggested) {
  const el = $('decide');
  $('detail').hidden = true;
  openDrawer(el);
  const sug = suggested || {};
  state.decideDraft = {
    ids: findingIds,
    disposition: sug.disposition || null,
    scope: sug.scope || 'finding',
    justification: '', approver: '', expires: '',
    adjusted_severity: sug.adjusted_severity || '',
    assigned_to: '', remediation_due: '', compensating: '',
    _context: null, _templates: null,
  };
  renderDecide();
  previewScope();
  loadDecideContext(findingIds);
  loadDecideTemplates();
}

async function loadDecideContext(ids) {
  const p = new URLSearchParams();
  ids.slice(0, 2000).forEach((i) => p.append('finding_ids', i));
  try {
    const ctx = await api(`/api/decide/context?${p}`);
    state.decideDraft._context = ctx;
    // Pre-fill suggested expiry if the user hasn't typed one yet
    if (!state.decideDraft.expires && ctx.suggested_expiry_days) {
      const date = new Date(Date.now() + ctx.suggested_expiry_days * 86400000);
      state.decideDraft.expires = date.toISOString().slice(0, 10);
    }
    renderDecide();
  } catch (e) { /* context is optional */ }
}

async function loadDecideTemplates() {
  try {
    const templates = await api('/api/decision-templates?enabled_only=true');
    state.decideDraft._templates = templates;
    renderDecide();
  } catch (e) { /* templates optional */ }
}

function applyDecideTemplate(tId) {
  const t = (state.decideDraft._templates || []).find((x) => x.id === Number(tId));
  if (!t) return;
  const d = state.decideDraft;
  d.disposition = t.disposition;
  d.scope = t.scope || d.scope;
  d.justification = t.justification_text || '';
  d.compensating = t.compensating_controls || '';
  d.adjusted_severity = t.adjusted_severity || '';
  if (t.expiry_days) {
    const date = new Date(Date.now() + t.expiry_days * 86400000);
    d.expires = date.toISOString().slice(0, 10);
  }
  if (t.remediation_days) {
    const date = new Date(Date.now() + t.remediation_days * 86400000);
    d.remediation_due = date.toISOString().slice(0, 10);
  }
  renderDecide();
  previewScope();
}

function renderDecide(problems) {
  const d = state.decideDraft;
  const el = $('decide');
  const meta = state.meta;
  const isRisk = ['accept_risk', 'adjust_risk', 'false_positive'].includes(d.disposition);
  const minChars = meta.policy.min_justification_chars;
  const short = d.justification.trim().length < minChars;

  el.innerHTML = `
    <div class="drawer-head">
      <div>
        <h2>Record a decision</h2>
        <p>${d.ids.length.toLocaleString()} finding${d.ids.length === 1 ? '' : 's'} selected</p>
      </div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      ${problems ? `<div class="problems"><ul>${problems.map((p) => `<li>${esc(p)}</li>`).join('')}</ul></div>` : ''}

      ${renderDecideContext(d._context)}

      ${renderDecideTemplatePicker(d._templates)}

      <div class="sec">
        <h3>Disposition</h3>
        <div class="disp-grid" id="dispGrid">
          ${meta.dispositions.map((x) => `
            <button class="disp ${d.disposition === x.value ? 'is-on' : ''}" data-v="${x.value}">
              <b>${esc(x.label)}</b>
              <small>${x.is_risk_decision ? 'Needs approval and an expiry' : 'Routes work, takes effect now'}</small>
            </button>`).join('')}
        </div>
      </div>

      <div class="sec">
        <h3>What this decision covers</h3>
        <div class="field-group">
          <label for="scopeSel">Attach the decision to</label>
          <select id="scopeSel" class="field">
            ${meta.scopes.map((s) => `<option value="${s.value}"${d.scope === s.value ? ' selected' : ''}>${esc(s.label)}</option>`).join('')}
          </select>
          <div class="hint">A wider scope keeps covering findings that arrive after today.
            A narrower one applies only to what you selected.</div>
        </div>
        <div id="coverage"><div class="spin">Working out coverage\u2026</div></div>
      </div>

      <div class="sec">
        <h3>Justification</h3>
        <div class="field-group">
          <textarea id="justInput" class="field" placeholder="Why is this the right call? Record the reasoning someone will need in six months, not a restatement of the finding.">${esc(d.justification)}</textarea>
          <div class="hint"><span class="counter ${short ? 'is-short' : ''}">${d.justification.trim().length} / ${minChars} characters minimum</span></div>
        </div>
        ${isRisk ? `<div class="field-group">
          <label for="compInput">Compensating controls (optional)</label>
          <textarea id="compInput" class="field" style="min-height:60px" placeholder="What reduces the exposure in the meantime?">${esc(d.compensating)}</textarea>
        </div>` : ''}
      </div>

      ${d.disposition === 'adjust_risk' ? `
      <div class="sec">
        <h3>Adjusted rating</h3>
        <div class="field-group">
          <label for="sevSel">Set effective severity to</label>
          <select id="sevSel" class="field">
            <option value="">Leave severity as reported</option>
            ${SEV_ORDER.map((s) => `<option value="${s}"${d.adjusted_severity === s ? ' selected' : ''}>${s}</option>`).join('')}
          </select>
          <div class="hint">The severity the source reported is kept and shown alongside this, so the
            change is visible rather than overwritten.</div>
        </div>
      </div>` : ''}

      ${isRisk ? `
      <div class="sec">
        <h3>Approval and expiry</h3>
        <div class="field-row">
          <div class="field-group">
            <label for="apprSel">Approver</label>
            <select id="apprSel" class="field">
              <option value="">Choose an approver</option>
              ${meta.approvers.filter((a) => a !== currentUser()).map((a) =>
                `<option value="${esc(a)}"${d.approver === a ? ' selected' : ''}>${esc(a)}</option>`).join('')}
            </select>
          </div>
          <div class="field-group">
            <label for="expInput">Expires on</label>
            <input id="expInput" type="date" class="field" value="${esc(d.expires)}">
          </div>
        </div>
        <div class="hint">Nothing changes until the approver signs off. When the expiry passes, the
          decision lapses on its own and these findings return to the backlog at full weight.</div>
      </div>` : `
      <div class="sec">
        <h3>Assignment</h3>
        <div class="field-row">
          <div class="field-group">
            <label for="assignSel">Assign to</label>
            <select id="assignSel" class="field">
              <option value="">Unassigned</option>
              ${meta.users.map((u) => `<option value="${esc(u)}"${d.assigned_to === u ? ' selected' : ''}>${esc(u)}</option>`).join('')}
            </select>
          </div>
          <div class="field-group">
            <label for="dueInput">Remediation due</label>
            <input id="dueInput" type="date" class="field" value="${esc(d.remediation_due)}">
          </div>
        </div>
      </div>`}
    </div>
    <div class="drawer-foot">
      <span class="hint">${isRisk ? 'Submits for approval.' : d.disposition ? 'Takes effect immediately.' : 'Pick a disposition to continue.'}</span>
      <div style="display:flex;gap:8px">
        <button class="btn-ghost" onclick="closeDrawers()">Cancel</button>
        <button class="btn btn-seal" id="submitDecision" ${!d.disposition ? 'disabled' : ''}>
          ${isRisk ? 'Submit for approval' : 'Record decision'}</button>
      </div>
    </div>`;

  const tplEl = $('decideTemplate');
  if (tplEl) tplEl.onchange = (e) => { if (e.target.value) applyDecideTemplate(e.target.value); };
  $('dispGrid').onclick = (e) => {
    const b = e.target.closest('.disp');
    if (!b) return;
    d.disposition = b.dataset.v;
    suggestDefaults();
  };
  $('scopeSel').onchange = (e) => { d.scope = e.target.value; previewScope(); };
  $('justInput').oninput = (e) => {
    d.justification = e.target.value;
    const c = el.querySelector('.counter');
    c.textContent = `${d.justification.trim().length} / ${minChars} characters minimum`;
    c.classList.toggle('is-short', d.justification.trim().length < minChars);
  };
  const bind = (id, key) => { const n = $(id); if (n) n.onchange = (e) => { d[key] = e.target.value; }; };
  bind('compInput', 'compensating');
  bind('sevSel', 'adjusted_severity');
  bind('apprSel', 'approver');
  bind('expInput', 'expires');
  bind('assignSel', 'assigned_to');
  bind('dueInput', 'remediation_due');
  const ci = $('compInput'); if (ci) ci.oninput = (e) => { d.compensating = e.target.value; };
  $('submitDecision').onclick = submitDecision;
}

async function suggestDefaults() {
  const d = state.decideDraft;
  if (['accept_risk', 'adjust_risk', 'false_positive'].includes(d.disposition) && !d.expires) {
    try {
      const s = await api(`/api/adjudications/defaults/suggest?disposition=${d.disposition}&severity=high`);
      if (s.expires_at) d.expires = s.expires_at;
    } catch (e) { /* suggestion only */ }
  }
  renderDecide();
  previewScope();
}

function renderDecideTemplatePicker(templates) {
  if (!templates || !templates.length) return '';
  return `<div class="sec" style="padding-top:8px">
    <h3 style="margin-bottom:6px">Start from a template</h3>
    <select id="decideTemplate" class="field" style="max-width:420px">
      <option value="">— Blank decision —</option>
      ${templates.map((t) => `<option value="${t.id}">${esc(t.name)} · ${esc(t.disposition.replace('_', ' '))}${
        t.expiry_days ? ` · ${t.expiry_days}d expiry` : ''
      }</option>`).join('')}
    </select>
    <div class="hint" style="margin-top:4px">Templates pre-fill disposition, scope, justification, expiry, and compensating controls. Edit anything you need to.</div>
  </div>`;
}

function renderDecideContext(ctx) {
  if (!ctx) return '<div class="sec"><div class="hint">Loading context…</div></div>';
  const vc = ctx.vuln_context, ac = ctx.asset_context;
  const kev = vc.kev_count ? `<span class="tag tag-kev">KEV ${vc.kev_count} of ${ctx.unique_vulns}</span>` : '';
  const epss = vc.max_epss !== null ? `<span class="tag">max EPSS ${(vc.max_epss * 100).toFixed(0)}%</span>` : '';
  const cvss = vc.max_cvss !== null ? `<span class="tag">max CVSS ${vc.max_cvss}</span>` : '';
  const fix = vc.fix_available_count ? `<span class="tag">fix in ${vc.fix_available_count}/${ctx.finding_count}</span>` : '';
  const envs = Object.entries(ac.environments).map(([k, v]) =>
    `<span class="tag">${esc(k)}: ${v}</span>`).join(' ');
  const owners = Object.entries(ac.owners).slice(0, 5).map(([k, v]) =>
    `<span class="tag">${esc(k)}: ${v}</span>`).join(' ');
  const bus = Object.entries(ac.business_units).slice(0, 5).map(([k, v]) =>
    `<span class="tag">${esc(k)}: ${v}</span>`).join(' ');
  const inet = ac.internet_facing;
  const inetChip = (inet.true || inet.false)
    ? `<span class="tag${inet.true ? ' tag-overdue' : ''}">internet-facing: ${inet.true} yes / ${inet.false} no / ${inet.unknown} unk</span>`
    : '';

  const priorHtml = ctx.prior_decisions_on_scope.length
    ? `<details open style="margin-top:8px"><summary style="cursor:pointer;font-weight:600">Prior decisions on this scope (${ctx.prior_decisions_on_scope.length})</summary>
       ${ctx.prior_decisions_on_scope.slice(0, 8).map(priorAdjHtml).join('')}</details>`
    : '';
  const peerHtml = ctx.peer_decisions_on_cve.length
    ? `<details style="margin-top:8px"><summary style="cursor:pointer;font-weight:600">Peer decisions on the same CVE (${ctx.peer_decisions_on_cve.length})</summary>
       ${ctx.peer_decisions_on_cve.slice(0, 8).map(priorAdjHtml).join('')}</details>`
    : '';
  const ticketsHtml = ctx.related_tickets.length
    ? `<details style="margin-top:8px"><summary style="cursor:pointer;font-weight:600">Related tickets (${ctx.related_tickets.length})</summary>
       ${ctx.related_tickets.slice(0, 10).map((t) => `
         <div class="ledger-row"><div>
           ${t.external_url ? `<a href="${esc(t.external_url)}" target="_blank">${esc(t.external_id)}</a>` : esc(t.external_id)}
           <small>${esc(t.summary || '')}</small>
         </div><div class="ledger-pts">${esc(t.status)}</div></div>`).join('')}</details>`
    : '';

  const empty = !priorHtml && !peerHtml && !ticketsHtml;

  return `<div class="sec" style="border-left:3px solid var(--ink);padding-left:12px">
    <h3 style="margin-bottom:6px">Context</h3>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px">
      ${kev} ${epss} ${cvss} ${fix}
    </div>
    <div style="font-size:12px;margin-bottom:4px"><b>Spans</b>: ${ctx.finding_count} findings on ${ctx.asset_count} assets, ${ctx.unique_vulns} unique CVE${ctx.unique_vulns === 1 ? '' : 's'}</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:4px">${envs} ${inetChip}</div>
    ${owners ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:4px"><span class="hint" style="font-size:11px">owners:</span>${owners}</div>` : ''}
    ${bus ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:4px"><span class="hint" style="font-size:11px">business units:</span>${bus}</div>` : ''}
    ${empty ? '<div class="hint" style="font-size:12px;margin-top:6px">No prior decisions, peer decisions, or tickets on record for this scope.</div>' : ''}
    ${priorHtml}
    ${peerHtml}
    ${ticketsHtml}
    ${ctx.suggested_expiry_days ? `<div class="hint" style="font-size:11px;margin-top:8px">Policy suggests an expiry of ${ctx.suggested_expiry_days} days for the worst severity in scope${vc.kev_count ? ' (KEV-aware)' : ''}.</div>` : ''}
  </div>`;
}

function priorAdjHtml(a) {
  const stateColor = a.state === 'approved' ? 'var(--success, var(--ink))'
                    : a.state === 'pending_approval' ? 'var(--notice)'
                    : 'var(--slate)';
  return `<div class="ledger-row" style="padding:4px 0">
    <div style="font-size:12px">
      <b>${esc(dispLabel(a.disposition))}</b>
      <span style="color:${stateColor}"> · ${esc(a.state.replace('_', ' '))}</span>
      ${a.adjusted_severity ? ` · → ${esc(a.adjusted_severity)}` : ''}
      <small>${esc(a.scope_type)}: ${esc(a.scope_label || a.scope_key)}</small>
      <small style="color:var(--slate);margin-top:2px">${esc(a.justification.slice(0, 180))}${a.justification.length > 180 ? '…' : ''}</small>
      <small style="color:var(--slate)">requested by ${esc(a.requested_by)}${a.approved_by ? `, decided by ${esc(a.approved_by)}` : ''}${a.decided_at ? ' on ' + fmtDate(a.decided_at) : ''}${a.expires_at ? ' · expires ' + fmtDate(a.expires_at) : ''}</small>
    </div>
  </div>`;
}

async function previewScope() {
  const d = state.decideDraft;
  const box = $('coverage');
  if (!box) return;
  try {
    const p = await api('/api/adjudications/preview', {
      method: 'POST', body: JSON.stringify({ finding_ids: d.ids, scope: d.scope }),
    });
    const sample = p.plans.slice(0, 6);
    const beyond = p.plans.reduce((acc, x) => acc + (x.coverage.includes('beyond your selection') ? 1 : 0), 0);
    box.innerHTML = `<div class="coverage">
      This creates <b>${p.decisions_to_create.toLocaleString()}</b> decision${p.decisions_to_create === 1 ? '' : 's'}
      from <b>${p.selected.toLocaleString()}</b> selected finding${p.selected === 1 ? '' : 's'}.
      ${beyond ? `<br><strong style="color:var(--seal)">${beyond} of them reach beyond what you selected.</strong>` : ''}
      <ul>${sample.map((x) => `<li>${esc(x.scope_label)} \u2014 ${esc(x.coverage)}</li>`).join('')}</ul>
      ${p.plans.length > sample.length ? `<div class="hint">\u2026 and ${(p.plans.length - sample.length).toLocaleString()} more.</div>` : ''}
    </div>`;
  } catch (e) {
    box.innerHTML = `<div class="hint is-warn">Could not work out coverage: ${esc(e.message)}</div>`;
  }
}

async function submitDecision() {
  const d = state.decideDraft;
  const body = {
    finding_ids: d.ids,
    disposition: d.disposition,
    scope: d.scope,
    justification: d.justification,
    approver: d.approver || null,
    expires_at: d.expires || null,
    adjusted_severity: d.adjusted_severity || null,
    assigned_to: d.assigned_to || null,
    remediation_due: d.remediation_due || null,
    compensating_controls: d.compensating || null,
    filter: state.filter,
  };
  $('submitDecision').disabled = true;
  try {
    const res = await api('/api/adjudications', { method: 'POST', body: JSON.stringify(body) });
    toast(`Recorded ${res.created} decision${res.created === 1 ? '' : 's'}.`);
    state.selected.clear();
    state.allMatchingIds = null;
    closeDrawers();
    loadFindings();
  } catch (e) {
    $('submitDecision').disabled = false;
    if (e.problems) renderDecide(e.problems);
    else toast(e.message, true);
  }
}

// ---------------------------------------------------------------- register

async function loadRegister() {
  const sum = $('regQueueSummary');
  const pendingMode = state.register.state === 'pending_approval';
  const useQueue = pendingMode && state.register.mine;
  let decisions = [];
  let queueMeta = null;

  if (useQueue) {
    queueMeta = await api('/api/adjudications/queue?approver=me');
    decisions = queueMeta.decisions;
  } else {
    const p = new URLSearchParams();
    if (state.register.state) p.append('state', state.register.state);
    if (state.register.q) p.set('q', state.register.q);
    if (state.register.due) p.set('due_within_days', '30');
    p.set('page_size', '200');
    const r = await api(`/api/adjudications?${p}`);
    decisions = r.adjudications;
  }

  // Summary line for the queue mode
  if (useQueue && queueMeta) {
    const bands = queueMeta.age_bands;
    sum.innerHTML = `<b>${queueMeta.total}</b> decisions awaiting your approval \u00b7
      <span style="color:var(--slate)">new ${bands.new} \u00b7 aging ${bands.aging}
      \u00b7 <b${bands.stale > 0 ? ' style="color:var(--seal)"' : ''}>stale ${bands.stale}</b></span>`;
  } else if (pendingMode) {
    sum.innerHTML = `<span class="hint">Tick "Only mine" to see just the decisions you can approve, with bulk actions.</span>`;
  } else {
    sum.innerHTML = '';
  }

  if (!decisions.length) {
    $('registerList').innerHTML = `<div class="empty"><b>${useQueue ? 'Nothing waiting on you.' : 'No decisions on record yet.'}</b>
      ${useQueue ? '' : 'Adjudicate findings from the Findings tab and they appear here.'}</div>`;
    updateBulkBar();
    return;
  }

  // Keep selection coherent with what's currently shown
  const shownIds = new Set(decisions.map((d) => d.id));
  for (const id of [...state.register.selected]) {
    if (!shownIds.has(id)) state.register.selected.delete(id);
  }

  $('registerList').innerHTML = decisions.map((d) => {
    const until = daysUntil(d.expires_at);
    const lapsing = until !== null && until <= 30 && d.state === 'approved';
    const checkable = useQueue && d.can_approve;
    const checked = state.register.selected.has(d.id);
    const ageStr = d.age_days !== undefined ? `${d.age_days}d old` : '';
    return `<div class="row ${checked ? 'is-selected' : ''}" data-adj="${d.id}" style="grid-template-columns:30px 30px 1fr 190px 150px 130px">
      <div class="edge ${d.state === 'approved' ? 'sev-critical' : d.state === 'pending_approval' ? 'sev-medium' : 'sev-low'}"></div>
      <div class="row-check">${checkable
        ? `<label class="checkbox"><input type="checkbox" class="reg-check" data-id="${d.id}" ${checked ? 'checked' : ''}><span></span></label>`
        : ''}</div>
      <div class="row-main">
        <div class="row-id">${esc(dispLabel(d.disposition))}</div>
        <div class="row-title">${esc(d.scope_label || d.scope_key)}</div>
        <div class="row-meta">
          <span>#${d.id}</span>
          <span>${esc(d.scope_type)}</span>
          <span>${d.applied_count} findings at decision</span>
          ${d.adjusted_severity ? `<span>\u2192 ${esc(d.adjusted_severity)}</span>` : ''}
          ${ageStr ? `<span${d.age_days >= 14 ? ' style="color:var(--seal)"' : ''}>${ageStr}</span>` : ''}
        </div>
      </div>
      <div class="row-asset">${esc(d.requested_by)}
        <small>${d.approved_by ? 'decided by ' + esc(d.approved_by) : 'awaiting ' + esc(d.approver || 'approver')}</small>
      </div>
      <div class="row-asset">${d.expires_at ? fmtDate(d.expires_at) : '\u2014'}
        <small>${d.expires_at ? (until >= 0 ? until + ' days left' : Math.abs(until) + ' days ago') : 'no expiry'}</small>
      </div>
      <div class="row-state">
        <span class="tag ${d.state === 'approved' ? 'tag-decided' : d.state === 'pending_approval' ? 'tag-pending' : 'tag-muted'}">${esc(d.state.replace('_', ' '))}</span>
        ${lapsing ? '<span class="tag tag-overdue">Lapsing</span>' : ''}
      </div>
    </div>`;
  }).join('');
  $('registerList').onclick = (e) => {
    const cb = e.target.closest('.reg-check');
    if (cb) {
      const id = Number(cb.dataset.id);
      if (cb.checked) state.register.selected.add(id);
      else state.register.selected.delete(id);
      updateBulkBar();
      return;
    }
    const row = e.target.closest('[data-adj]');
    if (row) openRegisterDetail(Number(row.dataset.adj));
  };
  updateBulkBar();
}

function updateBulkBar() {
  const n = state.register.selected.size;
  $('regBulkBar').hidden = n === 0;
  $('regBulkCount').textContent = `${n} selected`;
}

async function bulkDecide(approve) {
  const ids = [...state.register.selected];
  if (!ids.length) return;
  const note = approve
    ? prompt(`Approving ${ids.length} decision${ids.length === 1 ? '' : 's'}. Optional note:`, '')
    : prompt(`Rejecting ${ids.length} decision${ids.length === 1 ? '' : 's'}. Reason:`, '');
  if (note === null) return;    // cancelled
  if (!approve && !note.trim()) { toast('A rejection needs a reason.', true); return; }
  try {
    const r = await api('/api/adjudications/bulk-decide', {
      method: 'POST',
      body: JSON.stringify({ adjudication_ids: ids, approve, note }),
    });
    toast(`${r.succeeded} ${approve ? 'approved' : 'rejected'}${r.failed ? `, ${r.failed} failed` : ''}`);
    if (r.failed) {
      alert('Some decisions could not be processed:\n' +
            r.results.failed.map((f) => `#${f.id}: ${f.error}`).join('\n'));
    }
    state.register.selected.clear();
    loadRegister();
  } catch (e) {
    toast(e.message || 'Bulk decide failed', true);
  }
}

async function openRegisterDetail(id) {
  const el = $('detail');
  openDrawer(el);
  el.innerHTML = '<div class="spin">Loading\u2026</div>';
  const d = await api(`/api/adjudications/${id}`);
  el.innerHTML = `
    <div class="drawer-head">
      <div><h2>Decision #${d.id}</h2><p>${esc(dispLabel(d.disposition))} \u00b7 ${esc(d.state.replace('_', ' '))}</p></div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      ${stampHtml(d)}
      <div class="sec" style="margin-top:24px">
        <h3>Findings covered when recorded (${d.findings.length}${d.findings_truncated ? '+' : ''})</h3>
        ${d.findings.map((f) => `<div class="ledger-row">
          <div><span class="mono">${esc(f.vuln)}</span><small>${esc(f.asset)} \u00b7 ${esc(f.source)}${f.component ? ' \u00b7 ' + esc(f.component) : ''}</small></div>
          <div class="ledger-pts">${esc(f.severity)}</div></div>`).join('')}
        ${d.findings_truncated ? '<div class="hint">Showing the first 500. Export the register for the full list.</div>' : ''}
      </div>
      <div class="sec">
        <h3>Audit trail</h3>
        ${d.audit.map((a) => `<div class="ledger-row"><div>${esc(a.summary)}
          <small>${esc(a.actor)} \u00b7 ${fmtDate(a.ts)}</small></div>
          <div class="ledger-pts">${esc(a.action.split('.').pop())}</div></div>`).join('')}
      </div>
      ${d.scope_filter ? `<div class="sec"><h3>Filter in use when this was raised</h3>
        <div class="prose mono" style="font-size:11.5px">${esc(JSON.stringify(d.scope_filter))}</div></div>` : ''}
    </div>`;
}

// ---------------------------------------------------------------- activity

async function loadActivity() {
  $('lcWindow').onchange = loadLifecycleMetrics;
  $('trendGranularity').onchange = loadTrendChart;
  $('trendWindow').onchange = loadTrendChart;
  $('loadRemediated').onclick = loadRemediated;
  $('exportRemediated').onclick = (e) => { e.preventDefault(); window.open(remediatedUrl('/api/export/remediated.csv')); };
  loadLifecycleMetrics();
  loadTrendChart();
  loadRemediated();
  const rows = (await api('/api/audit?limit=300')).events || [];
  $('auditList').innerHTML = rows.length ? rows.map((e) => `
    <div class="row" style="grid-template-columns:30px 1fr 140px 150px;cursor:default">
      <div class="edge sev-low"></div>
      <div class="row-main">
        <div class="row-id" style="font-size:12.5px;font-weight:500">${esc(e.summary || e.action)}</div>
        <div class="row-meta"><span>${esc(e.action)}</span>${e.entity_id ? `<span>${esc(e.entity_type)} ${esc(e.entity_id)}</span>` : ''}</div>
      </div>
      <div class="row-asset">${esc(e.actor)}</div>
      <div class="row-asset">${new Date(e.ts).toLocaleString()}</div>
    </div>`).join('') : '<div class="empty"><b>Nothing recorded yet.</b></div>';
}

async function loadLifecycleMetrics() {
  const el = $('lifecycleMetrics');
  el.innerHTML = '<div class="spin">Loading…</div>';
  let m;
  try { m = await api(`/api/lifecycle/metrics?days=${$('lcWindow').value}`); }
  catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  const n = (v, suffix = '') => (v === null || v === undefined ? '—' : `${v.toLocaleString()}${suffix}`);
  const net = m.net_change > 0 ? `+${m.net_change}` : String(m.net_change);
  const tiles = [
    ['Opened', n(m.opened_in_window), '', null],
    ['Closed', n(m.closed_in_window), '', null],
    ['Net backlog change', net, m.net_change > 0 ? 'is-notice' : '', null],
    ['Mean days to close', n(m.mttr_days), '', null],
    ['Closed within SLA', n(m.closed_within_sla_pct, '%'), m.closed_within_sla_pct !== null && m.closed_within_sla_pct < 80 ? 'is-notice' : '', null],
    ['Reopened', n(m.reopened_in_window), m.reopened_in_window ? 'is-seal' : '', null],
    ['Awaiting verification', n(m.awaiting_verification), '', 'fixed,stale'],
    ['Tickets out of step', n(m.tickets.resolved_but_findings_open + m.tickets.open_but_findings_closed), '', null],
  ];
  const sevRows = SEV_ORDER.filter((s) => m.by_severity[s]).map((s) => {
    const b = m.by_severity[s];
    return `<tr><td>${gauge(s)} ${esc(s)}</td><td>${b.closed}</td><td>${b.mttr_days}</td>
      <td>${b.median_days}</td><td>${b.closed_within_sla_pct === null ? '—' : b.closed_within_sla_pct + '%'}</td></tr>`;
  }).join('');
  const drift = m.tickets;
  const driftList = (rows, label) => rows.length ? `<div class="hint" style="margin:0 18px 6px">${label}:
    ${rows.map((t) => `<span class="mono">${esc(t.external_id)}</span>`).join(', ')}</div>` : '';
  el.innerHTML = `
    <div class="lc-grid">${tiles.map(([label, val, cls, status]) =>
      `<div class="stat ${cls} ${status ? 'is-clickable' : ''}" ${status ? `data-status="${status}"` : ''}><b>${val}</b><span>${label}</span></div>`).join('')}</div>
    ${sevRows ? `<table class="lc-table"><thead><tr><th>Severity</th><th>Closed</th><th>Mean days</th><th>Median days</th><th>Within SLA</th></tr></thead><tbody>${sevRows}</tbody></table>`
      : '<div class="hint" style="margin:0 18px 18px">Nothing closed in this window yet.</div>'}
    ${driftList(drift.resolved_but_findings_open_sample, 'Tickets resolved while the scanner still reports the finding')}
    ${driftList(drift.open_but_findings_closed_sample, 'Tickets still open although every linked finding is closed')}`;
  el.onclick = (e) => {
    const s = e.target.closest('[data-status]');
    if (!s) return;
    state.filter.status = s.dataset.status.split(',');
    state.page = 1;
    switchView('findings');
    loadFindings();
  };
}

// ---------------------------------------------------------------- trend chart

async function loadTrendChart() {
  const el = $('trendChart');
  el.innerHTML = '<div class="spin">Loading…</div>';
  let data;
  try {
    data = await api(`/api/lifecycle/trends?days=${$('trendWindow').value}&granularity=${$('trendGranularity').value}`);
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  el.innerHTML = renderTrendChart(data);
}

function renderTrendChart(data) {
  const series = data.series || [];
  if (!series.length) return '<div class="hint">No history in this window.</div>';
  const W = 1120, H = 300, P_L = 44, P_R = 28, P_T = 20, P_B = 54;
  const inner_w = W - P_L - P_R, inner_h = H - P_T - P_B;
  const maxFlow = Math.max(1, ...series.map((s) => Math.max(s.opened, s.closed)));
  const maxBacklog = Math.max(1, ...series.map((s) => s.backlog_end));
  const n = series.length;
  const bar_w = Math.max(2, (inner_w / n) * 0.42);
  const slot = inner_w / n;

  const bars = series.map((s, i) => {
    const x = P_L + i * slot + slot / 2;
    const openedH = (s.opened / maxFlow) * inner_h;
    const closedH = (s.closed / maxFlow) * inner_h;
    return `
      <rect x="${x - bar_w - 1}" y="${P_T + inner_h - openedH}" width="${bar_w}" height="${openedH}" fill="var(--seal)" opacity="0.85">
        <title>${s.bucket_start.slice(0, 10)}: ${s.opened} opened</title></rect>
      <rect x="${x + 1}" y="${P_T + inner_h - closedH}" width="${bar_w}" height="${closedH}" fill="var(--ink)" opacity="0.75">
        <title>${s.bucket_start.slice(0, 10)}: ${s.closed} closed</title></rect>`;
  }).join('');

  const path = series.map((s, i) => {
    const x = P_L + i * slot + slot / 2;
    const y = P_T + inner_h - (s.backlog_end / maxBacklog) * inner_h;
    return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const y = P_T + inner_h - f * inner_h;
    const label = Math.round(f * maxFlow);
    return `<line x1="${P_L}" x2="${W - P_R}" y1="${y}" y2="${y}" stroke="var(--rule-soft)"/>
            <text x="${P_L - 6}" y="${y + 4}" text-anchor="end" font-size="10" fill="var(--slate)">${label}</text>`;
  }).join('');

  const yTicksR = [0, 0.5, 1].map((f) => {
    const y = P_T + inner_h - f * inner_h;
    const label = Math.round(f * maxBacklog);
    return `<text x="${W - P_R + 6}" y="${y + 4}" font-size="10" fill="var(--slate)">${label}</text>`;
  }).join('');

  const everyNth = Math.max(1, Math.ceil(n / 10));
  const xLabels = series.map((s, i) => {
    if (i % everyNth !== 0 && i !== n - 1) return '';
    const x = P_L + i * slot + slot / 2;
    return `<text x="${x}" y="${H - 28}" text-anchor="middle" font-size="10" fill="var(--slate)">${s.bucket_start.slice(0, 10)}</text>`;
  }).join('');

  const legend = `
    <g font-size="11" fill="var(--ink)">
      <rect x="${P_L}" y="${H - 14}" width="10" height="10" fill="var(--seal)" opacity="0.85"/>
      <text x="${P_L + 15}" y="${H - 5}">Opened</text>
      <rect x="${P_L + 80}" y="${H - 14}" width="10" height="10" fill="var(--ink)" opacity="0.75"/>
      <text x="${P_L + 95}" y="${H - 5}">Closed</text>
      <line x1="${P_L + 160}" y1="${H - 9}" x2="${P_L + 180}" y2="${H - 9}" stroke="var(--notice)" stroke-width="2"/>
      <text x="${P_L + 185}" y="${H - 5}">Open backlog (right axis)</text>
    </g>`;

  const summary = `<div style="margin-bottom:8px;font-size:12.5px;color:var(--slate)">
    <strong>${data.totals.opened.toLocaleString()}</strong> opened,
    <strong>${data.totals.closed.toLocaleString()}</strong> closed since ${data.start.slice(0, 10)}.
    Backlog at window start: <strong>${data.baseline_open_at_start.toLocaleString()}</strong>,
    now: <strong>${(series[series.length - 1]?.backlog_end || 0).toLocaleString()}</strong>.</div>`;

  return summary + `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;max-height:360px" xmlns="http://www.w3.org/2000/svg">
    <text x="${P_L}" y="12" font-size="10" fill="var(--slate)">Findings per ${data.granularity}</text>
    <text x="${W - P_R}" y="12" text-anchor="end" font-size="10" fill="var(--slate)">Open backlog</text>
    ${yTicks}
    ${yTicksR}
    ${bars}
    <path d="${path}" fill="none" stroke="var(--notice)" stroke-width="2"/>
    ${xLabels}
    ${legend}
  </svg>`;
}

// ---------------------------------------------------------------- remediated

function remediatedUrl(base) {
  const p = new URLSearchParams();
  if ($('remStart').value) p.set('start', $('remStart').value);
  if ($('remEnd').value) p.set('end', $('remEnd').value);
  if ($('remSeverity').value) p.append('severity', $('remSeverity').value);
  if ($('remSource').value) p.append('source', $('remSource').value);
  return `${base}?${p}`;
}

async function loadRemediated() {
  const el = $('remediatedList');
  el.innerHTML = '<div class="spin" style="padding:18px">Loading…</div>';
  let data;
  try { data = await api(remediatedUrl('/api/findings/remediated') + '&page_size=100'); }
  catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  if (data.total === 0) {
    el.innerHTML = '<div class="hint" style="padding:18px">No remediated findings in this window.</div>';
    return;
  }
  const s = data.summary;
  const sevChips = Object.entries(s.by_severity).sort((a, b) => SEV_ORDER.indexOf(a[0]) - SEV_ORDER.indexOf(b[0]))
    .map(([k, v]) => `<span class="tag">${esc(k)}: ${v}</span>`).join(' ');
  const srcChips = Object.entries(s.by_source).map(([k, v]) =>
    `<span class="tag">${esc({wiz: 'Wiz', falcon: 'Falcon', github: 'GitHub'}[k] || k)}: ${v}</span>`).join(' ');
  const monthChips = Object.entries(s.by_month).map(([k, v]) =>
    `<span class="tag">${esc(k)}: ${v}</span>`).join(' ');

  const header = `<div style="padding:0 18px 12px">
    <div style="font-size:13px;margin-bottom:8px">
      <strong>${data.total.toLocaleString()}</strong> remediated findings
      · mean time to close <strong>${s.mean_time_to_close_days ?? '—'}d</strong>
      · median <strong>${s.median_time_to_close_days ?? '—'}d</strong>
      · closed within SLA <strong>${s.closed_within_sla_pct ?? '—'}%</strong>
      (${s.closed_within_sla}/${s.measurable_against_sla})
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">${sevChips}</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">${srcChips}</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">${monthChips}</div>
  </div>`;

  const rows = data.findings.map((r) => {
    const sev = r.effective_severity;
    const slaClass = r.closed_within_sla ? '' : 'style="color:var(--notice)"';
    return `<div class="row" style="cursor:pointer" onclick="openDetail(${r.finding_id})">
      <div class="edge sev-${sev}"></div>
      <div class="row-check"></div>
      <div class="row-main">
        <div class="row-id">${esc(r.canonical_id || '')}</div>
        <div class="row-title">${esc(r.title || '')}</div>
        <div class="row-meta">
          <span>${gauge(sev)} <em>${sev}</em></span>
          <span>${esc(r.source)}</span>
          ${r.component ? `<span>${esc(r.component)}</span>` : ''}
          <span ${slaClass}>closed in ${r.time_to_close_days}d${r.closed_within_sla ? ', within SLA' : ', past SLA'}</span>
          ${r.reopened_count ? `<span class="tag tag-reopened">reopened ${r.reopened_count}×</span>` : ''}
        </div>
      </div>
      <div class="row-asset">${esc(r.asset || '')}<small>${esc(r.asset_type || '')}</small></div>
      <div class="row-risk"><div class="score">${fmtDate(r.closed_at)}</div></div>
      <div class="row-state"><span class="tag tag-closed">${esc(STATUS_SHORT[r.status] || r.status)}</span></div>
    </div>`;
  }).join('');

  el.innerHTML = header + `<div class="rows">${rows}</div>` +
    (data.pages > 1 ? `<div class="hint" style="padding:12px 18px">Showing page 1 of ${data.pages}. Use the Export CSV button to pull everything.</div>` : '');
}

// ---------------------------------------------------------------- sources

const SOURCE_INFO = {
  wiz: ['Wiz', 'Cloud workloads, misconfigurations, exposed secrets, and cloud asset discovery.'],
  falcon: ['CrowdStrike Falcon', 'Endpoint and server vulnerabilities from Spotlight.'],
  github: ['GitHub Advanced Security', 'Dependabot, code scanning, and secret scanning alerts.'],
};

async function loadSources() {
  const meta = await api('/api/meta');
  state.meta = meta;
  const runs = await api('/api/sync/runs?limit=40');
  // Most recent run per source, for the "last sync" line on each card.
  const latest = {};
  for (const r of runs) {
    if (!latest[r.source]) latest[r.source] = r;
  }

  $('sourceCards').innerHTML = Object.entries(SOURCE_INFO).map(([key, [name, blurb]]) => {
    const on = meta.connectors[key];
    const last = latest[key];
    return `<div class="source-card" data-source="${key}">
      <h4><span class="dot ${on ? 'on' : ''}"></span>${esc(name)}</h4>
      <div class="hint" style="margin:0 0 8px">${esc(blurb)}</div>
      <div class="status" id="status-${key}">${on
        ? 'Credentials are configured. Test the connection before the first sync.'
        : 'Not configured. Add its credentials to .env, or load demo data to try the interface.'}</div>
      <div class="sync-progress" id="progress-${key}"><div class="sync-progress-bar"></div></div>
      <div class="last-sync ${last && last.status !== 'ok' ? 'is-bad' : ''}" id="last-${key}">
        ${lastSyncLabel(last)}
      </div>
      <div class="actions">
        <button class="btn-ghost" onclick="testSource('${key}')">Test connection</button>
        <button class="btn-ghost" onclick="syncSource('${key}', false)"${on ? '' : ' disabled'}>Sync now</button>
        <button class="btn-ghost" onclick="syncSource('${key}', true)">Load demo data</button>
      </div>
    </div>`;
  }).join('');

  $('syncList').innerHTML = runs.length ? runs.map((r) => `
    <div class="row" style="grid-template-columns:30px 1fr 220px 150px 120px;cursor:default">
      <div class="edge ${r.status === 'ok' ? 'sev-low' : 'sev-critical'}"></div>
      <div class="row-main">
        <div class="row-id" style="font-size:13px">${esc(r.source)}</div>
        <div class="row-meta"><span>${esc(r.status)}</span>${r.error ? `<span style="color:var(--seal)">${esc(r.error.slice(0, 140))}</span>` : ''}</div>
      </div>
      <div class="row-asset">${r.findings.toLocaleString()} findings
        <small>${r.new} new \u00b7 ${r.closed} closed \u00b7 ${r.assets} assets</small></div>
      <div class="row-asset">${esc(r.triggered_by || '')}</div>
      <div class="row-asset">${new Date(r.started_at).toLocaleString()}</div>
    </div>`).join('') : '<div class="empty"><b>No syncs yet.</b></div>';
}

async function testSource(key) {
  const el = $(`status-${key}`);
  el.textContent = 'Testing\u2026';
  try {
    const r = await api(`/api/sync/check/${key}`);
    el.textContent = r.message;
    el.style.color = r.ok ? 'var(--slate)' : 'var(--seal)';
  } catch (e) {
    el.textContent = e.message;
    el.style.color = 'var(--seal)';
  }
}

function lastSyncLabel(r) {
  if (!r) return 'Last sync: never';
  const ts = new Date(r.started_at);
  const abs = ts.toLocaleString();
  const rel = relativeTime(ts);
  const status = r.status === 'ok' ? 'ok' : r.status;
  const bits = [`${r.findings.toLocaleString()} findings`];
  if (r.new) bits.push(`${r.new} new`);
  if (r.closed) bits.push(`${r.closed} closed`);
  return `Last sync: ${rel} (${abs}) \u00b7 ${status} \u00b7 ${bits.join(' / ')}`;
}

function relativeTime(date) {
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

async function syncSource(key, demo) {
  const el = $(`status-${key}`);
  const bar = $(`progress-${key}`);
  const last = $(`last-${key}`);
  el.textContent = demo ? 'Generating demo data\u2026' : 'Syncing\u2026 this can take a few minutes on the first run.';
  if (bar) bar.classList.add('on');
  // Kick the background watcher immediately so the Sources-tab "running" dot
  // and the Findings-tab "new" badge reflect this sync as soon as the request
  // starts, not at the next 5-second tick.
  if (typeof pollSyncRuns === 'function') setTimeout(pollSyncRuns, 50);

  // Stream progress via SSE while the POST runs in parallel. Close the
  // stream on completion or on sync failure.
  let evt = null;
  try {
    evt = new EventSource(`/api/sync/progress/${key}`);
    evt.addEventListener('progress', (e) => {
      try {
        const d = JSON.parse(e.data);
        el.textContent = `Syncing\u2026 ${d.findings.toLocaleString()} findings (${d.new} new) across ${d.assets} assets so far.`;
      } catch (_) {}
    });
    evt.addEventListener('complete', () => { if (evt) { evt.close(); evt = null; } });
  } catch (_) { /* SSE unsupported; ignore */ }

  try {
    const r = await api(`/api/sync/${key}?demo=${demo}`, { method: 'POST' });
    if (r.status === 'ok') {
      el.textContent = `${r.findings.toLocaleString()} findings (${r.new} new, ${r.closed} closed) across ${r.assets} assets.`;
      el.style.color = 'var(--slate)';
      toast(`${key} sync finished`);
    } else {
      el.textContent = r.error;
      el.style.color = 'var(--seal)';
    }
  } catch (e) {
    el.textContent = e.message;
    el.style.color = 'var(--seal)';
  } finally {
    if (bar) bar.classList.remove('on');
    if (evt) evt.close();
    // Refresh the last-sync line and schedule card.
    try {
      const runs = await api('/api/sync/runs?limit=5');
      const r = runs.find((x) => x.source === key);
      if (last) {
        last.textContent = lastSyncLabel(r);
        last.classList.toggle('is-bad', r && r.status !== 'ok');
      }
    } catch (_) {}
    loadSources();
    // One more poll so the global watcher's running-dot clears and the
    // findings-tab badge appears without waiting another 5 seconds.
    if (typeof pollSyncRuns === 'function') setTimeout(pollSyncRuns, 50);
  }
}

// ---------------------------------------------------------------- schedules (in sources tab)

async function loadSchedules() {
  const scheds = await api('/api/schedules');
  const el = $('scheduleCards');
  if (!scheds.length) {
    el.innerHTML = ['wiz', 'falcon', 'github'].map((s) => scheduleCard(s, null)).join('');
  } else {
    const bySource = {};
    scheds.forEach((s) => { bySource[s.source] = s; });
    el.innerHTML = ['wiz', 'falcon', 'github'].map((s) => scheduleCard(s, bySource[s] || null)).join('');
  }
}

function scheduleCard(source, sched) {
  const name = { wiz: 'Wiz', falcon: 'CrowdStrike Falcon', github: 'GitHub' }[source] || source;
  const enabled = sched ? sched.enabled : false;
  const interval = sched ? sched.interval_hours : 24;
  const hour = sched && sched.preferred_hour_utc !== null ? sched.preferred_hour_utc : '';
  const next = sched && sched.next_run_at ? new Date(sched.next_run_at).toLocaleString() : 'not scheduled';
  const last = sched && sched.last_run_at ? new Date(sched.last_run_at).toLocaleString() : 'never';
  const status = sched && sched.last_status ? sched.last_status : '';
  return `<div class="source-card">
    <h4>${esc(name)} import schedule</h4>
    <div class="kv" style="margin:10px 0;font-size:12px">
      <dt>Last run</dt><dd>${esc(last)}${status ? ' \u00b7 ' + esc(status) : ''}</dd>
      <dt>Next run</dt><dd>${esc(next)}</dd>
    </div>
    ${sched && sched.last_error ? `<div class="hint is-warn" style="margin-bottom:8px">${esc(sched.last_error)}</div>` : ''}
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <label class="checkbox" title="Enable schedule">
        <input type="checkbox" ${enabled ? 'checked' : ''} onchange="toggleSchedule('${source}', this.checked)"><span></span>
      </label>
      <span style="font-size:12px">Every</span>
      <select class="field-sm" id="schedInterval-${source}" style="width:80px" onchange="updateSchedule('${source}')">
        ${[1,2,4,6,8,12,24,48,72,168].map((h) =>
          `<option value="${h}"${interval === h ? ' selected' : ''}>${h < 24 ? h + 'h' : (h / 24) + 'd'}</option>`
        ).join('')}
      </select>
      <span style="font-size:12px">at</span>
      <select class="field-sm" id="schedHour-${source}" style="width:90px" onchange="updateSchedule('${source}')">
        <option value=""${hour === '' ? ' selected' : ''}>any time</option>
        ${Array.from({length:24},(_, i)=> i).map((h) =>
          `<option value="${h}"${hour === h ? ' selected' : ''}>${String(h).padStart(2,'0')}:00 UTC</option>`
        ).join('')}
      </select>
    </div>
  </div>`;
}

async function toggleSchedule(source, enabled) {
  try {
    await api('/api/schedules', {
      method: 'POST',
      body: JSON.stringify({ source, enabled, interval_hours: parseInt($(`schedInterval-${source}`).value) }),
    });
    toast(enabled ? `${source} schedule enabled` : `${source} schedule disabled`);
    loadSchedules();
  } catch (e) { toast(e.message, true); }
}

async function updateSchedule(source) {
  const hour = $(`schedHour-${source}`).value;
  try {
    await api('/api/schedules', {
      method: 'POST',
      body: JSON.stringify({
        source,
        enabled: true,
        interval_hours: parseInt($(`schedInterval-${source}`).value),
        preferred_hour_utc: hour === '' ? null : parseInt(hour),
      }),
    });
    toast(`${source} schedule updated`);
    loadSchedules();
  } catch (e) { toast(e.message, true); }
}

// patch loadSources to also load schedules
const _origLoadSources = loadSources;
loadSources = async function() {
  await _origLoadSources();
  await loadSchedules();
};

// ---------------------------------------------------------------- assignment rules

async function loadRules() {
  const rules = await api('/api/rules');
  const el = $('rulesList');
  $('rulePreview').innerHTML = '';

  if (!rules.length) {
    el.innerHTML = `<div class="empty"><b>No assignment rules yet.</b>
      Create a rule to automatically route findings to team members based on
      source, severity, asset, or component.</div>`;
  } else {
    el.innerHTML = rules.map(ruleRow).join('');
    el.onclick = (e) => {
      const del = e.target.closest('[data-delete]');
      if (del) { deleteRule(Number(del.dataset.delete)); return; }
      const tog = e.target.closest('[data-toggle]');
      if (tog) { toggleRule(Number(tog.dataset.toggle)); return; }
      const row = e.target.closest('.row[data-rule]');
      if (row) editRule(Number(row.dataset.rule));
    };
  }

  $('newRule').onclick = () => openRuleForm();
  $('previewRules').onclick = previewAllRules;
  $('runRules').onclick = runRulesNow;
}

function ruleRow(r) {
  const criteria = [];
  if (r.source) criteria.push(r.source);
  if (r.severity) criteria.push(r.severity);
  if (r.category) criteria.push(r.category);
  if (r.asset_pattern) criteria.push(`asset: ${r.asset_pattern}`);
  if (r.component_pattern) criteria.push(`component: ${r.component_pattern}`);
  if (r.environment) criteria.push(r.environment);
  if (r.kev_only) criteria.push('KEV only');
  if (r.fix_available_only) criteria.push('fix available');

  return `<div class="row" data-rule="${r.id}" style="grid-template-columns:30px 50px 1fr 180px 150px 100px">
    <div class="edge ${r.enabled ? 'sev-high' : 'sev-low'}"></div>
    <div class="mono" style="font-size:12px;color:var(--slate-soft)">#${r.priority}</div>
    <div class="row-main">
      <div class="row-id">${esc(r.name)}</div>
      <div class="row-title">${esc(r.description || '')}</div>
      <div class="row-meta">
        ${criteria.map((c) => `<span>${esc(c)}</span>`).join('')}
        ${!criteria.length ? '<span>all findings</span>' : ''}
      </div>
    </div>
    <div class="row-asset">→ ${esc(r.assign_to)}
      <small>${esc(DISP_SHORT[r.disposition] || r.disposition)}${r.remediation_days ? ' \u00b7 ' + r.remediation_days + 'd SLA' : ''}</small>
    </div>
    <div class="row-state">
      <span class="tag ${r.enabled ? 'tag-decided' : 'tag-muted'}">${r.enabled ? 'active' : 'disabled'}</span>
    </div>
    <div style="display:flex;gap:6px;align-items:start">
      <button class="btn-ghost" data-toggle="${r.id}" style="font-size:11px">${r.enabled ? 'Disable' : 'Enable'}</button>
      <button class="btn-ghost" data-delete="${r.id}" style="font-size:11px;color:var(--seal)">Delete</button>
    </div>
  </div>`;
}

async function toggleRule(id) {
  const rules = await api('/api/rules');
  const rule = rules.find((r) => r.id === id);
  if (!rule) return;
  await api(`/api/rules/${id}`, {
    method: 'PUT', body: JSON.stringify({ enabled: !rule.enabled }),
  });
  toast(rule.enabled ? 'Rule disabled' : 'Rule enabled');
  loadRules();
}

async function deleteRule(id) {
  if (!confirm('Delete this assignment rule?')) return;
  await api(`/api/rules/${id}`, { method: 'DELETE' });
  toast('Rule deleted');
  loadRules();
}

async function editRule(id) {
  const rules = await api('/api/rules');
  const rule = rules.find((r) => r.id === id);
  if (rule) openRuleForm(rule);
}

function openRuleForm(existing) {
  const el = $('decide');
  $('detail').hidden = true;
  $('scrim').hidden = false;
  el.hidden = false;
  el.scrollTop = 0;

  const r = existing || {};
  const isNew = !r.id;
  const meta = state.meta;

  el.innerHTML = `
    <div class="drawer-head">
      <div><h2>${isNew ? 'New assignment rule' : 'Edit rule'}</h2>
        <p>Criteria use AND logic — every non-empty field must match.</p></div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      <div class="sec">
        <h3>Rule identity</h3>
        <div class="field-group">
          <label>Name</label>
          <input id="ruleName" class="field" placeholder="e.g. Critical KEV to security1" value="${esc(r.name || '')}">
        </div>
        <div class="field-group">
          <label>Description</label>
          <input id="ruleDesc" class="field" placeholder="What this rule does" value="${esc(r.description || '')}">
        </div>
        <div class="field-row">
          <div class="field-group">
            <label>Priority (lower = evaluated first)</label>
            <input id="rulePri" type="number" class="field" min="1" max="9999" value="${r.priority || 100}">
          </div>
          <div class="field-group">
            <label>Status</label>
            <select id="ruleEnabled" class="field">
              <option value="true"${r.enabled !== false ? ' selected' : ''}>Active</option>
              <option value="false"${r.enabled === false ? ' selected' : ''}>Disabled</option>
            </select>
          </div>
        </div>
      </div>

      <div class="sec">
        <h3>Match criteria</h3>
        <div class="hint" style="margin-bottom:12px">Leave a field empty to match all values for that dimension.</div>
        <div class="field-row">
          <div class="field-group">
            <label>Source</label>
            <select id="ruleSource" class="field">
              <option value="">Any source</option>
              <option value="wiz"${r.source === 'wiz' ? ' selected' : ''}>Wiz</option>
              <option value="falcon"${r.source === 'falcon' ? ' selected' : ''}>CrowdStrike Falcon</option>
              <option value="github"${r.source === 'github' ? ' selected' : ''}>GitHub</option>
            </select>
          </div>
          <div class="field-group">
            <label>Severity (comma-separated)</label>
            <input id="ruleSev" class="field mono" placeholder="critical,high" value="${esc(r.severity || '')}">
          </div>
        </div>
        <div class="field-row">
          <div class="field-group">
            <label>Category (comma-separated)</label>
            <input id="ruleCat" class="field mono" placeholder="os_vuln,cloud_vuln" value="${esc(r.category || '')}">
          </div>
          <div class="field-group">
            <label>Environment</label>
            <select id="ruleEnv" class="field">
              <option value="">Any environment</option>
              <option value="production"${r.environment === 'production' ? ' selected' : ''}>Production</option>
              <option value="non_production"${r.environment === 'non_production' ? ' selected' : ''}>Non-production</option>
            </select>
          </div>
        </div>
        <div class="field-row">
          <div class="field-group">
            <label>Asset name pattern</label>
            <input id="ruleAsset" class="field mono" placeholder="pli-prod-%" value="${esc(r.asset_pattern || '')}">
            <div class="hint">Use % as wildcard. E.g. <code>pli-prod-%</code> matches all production-prefixed assets.</div>
          </div>
          <div class="field-group">
            <label>Component pattern</label>
            <input id="ruleComp" class="field mono" placeholder="%" value="${esc(r.component_pattern || '')}">
          </div>
        </div>
        <div class="field-row">
          <div class="field-group">
            <label class="checkbox" style="gap:8px;font-size:13px">
              <input type="checkbox" id="ruleKev" ${r.kev_only ? 'checked' : ''}><span></span>
              Only KEV-listed vulnerabilities
            </label>
          </div>
          <div class="field-group">
            <label class="checkbox" style="gap:8px;font-size:13px">
              <input type="checkbox" id="ruleFix" ${r.fix_available_only ? 'checked' : ''}><span></span>
              Only findings with a published fix
            </label>
          </div>
        </div>
      </div>

      <div class="sec">
        <h3>Assignment action</h3>
        <div class="field-row">
          <div class="field-group">
            <label>Assign to</label>
            <select id="ruleAssign" class="field">
              ${meta.users.map((u) =>
                `<option value="${esc(u)}"${r.assign_to === u ? ' selected' : ''}>${esc(u)}</option>`
              ).join('')}
            </select>
          </div>
          <div class="field-group">
            <label>Routing disposition</label>
            <select id="ruleDisp" class="field">
              <option value="fix_immediately"${r.disposition === 'fix_immediately' ? ' selected' : ''}>Fix immediately</option>
              <option value="complex_resolution"${r.disposition === 'complex_resolution' ? ' selected' : ''}>Complex resolution</option>
              <option value="developer_review"${r.disposition === 'developer_review' ? ' selected' : ''}>Developer review</option>
            </select>
          </div>
        </div>
        <div class="field-row">
          <div class="field-group">
            <label>Remediation SLA (days from detection)</label>
            <input id="ruleRemDays" type="number" class="field" placeholder="Leave blank for policy default" value="${r.remediation_days || ''}">
          </div>
        </div>
        <div class="field-group">
          <label>Justification template</label>
          <textarea id="ruleJust" class="field" style="min-height:60px" placeholder="Pre-filled text for the routing decision">${esc(r.justification_template || '')}</textarea>
        </div>
      </div>
    </div>
    <div class="drawer-foot">
      <button class="btn-ghost" onclick="closeDrawers()">Cancel</button>
      <button class="btn btn-seal" id="saveRule">${isNew ? 'Create rule' : 'Save changes'}</button>
    </div>`;

  $('saveRule').onclick = () => saveRule(r.id);
}

async function saveRule(existingId) {
  const body = {
    name: $('ruleName').value.trim(),
    description: $('ruleDesc').value.trim() || null,
    enabled: $('ruleEnabled').value === 'true',
    priority: parseInt($('rulePri').value) || 100,
    source: $('ruleSource').value || null,
    severity: $('ruleSev').value.trim() || null,
    category: $('ruleCat').value.trim() || null,
    asset_pattern: $('ruleAsset').value.trim() || null,
    component_pattern: $('ruleComp').value.trim() || null,
    environment: $('ruleEnv').value || null,
    kev_only: $('ruleKev').checked,
    fix_available_only: $('ruleFix').checked,
    assign_to: $('ruleAssign').value,
    disposition: $('ruleDisp').value,
    remediation_days: parseInt($('ruleRemDays').value) || null,
    justification_template: $('ruleJust').value.trim() || null,
  };
  if (!body.name) { toast('Name is required', true); return; }

  try {
    if (existingId) {
      await api(`/api/rules/${existingId}`, { method: 'PUT', body: JSON.stringify(body) });
      toast('Rule updated');
    } else {
      await api('/api/rules', { method: 'POST', body: JSON.stringify(body) });
      toast('Rule created');
    }
    closeDrawers();
    loadRules();
  } catch (e) { showProblems(e); }
}

async function previewAllRules() {
  $('rulePreview').innerHTML = '<div class="spin">Evaluating rules against all open findings\u2026</div>';
  try {
    const p = await api('/api/rules/preview', { method: 'POST' });
    let html = `<div class="coverage" style="margin-top:14px">
      <b>${p.total_matched.toLocaleString()}</b> of <b>${p.total_open.toLocaleString()}</b> open findings
      would be assigned. <b>${p.unmatched.toLocaleString()}</b> unmatched.</div>`;
    html += p.rules.map((r) => `
      <div style="margin-top:14px;border:1px solid var(--rule);padding:12px;background:var(--panel)">
        <div style="display:flex;justify-content:space-between">
          <strong>${esc(r.rule_name)}</strong>
          <span class="mono" style="font-size:12px">${r.match_count.toLocaleString()} findings \u2192 ${esc(r.assign_to)}</span>
        </div>
        ${r.sample.length ? `<div class="row-meta" style="margin-top:6px;flex-wrap:wrap">
          ${r.sample.slice(0, 12).map((s) =>
            `<span>${esc(s.vuln)} on ${esc(s.asset)} (${esc(s.severity)})</span>`
          ).join('')}
          ${r.match_count > 12 ? `<span>\u2026 and ${(r.match_count - 12).toLocaleString()} more</span>` : ''}
        </div>` : '<div class="hint">No matches right now.</div>'}
      </div>`).join('');
    $('rulePreview').innerHTML = html;
  } catch (e) {
    $('rulePreview').innerHTML = `<div class="hint is-warn">${esc(e.message)}</div>`;
  }
}

async function runRulesNow() {
  if (!confirm('Run all assignment rules against open findings now? This will create routing decisions for every match.')) return;
  try {
    const r = await api('/api/rules/run', { method: 'POST', body: JSON.stringify({}) });
    toast(`${r.assigned} findings assigned across ${Object.keys(r.rules_fired).length} rules`);
    loadRules();
  } catch (e) { toast(e.message, true); }
}

// ---------------------------------------------------------------- compliance

async function loadCompliance() {
  const data = await api('/api/compliance');
  const el = $('complianceSummary');
  const det = $('complianceDetail');
  det.innerHTML = '';

  // Wire upload
  $('complianceFile').onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    try {
      const r = await fetch('/api/compliance/import', {
        method: 'POST', body: form,
        headers: { 'X-RiskDesk-User': currentUser() },
      });
      if (!r.ok) { const b = await r.json(); throw new Error(b.detail || r.statusText); }
      const result = await r.json();
      const scans = result.scans || [];
      toast(`Imported ${scans.length} scan(s): ${scans.map((s) => s.score_percent + '%').join(', ')}`);
      loadCompliance();
    } catch (err) {
      toast(err.message, true);
    }
    e.target.value = '';
  };

  if (!data.benchmarks || !data.benchmarks.length) {
    el.innerHTML = `<div class="empty"><b>No compliance scans imported yet.</b>
      Import a CIS-CAT or STIG Viewer CSV using the button above.
      Supports CIS-CAT Pro Assessor exports and STIG Viewer / Evaluate-STIG CSVs.</div>`;
    return;
  }

  el.innerHTML = data.benchmarks.map((bm) => {
    const score = bm.latest_score;
    const scoreCls = score >= 90 ? '' : score >= 70 ? 'is-notice' : 'is-seal';
    const trend = bm.trend || [];
    const trendHtml = trend.length > 1
      ? `<div class="row-meta" style="margin-top:8px">
          ${trend.map((t) => `<span>${fmtDate(t.date)}: ${t.score !== null ? t.score + '%' : '?'}</span>`).join('')}
        </div>`
      : '';

    return `<div class="source-card" style="margin-bottom:14px;cursor:pointer" data-bm-scan="${bm.trend[bm.trend.length - 1]?.scan_id || ''}">
      <div style="display:flex;justify-content:space-between;align-items:start">
        <div>
          <h4>${esc(bm.name)}</h4>
          <div class="hint" style="margin:0">${esc(bm.framework.toUpperCase())}${bm.version ? ' v' + esc(bm.version) : ''}${bm.profile ? ' \u00b7 ' + esc(bm.profile) : ''}</div>
        </div>
        <div style="text-align:right">
          <div class="stat ${scoreCls}" style="padding:6px 10px;border:1px solid var(--rule)">
            <b>${score !== null ? score + '%' : '?'}</b>
            <span>COMPLIANCE</span>
          </div>
        </div>
      </div>
      <div class="kv" style="margin-top:12px;font-size:12px">
        <dt>Last scan</dt><dd>${fmtDate(bm.latest_date) || 'unknown'}</dd>
        <dt>Pass / Fail / Manual</dt><dd>${bm.latest_pass} / ${bm.latest_fail} / ${bm.latest_manual}</dd>
        <dt>Hosts scanned</dt><dd>${bm.latest_hosts}</dd>
        <dt>Total scans</dt><dd>${bm.scan_count}</dd>
      </div>
      ${trendHtml}
    </div>`;
  }).join('');

  el.onclick = (e) => {
    const card = e.target.closest('[data-bm-scan]');
    if (card && card.dataset.bmScan) openScanDetail(Number(card.dataset.bmScan));
  };
}

async function openScanDetail(scanId) {
  const el = $('detail');
  openDrawer(el);
  el.innerHTML = '<div class="spin">Loading scan detail\u2026</div>';
  const d = await api(`/api/compliance/scans/${scanId}`);

  const scoreCls = d.score_percent >= 90 ? '' : d.score_percent >= 70 ? 'is-notice' : 'is-seal';

  el.innerHTML = `
    <div class="drawer-head">
      <div>
        <h2>${esc(d.benchmark || 'Scan')}</h2>
        <p>${esc(d.framework?.toUpperCase() || '')}${d.version ? ' v' + esc(d.version) : ''}${d.profile ? ' \u00b7 ' + esc(d.profile) : ''}</p>
      </div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      <div class="stat ${scoreCls}" style="border:1px solid var(--rule);padding:14px;margin-bottom:20px;text-align:center">
        <b style="font-size:32px">${d.score_percent !== null ? d.score_percent + '%' : '?'}</b>
        <span>COMPLIANCE SCORE</span>
      </div>

      <div class="kv" style="margin-bottom:20px">
        <dt>Scan date</dt><dd>${fmtDate(d.scan_date) || 'unknown'}</dd>
        <dt>Source file</dt><dd>${esc(d.source_file || 'unknown')}</dd>
        <dt>Imported by</dt><dd>${esc(d.imported_by || '')}</dd>
        <dt>Pass / Fail / Manual</dt><dd>${d.total_pass} / ${d.total_fail} / ${d.total_manual}</dd>
        <dt>Hosts</dt><dd>${d.host_count}</dd>
      </div>

      ${Object.keys(d.hosts || {}).length ? `<div class="sec"><h3>Per-host scores</h3>
        ${Object.entries(d.hosts).map(([host, h]) =>
          `<div class="ledger-row">
            <div><strong class="mono">${esc(host)}</strong>
              <small>${h.pass} pass \u00b7 ${h.fail} fail \u00b7 ${h.manual} manual</small></div>
            <div class="ledger-pts ${h.score < 70 ? 'is-seal' : ''}" style="font-size:14px;font-weight:700">${h.score !== null ? h.score + '%' : '?'}</div>
          </div>`
        ).join('')}
      </div>` : ''}

      ${d.fail_details?.length ? `<div class="sec"><h3>Failed checks (${d.fail_details.length})</h3>
        ${d.fail_details.map((f) =>
          `<div class="ledger-row" style="grid-template-columns:1fr">
            <div><span class="tag tag-overdue">FAIL</span>
              <strong class="mono" style="margin-left:8px">${esc(f.rule_id)}</strong>
              ${esc(f.rule_title)}
              <small>${esc(f.hostname)}${f.references ? ' \u00b7 ' + esc(f.references.slice(0, 100)) : ''}</small></div>
          </div>`
        ).join('')}
      </div>` : '<div class="sec"><h3>Failed checks</h3><div class="hint">All checks passed.</div></div>'}

      ${d.manual_details?.length ? `<div class="sec"><h3>Manual checks (${d.manual_details.length})</h3>
        ${d.manual_details.slice(0, 30).map((m) =>
          `<div class="ledger-row" style="grid-template-columns:1fr">
            <div><span class="tag">MANUAL</span>
              <strong class="mono" style="margin-left:8px">${esc(m.rule_id)}</strong>
              ${esc(m.rule_title)}
              <small>${esc(m.hostname)}</small></div>
          </div>`
        ).join('')}
        ${d.manual_details.length > 30 ? `<div class="hint">\u2026 and ${d.manual_details.length - 30} more</div>` : ''}
      </div>` : ''}
    </div>`;
}

// ---------------------------------------------------------------- exceptions

state.exc = { state: '', mine: false, reviewing: false, q: '' };

async function loadExceptions() {
  const p = new URLSearchParams();
  if (state.exc.state) p.append('status', state.exc.state);
  if (state.exc.mine) p.set('submitted_by', currentUser());
  if (state.exc.reviewing) p.set('reviewer', currentUser());
  if (state.exc.q) p.set('q', state.exc.q);
  p.set('page_size', '200');
  const r = await api(`/api/exceptions?${p}`);
  const el = $('exceptionsList');

  $('excState').onclick = (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    state.exc.state = b.dataset.state;
    [...$('excState').children].forEach((c) => c.classList.toggle('is-active', c === b));
    loadExceptions();
  };
  $('myExceptions').onclick = () => { state.exc.mine = !state.exc.mine; state.exc.reviewing = false; $('myExceptions').classList.toggle('is-active'); $('myReviews').classList.remove('is-active'); loadExceptions(); };
  $('myReviews').onclick = () => { state.exc.reviewing = !state.exc.reviewing; state.exc.mine = false; $('myReviews').classList.toggle('is-active'); $('myExceptions').classList.remove('is-active'); loadExceptions(); };
  $('excSearch').oninput = debounce(() => { state.exc.q = $('excSearch').value.trim(); loadExceptions(); }, 300);

  if (!r.exceptions.length) {
    el.innerHTML = `<div class="empty"><b>No exception requests.</b>
      Team members can submit exceptions from the finding detail view.</div>`;
    return;
  }
  el.innerHTML = r.exceptions.map(excRow).join('');
  el.onclick = (e) => {
    const row = e.target.closest('[data-exc]');
    if (row) openExceptionDetail(Number(row.dataset.exc));
  };
}

const EXC_STATUS_TAG = {
  submitted: 'tag-pending', under_review: 'tag-pending', info_requested: 'tag-overdue',
  approved: 'tag-decided', rejected: 'tag-muted', withdrawn: 'tag-muted',
};

function excRow(e) {
  return `<div class="row" data-exc="${e.id}" style="grid-template-columns:30px 1fr 160px 150px 130px">
    <div class="edge ${e.status === 'approved' ? 'sev-high' : e.status === 'rejected' ? 'sev-low' : 'sev-medium'}"></div>
    <div class="row-main">
      <div class="row-id">${esc(e.title)}</div>
      <div class="row-title">${esc(e.scope_label || '')} \u00b7 ${esc(dispLabel(e.requested_disposition))}</div>
      <div class="row-meta">
        <span>#${e.id}</span>
        <span>${(e.finding_ids || []).length} findings</span>
        ${e.adjusted_severity ? `<span>\u2192 ${esc(e.adjusted_severity)}</span>` : ''}
        ${e.requested_duration_days ? `<span>${e.requested_duration_days}d requested</span>` : ''}
      </div>
    </div>
    <div class="row-asset">${esc(e.submitted_by)}
      <small>${e.submitter_team ? esc(e.submitter_team) : ''}</small>
    </div>
    <div class="row-asset">${e.assigned_reviewer ? esc(e.assigned_reviewer) : 'unassigned'}
      <small>${e.submitted_at ? fmtDate(e.submitted_at) : ''}</small>
    </div>
    <div class="row-state">
      <span class="tag ${EXC_STATUS_TAG[e.status] || ''}">${esc(e.status.replace('_', ' '))}</span>
    </div>
  </div>`;
}

async function openExceptionDetail(id) {
  const el = $('detail');
  openDrawer(el);
  el.innerHTML = '<div class="spin">Loading\u2026</div>';
  const e = await api(`/api/exceptions/${id}`);
  const me = currentUser();
  const isSecurity = (state.meta?.approvers || []).includes(me) || (state.meta?.role && ['admin', 'executive', 'security'].includes(state.meta.role));
  const isSubmitter = me === e.submitted_by;
  const canReview = isSecurity && e.status !== 'approved' && e.status !== 'rejected' && e.status !== 'withdrawn';

  el.innerHTML = `
    <div class="drawer-head">
      <div><h2>Exception #${e.id}</h2><p>${esc(e.title)}</p></div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      <div class="stamp ${e.status === 'approved' ? '' : e.status === 'rejected' ? 'is-lapsed' : 'is-pending'}">
        <div class="stamp-disp">${esc(e.status.replace('_', ' ').toUpperCase())}</div>
        <div class="stamp-meta">
          Requesting: ${esc(dispLabel(e.requested_disposition))} on ${esc(e.scope_label || '')}<br>
          Submitted by ${esc(e.submitted_by)}${e.submitter_team ? ' (' + esc(e.submitter_team) + ')' : ''} on ${fmtDate(e.submitted_at)}<br>
          ${e.assigned_reviewer ? 'Reviewer: ' + esc(e.assigned_reviewer) : 'No reviewer assigned'}<br>
          Duration requested: ${e.requested_duration_days || '?'} days
          ${e.adjusted_severity ? '<br>Adjusted severity: ' + esc(e.adjusted_severity) : ''}
          ${e.adjudication_id ? '<br>Created adjudication #' + e.adjudication_id : ''}
        </div>
        ${e.reviewed_by ? `<div class="stamp-meta" style="margin-top:8px;border-top:1px solid var(--rule);padding-top:8px">
          ${e.review_decision === 'approved' ? 'Approved' : 'Rejected'} by ${esc(e.reviewed_by)} on ${fmtDate(e.review_date)}
          ${e.review_note ? '<br>' + esc(e.review_note) : ''}
        </div>` : ''}
      </div>

      <div class="sec" style="margin-top:20px">
        <h3>Justification</h3>
        <div class="prose">${esc(e.justification)}</div>
      </div>
      ${e.business_impact ? `<div class="sec"><h3>Business impact</h3><div class="prose">${esc(e.business_impact)}</div></div>` : ''}
      ${e.compensating_controls ? `<div class="sec"><h3>Compensating controls</h3><div class="prose">${esc(e.compensating_controls)}</div></div>` : ''}

      ${(e.comments || []).length ? `<div class="sec"><h3>Discussion</h3>
        ${e.comments.map((c) => `<div style="margin-bottom:12px;padding:10px;background:${c.is_internal ? 'var(--notice-wash)' : 'var(--paper)'};border-left:3px solid ${c.is_internal ? 'var(--notice)' : 'var(--rule)'}">
          <div style="font-size:11px;color:var(--slate-soft)">${esc(c.author)} \u00b7 ${fmtDate(c.created_at)}${c.is_internal ? ' \u00b7 internal note' : ''}</div>
          <div class="prose" style="margin-top:4px">${esc(c.body)}</div>
        </div>`).join('')}
      </div>` : ''}

      ${canReview ? `<div class="sec"><h3>Review actions</h3>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-seal" onclick="reviewException(${e.id},'approved')">Approve</button>
          <button class="btn-ghost" onclick="reviewException(${e.id},'rejected')">Reject</button>
          <button class="btn-ghost" onclick="requestExcInfo(${e.id})">Request more info</button>
          <button class="btn-ghost" onclick="assignExcReviewer(${e.id})">Assign reviewer</button>
        </div>
        <div class="field-group" style="margin-top:12px">
          <label>Add a comment</label>
          <textarea id="excComment" class="field" style="min-height:60px" placeholder="Note for the submitter or an internal-only comment"></textarea>
          <div style="display:flex;gap:8px;margin-top:6px">
            <button class="btn-ghost" onclick="addExcComment(${e.id},false)">Post comment</button>
            <button class="btn-ghost" onclick="addExcComment(${e.id},true)">Post as internal note</button>
          </div>
        </div>
      </div>` : ''}

      ${isSubmitter && e.status === 'info_requested' ? `<div class="sec"><h3>Respond to information request</h3>
        <textarea id="excRespond" class="field" style="min-height:60px" placeholder="Provide the additional information requested"></textarea>
        <button class="btn btn-seal" style="margin-top:8px" onclick="respondExcInfo(${e.id})">Submit response</button>
      </div>` : ''}

      ${isSubmitter && !['approved','rejected','withdrawn'].includes(e.status) ? `
        <div class="sec"><button class="btn-ghost" onclick="withdrawExc(${e.id})">Withdraw this exception</button></div>
      ` : ''}
    </div>`;
}

async function reviewException(id, decision) {
  const note = prompt(decision === 'approved' ? 'Approval note (optional):' : 'Reason for rejecting:');
  if (decision === 'rejected' && !note) return;
  try {
    await api(`/api/exceptions/${id}/review`, {
      method: 'POST', body: JSON.stringify({ decision, note }),
    });
    toast(decision === 'approved' ? 'Exception approved. Adjudication created.' : 'Exception rejected.');
    closeDrawers();
    loadExceptions();
  } catch (e) { toast(e.message || e.detail, true); }
}

async function requestExcInfo(id) {
  const message = prompt('What information do you need from the submitter?');
  if (!message) return;
  try {
    await api(`/api/exceptions/${id}/request-info`, {
      method: 'POST', body: JSON.stringify({ message }),
    });
    toast('Information requested. The submitter will be notified.');
    closeDrawers();
    loadExceptions();
  } catch (e) { toast(e.message, true); }
}

async function respondExcInfo(id) {
  const message = $('excRespond')?.value?.trim();
  if (!message) { toast('Write a response first.', true); return; }
  try {
    await api(`/api/exceptions/${id}/respond`, {
      method: 'POST', body: JSON.stringify({ message }),
    });
    toast('Response submitted. The exception is back under review.');
    closeDrawers();
    loadExceptions();
  } catch (e) { toast(e.message, true); }
}

async function assignExcReviewer(id) {
  const reviewer = prompt(`Assign reviewer (${(state.meta?.users || []).join(', ')}):`);
  if (!reviewer) return;
  try {
    await api(`/api/exceptions/${id}/assign`, {
      method: 'POST', body: JSON.stringify({ reviewer }),
    });
    toast(`Assigned to ${reviewer}`);
    closeDrawers();
    loadExceptions();
  } catch (e) { toast(e.message, true); }
}

async function addExcComment(id, isInternal) {
  const body = $('excComment')?.value?.trim();
  if (!body) { toast('Write a comment first.', true); return; }
  try {
    await api(`/api/exceptions/${id}/comment`, {
      method: 'POST', body: JSON.stringify({ body, is_internal: isInternal }),
    });
    toast('Comment posted.');
    openExceptionDetail(id);
  } catch (e) { toast(e.message, true); }
}

async function withdrawExc(id) {
  if (!confirm('Withdraw this exception? The findings return to the backlog.')) return;
  try {
    await api(`/api/exceptions/${id}/withdraw`, { method: 'POST' });
    toast('Exception withdrawn.');
    closeDrawers();
    loadExceptions();
  } catch (e) { toast(e.message, true); }
}

// --- submit exception from finding detail ---

function submitExceptionButton(findingIds) {
  return `<button class="btn-ghost" onclick="openExceptionForm(${JSON.stringify(findingIds)})">Submit exception request</button>`;
}

async function openExceptionForm(findingIds) {
  const el = $('decide');
  $('detail').hidden = true;
  openDrawer(el);
  const meta = state.meta;
  const SEV = ['critical','high','medium','low','info'];

  el.innerHTML = `
    <div class="drawer-head">
      <div><h2>Submit an exception request</h2>
        <p>${findingIds.length} finding${findingIds.length === 1 ? '' : 's'} selected</p></div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">\u00d7</button>
    </div>
    <div class="drawer-body">
      <div class="hint" style="margin-bottom:16px">
        An exception request asks the security team to accept, adjust, or dismiss these findings.
        It will be reviewed before taking effect.
      </div>
      <div class="field-group">
        <label>Title</label>
        <input id="excTitle" class="field" placeholder="Short description, e.g. 'Test credentials in staging repo'">
      </div>
      <div class="field-group">
        <label>What are you requesting?</label>
        <select id="excDisp" class="field">
          <option value="accept_risk">Accept risk — the finding is real but tolerable</option>
          <option value="false_positive">False positive — the finding does not apply</option>
          <option value="adjust_risk">Adjust risk — the severity should be lower</option>
        </select>
      </div>
      <div class="field-group" id="excSevGroup" hidden>
        <label>What severity do you believe is correct?</label>
        <select id="excSev" class="field">
          ${SEV.map((s) => `<option value="${s}">${s}</option>`).join('')}
        </select>
      </div>
      <div class="field-group">
        <label>Justification (40+ characters)</label>
        <textarea id="excJust" class="field" placeholder="Why is this risk tolerable for your workload? What would an auditor need to know in six months?"></textarea>
      </div>
      <div class="field-group">
        <label>Business impact (optional)</label>
        <textarea id="excImpact" class="field" style="min-height:50px" placeholder="What business process depends on this staying as-is?"></textarea>
      </div>
      <div class="field-group">
        <label>Compensating controls (optional)</label>
        <textarea id="excControls" class="field" style="min-height:50px" placeholder="What reduces the exposure in the meantime?"></textarea>
      </div>
      <div class="field-group">
        <label>Requested duration (days)</label>
        <input id="excDays" type="number" class="field" value="90" min="1" max="365">
      </div>
    </div>
    <div class="drawer-foot">
      <button class="btn-ghost" onclick="closeDrawers()">Cancel</button>
      <button class="btn btn-seal" id="submitExc">Submit for review</button>
    </div>`;

  $('excDisp').onchange = () => {
    $('excSevGroup').hidden = $('excDisp').value !== 'adjust_risk';
  };
  $('submitExc').onclick = () => submitExceptionRequest(findingIds);
}

async function submitExceptionRequest(findingIds) {
  const body = {
    title: $('excTitle').value.trim(),
    finding_ids: findingIds,
    requested_disposition: $('excDisp').value,
    justification: $('excJust').value.trim(),
    business_impact: $('excImpact').value.trim() || null,
    compensating_controls: $('excControls').value.trim() || null,
    adjusted_severity: $('excDisp').value === 'adjust_risk' ? $('excSev').value : null,
    requested_duration_days: parseInt($('excDays').value) || 90,
    scope: findingIds.length > 1 ? 'vuln' : 'finding',
  };
  $('submitExc').disabled = true;
  try {
    await api('/api/exceptions', { method: 'POST', body: JSON.stringify(body) });
    toast('Exception submitted for review.');
    closeDrawers();
  } catch (e) {
    $('submitExc').disabled = false;
    toast(e.detail || e.message, true);
  }
}

// ---------------------------------------------------------------- saved views

async function loadSavedViews() {
  const views = await api('/api/views');
  const el = $('savedViews');
  el.innerHTML = views.map((v) =>
    `<button data-view-id="${v.id}" title="${esc(v.description || '')}">${esc(v.name)}${v.shared ? ' \u00b7 shared' : ''}</button>`
  ).join('') || '<span class="hint" style="font-size:11px">No saved views yet.</span>';
  el.onclick = (e) => {
    const b = e.target.closest('[data-view-id]');
    if (!b) return;
    const v = views.find((x) => x.id === Number(b.dataset.viewId));
    if (v) applySavedView(v);
  };
  $('saveCurrentView').onclick = saveCurrentFilter;
}

function applySavedView(v) {
  const f = v.filters || {};
  state.filter = {
    status: f.status || f.statuses || ['open'],
    source: f.sources || [], severity: f.severities || [], category: f.categories || [],
    disposition: f.dispositions || [], bucket: f.buckets || [], quick: f.quick || null,
    q: f.q || '', sort: f.sort || 'risk',
  };
  $('qInput').value = state.filter.q;
  $('sortSelect').value = state.filter.sort;
  state.page = 1;
  state.selected.clear();
  state.allMatchingIds = null;
  loadFindings();
  toast(`Loaded view: ${v.name}`);
}

async function saveCurrentFilter() {
  const name = prompt('Name for this saved view:');
  if (!name) return;
  const shared = confirm('Share this view with all users?');
  try {
    await api('/api/views', { method: 'POST', body: JSON.stringify({
      name, filters: state.filter, shared, pinned: true,
    })});
    toast('View saved');
    loadSavedViews();
  } catch (e) { toast(e.message, true); }
}

// Wire saved views into the findings load
const _origLoadFindings = loadFindings;
loadFindings = async function() {
  await _origLoadFindings();
  await loadSavedViews();
};

// ---------------------------------------------------------------- connector config

async function loadConnectorConfig() {
  const data = await api('/api/config/sources');
  const el = $('configCards');
  const names = { wiz: 'Wiz', falcon: 'CrowdStrike Falcon', github: 'GitHub' };
  el.innerHTML = Object.entries(data).map(([source, info]) => {
    const fields = info.fields || [];
    const config = info.config || {};
    return `<div class="source-card">
      <h4>${esc(names[source] || source)} API</h4>
      ${fields.map((f) => `<div class="field-group" style="margin:6px 0">
        <label style="font-size:11px">${esc(f.label)}${f.required ? ' *' : ''}</label>
        <input class="field mono" style="font-size:12px" data-source="${source}" data-key="${f.key}"
          type="${f.sensitive ? 'password' : 'text'}"
          value="${esc(config[f.key] || '')}"
          placeholder="${esc(f.placeholder || f.default || '')}">
        ${f.help ? `<div class="hint">${esc(f.help)}</div>` : ''}
      </div>`).join('')}
      <button class="btn" style="margin-top:8px" onclick="saveConnectorConfig('${source}')">Save</button>
    </div>`;
  }).join('');
}

async function saveConnectorConfig(source) {
  const inputs = document.querySelectorAll(`[data-source="${source}"]`);
  const config = {};
  inputs.forEach((inp) => {
    if (inp.value && inp.value !== '****' && !inp.value.includes('****')) {
      config[inp.dataset.key] = inp.value;
    }
  });
  try {
    await api(`/api/config/sources/${source}`, {
      method: 'POST', body: JSON.stringify({ config }),
    });
    toast(`${source} configuration saved`);
    loadConnectorConfig();
  } catch (e) { toast(e.message, true); }
}

// ---------------------------------------------------------------- enrichment

async function runEnrichment() {
  $('enrichBtn').disabled = true;
  $('enrichBtn').textContent = 'Updating feeds\u2026';
  try {
    const r = await api('/api/enrich', { method: 'POST' });
    const parts = [];
    if (r.epss) parts.push(`EPSS: ${r.epss.updated || 0} CVEs`);
    if (r.kev) parts.push(`KEV: ${r.kev.updated || 0} CVEs`);
    toast(parts.join(', ') || 'Feeds updated');
  } catch (e) { toast(e.message, true); }
  $('enrichBtn').disabled = false;
  $('enrichBtn').textContent = 'Update EPSS & KEV feeds';
}

// patch loadSources
const _origLoadSources2 = loadSources;
loadSources = async function() {
  await _origLoadSources2();
  await loadConnectorConfig();
  $('enrichBtn').onclick = runEnrichment;
};

// ---------------------------------------------------------------- Wiz query builder

let _wizLastResult = null;

async function runWizQuery() {
  const query = $('wizQueryInput').value.trim();
  if (!query) { toast('Enter a GraphQL query', true); return; }
  let variables = {};
  const varsText = $('wizVarsInput').value.trim();
  if (varsText && varsText !== '{}') {
    try { variables = JSON.parse(varsText); }
    catch (e) { toast('Variables must be valid JSON', true); return; }
  }
  $('wizQueryBtn').disabled = true;
  $('wizQueryBtn').textContent = 'Running…';
  $('wizQueryStatus').textContent = '';
  $('wizQueryResult').style.display = 'none';
  try {
    const t0 = Date.now();
    const res = await api('/api/wiz/query', { method: 'POST', body: JSON.stringify({ query, variables }) });
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    if (res.ok === false) {
      const detail = res.error + (res.traceback ? '\n\n' + res.traceback : '') + (res.debug ? '\n\nDebug: ' + JSON.stringify(res.debug) : '');
      $('wizQueryResult').textContent = detail;
      $('wizQueryResult').style.display = 'block';
      $('wizQueryStatus').textContent = 'Query failed';
      $('wizExportJSON').disabled = true;
      $('wizExportCSV').disabled = true;
      $('wizCopyResult').disabled = true;
    } else {
      _wizLastResult = res.data;
      $('wizQueryResult').textContent = JSON.stringify(res.data, null, 2);
      $('wizQueryResult').style.display = 'block';
      $('wizQueryStatus').textContent = `Completed in ${elapsed}s`;
      $('wizExportJSON').disabled = false;
      $('wizExportCSV').disabled = false;
      $('wizCopyResult').disabled = false;
    }
  } catch (e) {
    $('wizQueryResult').textContent = e.message || String(e);
    $('wizQueryResult').style.display = 'block';
    $('wizQueryStatus').textContent = 'Query failed';
    $('wizExportJSON').disabled = true;
    $('wizExportCSV').disabled = true;
    $('wizCopyResult').disabled = true;
  }
  $('wizQueryBtn').disabled = false;
  $('wizQueryBtn').textContent = 'Run Query';
}

async function runWizIntrospect() {
  const typeName = $('wizIntrospectType').value.trim();
  if (!typeName) { toast('Enter a type name to introspect', true); return; }
  $('wizIntrospectBtn').disabled = true;
  $('wizIntrospectBtn').textContent = 'Loading…';
  try {
    const res = await api('/api/wiz/introspect', { method: 'POST', body: JSON.stringify({ type: typeName }) });
    if (res.ok === false) {
      const detail = res.error + (res.traceback ? '\n\n' + res.traceback : '') + (res.debug ? '\n\nDebug: ' + JSON.stringify(res.debug) : '');
      $('wizQueryResult').textContent = detail;
      $('wizQueryResult').style.display = 'block';
      $('wizQueryStatus').textContent = 'Introspection failed';
    } else {
      _wizLastResult = { type: typeName, fields: res.fields };
      $('wizQueryResult').textContent = (res.fields || []).join('\n') || 'No fields found';
      $('wizQueryResult').style.display = 'block';
      $('wizQueryStatus').textContent = `${(res.fields || []).length} fields on ${typeName}`;
      $('wizExportJSON').disabled = false;
      $('wizExportCSV').disabled = true;
      $('wizCopyResult').disabled = false;
    }
  } catch (e) {
    $('wizQueryResult').textContent = e.message || String(e);
    $('wizQueryResult').style.display = 'block';
    $('wizQueryStatus').textContent = 'Introspection failed';
  }
  $('wizIntrospectBtn').disabled = false;
  $('wizIntrospectBtn').textContent = 'Introspect Type';
}

function wizExportJSON() {
  if (!_wizLastResult) return;
  const blob = new Blob([JSON.stringify(_wizLastResult, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'wiz-query-result.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

function wizExportCSV() {
  if (!_wizLastResult) return;
  const nodes = _findNodes(_wizLastResult);
  if (!nodes.length) { toast('No array data found to export as CSV', true); return; }
  const keys = [...new Set(nodes.flatMap(n => Object.keys(n)))];
  const escape = v => {
    const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    return s.includes(',') || s.includes('"') || s.includes('\n') ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const csv = [keys.join(','), ...nodes.map(n => keys.map(k => escape(n[k])).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'wiz-query-result.csv';
  a.click();
  URL.revokeObjectURL(a.href);
}

function _findNodes(obj) {
  if (Array.isArray(obj)) return obj;
  if (obj && typeof obj === 'object') {
    if (Array.isArray(obj.nodes)) return obj.nodes;
    for (const v of Object.values(obj)) {
      const found = _findNodes(v);
      if (found.length) return found;
    }
  }
  return [];
}

function wizCopyResult() {
  const text = $('wizQueryResult').textContent;
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard'));
}

$('wizQueryBtn').onclick = runWizQuery;
$('wizIntrospectBtn').onclick = runWizIntrospect;
$('wizExportJSON').onclick = wizExportJSON;
$('wizExportCSV').onclick = wizExportCSV;
$('wizCopyResult').onclick = wizCopyResult;

$('wizQueryInput').addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runWizQuery(); }
});

// ---------------------------------------------------------------- Wiz diagnostics

async function runWizTestSuite() {
  const btn = $('wizTestSuiteBtn');
  const el = $('wizTestSuiteResult');
  btn.disabled = true;
  btn.textContent = 'Running…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Running test suite — this checks config, auth, connectivity, schema, and data probes…</div>';

  try {
    const res = await api('/api/wiz/test-suite', { method: 'POST' });
    el.innerHTML = _renderTestSuite(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${e.message || e}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Run Test Suite';
}

function _renderTestSuite(res) {
  const summary = `<div style="display:flex;gap:12px;margin-bottom:12px;font-size:13px;font-weight:600">
    <span style="color:var(--success)">${res.passed} passed</span>
    <span style="color:var(--danger)">${res.failed} failed</span>
    <span style="color:var(--muted)">${res.skipped} skipped</span>
  </div>`;

  const rows = res.steps.map(s => {
    const icon = s.status === 'pass' ? '✓' : s.status === 'fail' ? '✗' : '—';
    const color = s.status === 'pass' ? 'var(--success)' : s.status === 'fail' ? 'var(--danger)' : 'var(--muted)';
    const timing = s.elapsed_s != null ? ` (${s.elapsed_s}s)` : '';

    let detail = '';
    if (s.status === 'fail') {
      detail = `<div style="color:var(--danger);font-size:12px;margin:4px 0 4px 24px;white-space:pre-wrap">${_esc(s.error)}</div>`;
      if (s.traceback) {
        detail += `<details style="margin:0 0 4px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Stack trace</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;margin:4px 0">${_esc(s.traceback)}</pre></details>`;
      }
    } else if (s.status === 'skip') {
      detail = `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">${_esc(s.reason)}</div>`;
    } else if (s.status === 'pass') {
      const extras = [];
      if (s.config) extras.push(`API: ${s.config.api_url}`);
      if (s.total_count != null) extras.push(`Count: ${s.total_count}`);
      if (s.total_fields != null) extras.push(`${s.total_fields} fields`);
      if (s.by_severity) extras.push(Object.entries(s.by_severity).map(([k,v]) => `${k}: ${v}`).join(', '));
      if (s.missing_fields) extras.push(`Missing: ${s.missing_fields.join(', ')}`);
      if (s.warning) detail += `<div style="color:var(--warning,#e6a700);font-size:12px;margin:2px 0 2px 24px">${_esc(s.warning)}</div>`;
      if (s.note) extras.push(s.note);
      if (s.sample) extras.push(`Sample: ${JSON.stringify(s.sample).substring(0, 120)}…`);
      if (s.mapped_record) extras.push(`Mapped: ${s.mapped_record.canonical_id} → ${s.mapped_record.severity}`);
      if (s.mapping_error) detail += `<div style="color:var(--danger);font-size:12px;margin:2px 0 2px 24px">Mapping error: ${_esc(s.mapping_error)}</div>`;
      if (s.raw_node) {
        detail += `<details style="margin:2px 0 2px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Raw node</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;margin:4px 0;max-height:200px;overflow:auto">${_esc(JSON.stringify(s.raw_node, null, 2))}</pre></details>`;
      }
      if (extras.length) detail += `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">${extras.join(' · ')}</div>`;
    }

    return `<div style="padding:4px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="color:${color};font-weight:700;width:14px;text-align:center">${icon}</span>
        <span style="font-size:13px;font-weight:500">${_esc(s.step)}</span>
        <span style="font-size:12px;color:var(--muted)">${_esc(s.description)}${timing}</span>
      </div>
      ${detail}
    </div>`;
  }).join('');

  return summary + '<div style="border:1px solid var(--border);border-radius:6px;padding:8px 12px">' + rows + '</div>';
}

function _esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

async function runWizDryRun() {
  const btn = $('wizDryRunBtn');
  const el = $('wizDryRunResult');
  btn.disabled = true;
  btn.textContent = 'Running…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Fetching sample records from Wiz (no database writes)…</div>';

  try {
    const res = await api('/api/wiz/dry-run', { method: 'POST' });
    el.innerHTML = _renderDryRun(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${e.message || e}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Dry Run (preview sync)';
}

function _renderDryRun(res) {
  if (!res.ok) {
    let html = `<div style="color:var(--danger);font-size:13px;margin-bottom:8px">${_esc(res.error)}</div>`;
    if (res.traceback) {
      html += `<details><summary style="font-size:11px;color:var(--muted);cursor:pointer">Stack trace</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap">${_esc(res.traceback)}</pre></details>`;
    }
    return html;
  }

  let html = `<div style="display:flex;gap:16px;margin-bottom:12px;font-size:13px">
    <span><strong>${res.fetched}</strong> fetched</span>
    <span style="color:var(--success)"><strong>${res.mapped}</strong> mapped successfully</span>
    ${res.mapping_errors ? `<span style="color:var(--danger)"><strong>${res.mapping_errors}</strong> mapping errors</span>` : ''}
  </div>`;

  if (res.by_severity && Object.keys(res.by_severity).length) {
    html += '<div style="display:flex;gap:8px;margin-bottom:12px">';
    for (const [sev, count] of Object.entries(res.by_severity)) {
      const color = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)',info:'var(--muted)'}[sev] || 'var(--fg)';
      html += `<span style="font-size:12px;padding:2px 8px;border-radius:4px;background:color-mix(in srgb, ${color} 15%, transparent);color:${color}">${sev}: ${count}</span>`;
    }
    html += '</div>';
  }

  if (res.errors && res.errors.length) {
    html += '<details style="margin-bottom:8px"><summary style="font-size:12px;color:var(--danger);cursor:pointer">Mapping errors</summary>';
    html += res.errors.map(e => `<div style="font-size:12px;padding:2px 0;color:var(--muted)">Node ${_esc(e.node_id || '?')}: ${_esc(e.error)}</div>`).join('');
    html += '</details>';
  }

  if (res.records && res.records.length) {
    html += '<div style="overflow-x:auto"><table style="width:100%;font-size:12px;border-collapse:collapse">';
    html += '<thead><tr style="text-align:left;border-bottom:2px solid var(--border)">';
    html += '<th style="padding:4px 8px">CVE / ID</th><th style="padding:4px 8px">Severity</th><th style="padding:4px 8px">Asset</th><th style="padding:4px 8px">Component</th><th style="padding:4px 8px">Fix</th>';
    html += '</tr></thead><tbody>';
    for (const r of res.records) {
      const sevColor = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)',info:'var(--muted)'}[r.severity] || 'var(--fg)';
      html += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-family:monospace">${_esc(r.vuln.canonical_id || '')}</td>
        <td style="padding:4px 8px;color:${sevColor}">${_esc(r.severity)}</td>
        <td style="padding:4px 8px">${_esc(r.asset.name || '')} <span style="color:var(--muted)">${_esc(r.asset.region || '')}</span></td>
        <td style="padding:4px 8px">${_esc(r.component || '—')}</td>
        <td style="padding:4px 8px">${r.fix_available ? _esc(r.fix_version || 'yes') : '—'}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }

  if (res.raw_sample) {
    html += `<details style="margin-top:8px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Raw API response (first record)</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:300px;overflow:auto">${_esc(JSON.stringify(res.raw_sample, null, 2))}</pre></details>`;
  }

  return html;
}

async function loadWizTemplates() {
  try {
    const res = await api('/api/wiz/query-templates');
    const el = $('wizTemplates');
    if (!res.templates || !res.templates.length) { el.style.display = 'none'; return; }
    el.innerHTML = res.templates.map(t =>
      `<button class="btn-ghost" style="font-size:11px;padding:3px 10px" onclick='_loadTemplate(${JSON.stringify(t.name)})' title="${_esc(t.description)}">${_esc(t.label)}</button>`
    ).join('');
    window._wizTemplates = res.templates;
  } catch (e) {
    // templates are a convenience — fail silently
  }
}

function _loadTemplate(name) {
  const t = (window._wizTemplates || []).find(t => t.name === name);
  if (!t) return;
  $('wizQueryInput').value = t.query;
  $('wizVarsInput').value = t.variables && Object.keys(t.variables).length ? JSON.stringify(t.variables, null, 2) : '{}';
  toast(`Loaded: ${t.label}`);
  // scroll the query builder into view
  $('wizQueryInput').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('wizQueryInput').focus();
}

$('wizTestSuiteBtn').onclick = runWizTestSuite;
$('wizDryRunBtn').onclick = runWizDryRun;

const _origLoadSources3 = loadSources;
loadSources = async function() {
  await _origLoadSources3();
  loadWizTemplates();
};

// ---------------------------------------------------------------- settings (tokens + correlation)

async function loadDecisionTemplates() {
  const el = $('templateList');
  const templates = await api('/api/decision-templates');
  _templatesCache = templates;
  if (!templates.length) {
    el.innerHTML = '<div class="empty">No templates yet. Create one and it will appear in the Decide drawer.</div>';
    return;
  }
  el.innerHTML = templates.map((t) => `
    <div class="row" style="grid-template-columns:30px 1fr 180px 120px 120px;cursor:default" data-template="${t.id}">
      <div class="edge ${t.enabled ? 'sev-high' : 'sev-low'}"></div>
      <div class="row-main">
        <div class="row-id">${esc(t.name)}</div>
        <div class="row-title">${esc(t.description || '')}</div>
        <div class="row-meta">
          <span>${esc(t.disposition.replace('_', ' '))}</span>
          <span>scope: ${esc(t.scope)}</span>
          ${t.expiry_days ? `<span>${t.expiry_days}d expiry</span>` : ''}
          ${t.remediation_days ? `<span>${t.remediation_days}d remediation</span>` : ''}
          ${t.adjusted_severity ? `<span>→ ${esc(t.adjusted_severity)}</span>` : ''}
        </div>
      </div>
      <div class="row-asset">${esc(t.created_by || '')}
        <small>${t.updated_at ? 'Updated ' + fmtDate(t.updated_at) : ''}</small>
      </div>
      <div class="row-asset">${t.enabled ? 'Enabled' : 'Disabled'}</div>
      <div>
        <button class="btn-ghost" style="font-size:11px" onclick="openTemplateEditor(${t.id})">Edit</button>
        <button class="link" style="font-size:11px;color:var(--seal)" onclick="deleteDecisionTemplate(${t.id})">Delete</button>
      </div>
    </div>`).join('');
}

function openTemplateEditor(id) {
  const existing = id ? _templateById(id) : null;
  const t = existing || {
    name: '', description: '', disposition: 'accept_risk', scope: 'finding',
    justification_text: '', compensating_controls: '', adjusted_severity: '',
    expiry_days: 90, remediation_days: null, enabled: true,
  };
  const el = $('detail');
  openDrawer(el);
  const meta = state.meta;
  el.innerHTML = `
    <div class="drawer-head">
      <div><h2>${id ? 'Edit' : 'New'} decision template</h2>
        <p>Pre-filled Decide form</p></div>
      <button class="x" onclick="closeDrawers()" aria-label="Close">×</button>
    </div>
    <div class="drawer-body">
      <div class="field-group"><label>Name</label>
        <input id="tplName" class="field" value="${esc(t.name)}"></div>
      <div class="field-group"><label>Description</label>
        <input id="tplDesc" class="field" value="${esc(t.description || '')}"></div>
      <div class="field-row">
        <div class="field-group" style="flex:1"><label>Disposition</label>
          <select id="tplDisp" class="field">
            ${meta.dispositions.map((d) => `<option value="${d.value}"${t.disposition === d.value ? ' selected' : ''}>${esc(d.label)}</option>`).join('')}
          </select>
        </div>
        <div class="field-group" style="flex:1"><label>Default scope</label>
          <select id="tplScope" class="field">
            ${meta.scopes.map((s) => `<option value="${s.value}"${t.scope === s.value ? ' selected' : ''}>${esc(s.label)}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="field-group"><label>Justification template</label>
        <textarea id="tplJust" class="field" style="min-height:120px">${esc(t.justification_text)}</textarea>
        <div class="hint">What the reviewer sees pre-filled. Edit freely per decision.</div></div>
      <div class="field-group"><label>Compensating controls</label>
        <textarea id="tplComp" class="field" style="min-height:60px">${esc(t.compensating_controls || '')}</textarea></div>
      <div class="field-row">
        <div class="field-group" style="flex:1"><label>Expiry (days, risk decisions)</label>
          <input id="tplExp" class="field" type="number" value="${t.expiry_days || ''}"></div>
        <div class="field-group" style="flex:1"><label>Remediation due (days, routing)</label>
          <input id="tplRem" class="field" type="number" value="${t.remediation_days || ''}"></div>
      </div>
      <div class="field-row">
        <div class="field-group" style="flex:1"><label>Adjusted severity (adjust_risk only)</label>
          <select id="tplSev" class="field">
            <option value="">— none —</option>
            ${SEV_ORDER.map((s) => `<option value="${s}"${t.adjusted_severity === s ? ' selected' : ''}>${s}</option>`).join('')}
          </select>
        </div>
        <div class="field-group" style="flex:1"><label><input type="checkbox" id="tplEnabled" ${t.enabled ? 'checked' : ''}> Enabled</label></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="btn btn-seal" onclick="saveTemplate(${id || 'null'})">${id ? 'Save' : 'Create'}</button>
        <button class="btn-ghost" onclick="closeDrawers()">Cancel</button>
      </div>
    </div>`;
}

let _templatesCache = [];
function _templateById(id) {
  return _templatesCache.find((t) => t.id === id);
}

async function saveTemplate(id) {
  const body = {
    name: $('tplName').value.trim(),
    description: $('tplDesc').value.trim() || null,
    disposition: $('tplDisp').value,
    scope: $('tplScope').value,
    justification_text: $('tplJust').value.trim(),
    compensating_controls: $('tplComp').value.trim() || null,
    adjusted_severity: $('tplSev').value || null,
    expiry_days: $('tplExp').value ? parseInt($('tplExp').value) : null,
    remediation_days: $('tplRem').value ? parseInt($('tplRem').value) : null,
    enabled: $('tplEnabled').checked,
  };
  if (!body.name || !body.justification_text) {
    toast('Name and justification are required', true);
    return;
  }
  try {
    if (id) await api(`/api/decision-templates/${id}`, { method: 'PUT', body: JSON.stringify(body) });
    else await api('/api/decision-templates', { method: 'POST', body: JSON.stringify(body) });
    toast('Template saved');
    closeDrawers();
    loadDecisionTemplates();
  } catch (e) { toast(e.message || 'Save failed', true); }
}

async function deleteDecisionTemplate(id) {
  if (!confirm('Delete this template?')) return;
  await api(`/api/decision-templates/${id}`, { method: 'DELETE' });
  toast('Template deleted');
  loadDecisionTemplates();
}

async function loadSettings() {
  // Tokens
  const tokens = await api('/api/tokens');
  const tl = $('tokenList');
  tl.innerHTML = tokens.length ? tokens.map((t) => `
    <div class="row" style="grid-template-columns:30px 1fr 200px 150px 100px;cursor:default">
      <div class="edge ${t.active ? 'sev-high' : 'sev-low'}"></div>
      <div class="row-main">
        <div class="row-id">${esc(t.name)}</div>
        <div class="row-meta"><span class="mono">${esc(t.prefix)}\u2026</span>
          ${t.scopes?.length ? `<span>scopes: ${esc(t.scopes.join(', '))}</span>` : '<span>all permissions</span>'}
        </div>
      </div>
      <div class="row-asset">${t.last_used ? 'Last used ' + fmtDate(t.last_used) : 'Never used'}
        <small>Created ${fmtDate(t.created_at)}</small></div>
      <div class="row-asset">${t.expires_at ? 'Expires ' + fmtDate(t.expires_at) : 'No expiry'}</div>
      <div><button class="btn-ghost" style="font-size:11px" onclick="revokeApiToken(${t.id})">${t.active ? 'Revoke' : 'Revoked'}</button></div>
    </div>`).join('') : '<div class="empty">No API tokens. Create one for CI pipelines or scripts.</div>';

  $('newToken').onclick = createApiToken;

  // Decision templates
  loadDecisionTemplates();
  $('newTemplate').onclick = () => openTemplateEditor(null);

  // Correlation
  try {
    const stats = await api('/api/correlations/stats');
    $('correlationStats').innerHTML = `<div class="coverage" style="margin:12px 0">
      <b>${stats.raw_count.toLocaleString()}</b> raw findings,
      <b>${stats.deduplicated_count.toLocaleString()}</b> after dedup
      (${stats.duplicate_findings.toLocaleString()} cross-source duplicates in
      ${stats.correlation_groups} correlation groups)</div>`;
  } catch (e) {
    $('correlationStats').innerHTML = '';
  }

  const corrs = await api('/api/correlations');
  const cl = $('correlationList');
  cl.innerHTML = corrs.length ? corrs.map((c) => `
    <div class="row" style="grid-template-columns:30px 1fr 200px 100px;cursor:default">
      <div class="edge sev-medium"></div>
      <div class="row-main">
        <div class="row-id">${esc(c.canonical_name)}</div>
        <div class="row-meta">
          ${c.sources.map((s) => `<span>${esc(s)}</span>`).join('')}
          <span>${c.asset_count} assets</span>
          <span>${c.finding_count} findings</span>
          <span>${esc(c.match_method)}</span>
        </div>
      </div>
      <div class="row-asset">${c.environment || ''}<small>${c.data_classification || ''}</small></div>
      <div><button class="btn-ghost" style="font-size:11px" onclick="deleteCorrelation(${c.id})">Remove</button></div>
    </div>`).join('') : '<div class="empty">No correlations yet. Auto-correlate matches assets across sources by hostname.</div>';

  $('autoCorrelate').onclick = async () => {
    const r = await api('/api/correlations/auto', {
      method: 'POST', body: JSON.stringify({ method: 'hostname' }),
    });
    toast(`Created ${r.created} correlation groups`);
    loadSettings();
  };

  // Pipeline containers
  $('refreshContainers').onclick = loadContainers;
  await loadContainers();
}

async function loadContainers() {
  const containers = await api('/api/pipeline/containers');
  const el = $('containerList');
  if (containers.length === 1 && containers[0].error) {
    el.innerHTML = `<div class="empty">${esc(containers[0].error)}<br>
      <span class="hint">Mount the Docker socket into RiskDesk to enable container management,
      or install the DevSecOps pipeline stack separately.</span></div>`;
    return;
  }
  el.innerHTML = containers.map((c) => {
    const stateClass = c.state === 'running' ? 'sev-high' : c.state === 'exited' ? 'sev-low' : 'sev-medium';
    return `<div class="row" style="grid-template-columns:30px 1fr 200px 180px 160px;cursor:default">
      <div class="edge ${stateClass}"></div>
      <div class="row-main">
        <div class="row-id">${esc(c.name)}</div>
        <div class="row-title">${esc(c.description)}</div>
        <div class="row-meta">
          <span>${esc(c.container)}</span>
          ${c.port ? `<span>port ${c.port}</span>` : ''}
        </div>
      </div>
      <div class="row-asset">${esc(c.status)}</div>
      <div class="row-state">
        <span class="tag ${c.state === 'running' ? 'tag-decided' : 'tag-muted'}">${esc(c.state)}</span>
      </div>
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        ${c.state === 'running'
          ? `<button class="btn-ghost" style="font-size:11px" onclick="containerAction('${c.service}','restart')">Restart</button>
             <button class="btn-ghost" style="font-size:11px" onclick="containerAction('${c.service}','stop')">Stop</button>`
          : `<button class="btn-ghost" style="font-size:11px" onclick="containerAction('${c.service}','start')">Start</button>`}
        <button class="btn-ghost" style="font-size:11px" onclick="containerLogs('${c.service}')">Logs</button>
      </div>
    </div>`;
  }).join('');
}

async function containerAction(service, action) {
  try {
    const r = await api(`/api/pipeline/containers/${service}/${action}`, { method: 'POST' });
    toast(r.success ? `${service}: ${action} succeeded` : `${service}: ${r.output || r.error}`, !r.success);
    setTimeout(loadContainers, 2000);
  } catch (e) { toast(e.message, true); }
}

async function containerLogs(service) {
  const el = $('detail');
  openDrawer(el);
  el.innerHTML = '<div class="spin">Fetching logs\u2026</div>';
  try {
    const r = await api(`/api/pipeline/containers/${service}/logs`, { method: 'POST' });
    el.innerHTML = `<div class="drawer-head"><div><h2>${esc(service)} logs</h2></div>
      <button class="x" onclick="closeDrawers()">\u00d7</button></div>
      <div class="drawer-body"><pre class="mono" style="font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.5">${esc(r.logs || 'No logs available.')}</pre></div>`;
  } catch (e) {
    el.innerHTML = `<div class="drawer-body"><div class="hint is-warn">${esc(e.message)}</div></div>`;
  }
}

async function createApiToken() {
  const name = prompt('Token name (e.g. "CI pipeline", "weekly report script"):');
  if (!name) return;
  const days = prompt('Expires in how many days? (leave blank for no expiry)');
  try {
    const r = await api('/api/tokens', {
      method: 'POST', body: JSON.stringify({
        name, expires_days: days ? parseInt(days) : null,
      }),
    });
    // Show the token in a non-dismissable way
    const el = $('detail');
    openDrawer(el);
    el.innerHTML = `<div class="drawer-head"><div><h2>API Token Created</h2></div>
      <button class="x" onclick="closeDrawers()">\u00d7</button></div>
      <div class="drawer-body">
        <div class="stamp"><div class="stamp-disp">COPY THIS TOKEN NOW</div>
          <div class="stamp-meta">It will not be shown again.</div>
          <div class="mono" style="margin-top:12px;padding:12px;background:var(--paper);border:1px solid var(--rule);word-break:break-all;font-size:14px;user-select:all">${esc(r.token)}</div>
          <div class="hint" style="margin-top:12px">Use as: <code>Authorization: Bearer ${esc(r.token.slice(0, 20))}\u2026</code></div>
        </div>
      </div>`;
    loadSettings();
  } catch (e) { toast(e.message, true); }
}

async function revokeApiToken(id) {
  if (!confirm('Revoke this token? Any automation using it will stop working.')) return;
  await api(`/api/tokens/${id}`, { method: 'DELETE' });
  toast('Token revoked');
  loadSettings();
}

async function deleteCorrelation(id) {
  await api(`/api/correlations/${id}`, { method: 'DELETE' });
  toast('Correlation removed');
  loadSettings();
}

// ---------------------------------------------------------------- compliance targets (in compliance tab)

const _origLoadCompliance = loadCompliance;
loadCompliance = async function() {
  await _origLoadCompliance();
  // Add target controls and report button to the summary
  const el = $('complianceSummary');
  if (!el) return;

  // Add report button
  const toolbar = el.closest('.pane')?.querySelector('.toolbar .toolbar-right');
  if (toolbar && !toolbar.querySelector('#reportBtn')) {
    const btn = document.createElement('a');
    btn.id = 'reportBtn';
    btn.className = 'btn-ghost';
    btn.href = '/api/report';
    btn.target = '_blank';
    btn.textContent = 'Executive report JSON';
    toolbar.insertBefore(btn, toolbar.firstChild);
  }

  // Load targets and add set-target buttons to cards
  try {
    const targets = await api('/api/compliance/targets');
    const cards = el.querySelectorAll('.source-card');
    const data = await api('/api/compliance');
    for (const bm of (data.benchmarks || [])) {
      const target = targets.find((t) => t.benchmark_id === bm.benchmark_id);
      const card = [...cards].find((c) => c.querySelector('h4')?.textContent.includes(bm.name));
      if (!card) continue;
      const existing = card.querySelector('.target-info');
      if (existing) existing.remove();
      const div = document.createElement('div');
      div.className = 'target-info';
      if (target) {
        const glide = _glideScore(target);
        const onTrack = bm.latest_score >= glide;
        div.innerHTML = `<div class="kv" style="margin-top:8px;font-size:12px">
          <dt>Target</dt><dd>${target.target_percent}% by ${fmtDate(target.target_date)}</dd>
          <dt>Glide path</dt><dd>${glide.toFixed(1)}% now \u2014 <strong style="color:${onTrack ? 'var(--ink)' : 'var(--seal)'}">${onTrack ? 'on track' : 'behind'}</strong></dd>
        </div>`;
      }
      div.innerHTML += `<button class="btn-ghost" style="margin-top:6px;font-size:11px" onclick="setComplianceTarget(${bm.benchmark_id}, ${bm.latest_score})">
        ${target ? 'Update target' : 'Set target'}</button>`;
      card.appendChild(div);
    }
  } catch (e) { /* targets are optional */ }
};

function _glideScore(target) {
  if (!target.baseline_percent || !target.baseline_date) return target.target_percent;
  const start = new Date(target.baseline_date).getTime();
  const end = new Date(target.target_date).getTime();
  const now = Date.now();
  const progress = Math.min(1, Math.max(0, (now - start) / (end - start)));
  return target.baseline_percent + progress * (target.target_percent - target.baseline_percent);
}

async function setComplianceTarget(benchmarkId, currentScore) {
  const targetPct = prompt('Target compliance percentage:', '100');
  if (!targetPct) return;
  const targetDate = prompt('Target date (YYYY-MM-DD):', '2027-04-01');
  if (!targetDate) return;
  const baselinePct = prompt('Baseline percentage (starting point):', String(currentScore || ''));
  try {
    await api('/api/compliance/targets', { method: 'POST', body: JSON.stringify({
      benchmark_id: benchmarkId,
      target_percent: parseFloat(targetPct),
      target_date: targetDate,
      baseline_percent: baselinePct ? parseFloat(baselinePct) : null,
      baseline_date: new Date().toISOString().slice(0, 10),
    })});
    toast('Target set');
    loadCompliance();
  } catch (e) { toast(e.message, true); }
}

// ---------------------------------------------------------------- tickets

let _ticketFilter = { status: '', q: '' };

async function loadTickets() {
  const el = $('ticketList');
  if (!el) return;
  el.innerHTML = '<div class="spin">Loading…</div>';
  try {
    const params = new URLSearchParams();
    if (_ticketFilter.status) params.set('status', _ticketFilter.status);
    const tickets = await api(`/api/tickets?${params}`);
    const filtered = _ticketFilter.q
      ? tickets.filter(t => (t.summary + t.external_id + (t.assignee||'')).toLowerCase().includes(_ticketFilter.q.toLowerCase()))
      : tickets;
    if (!filtered.length) {
      el.innerHTML = '<div class="empty">No tickets yet. Create one from selected findings or from a finding detail view.</div>';
      return;
    }
    el.innerHTML = filtered.map(ticketRowHtml).join('');
    el.onclick = (e) => {
      const row = e.target.closest('.row');
      if (!row) return;
      openTicketDetail(Number(row.dataset.id));
    };
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function ticketRowHtml(t) {
  const statusCls = t.status === 'resolved' || t.status === 'closed' ? 'sev-low'
    : t.status === 'in_progress' ? 'sev-medium'
    : t.status === "won't_fix" ? 'sev-info' : 'sev-high';
  return `<div class="row" data-id="${t.id}" style="cursor:pointer">
    <div class="row-main">
      <div class="row-id mono" style="min-width:120px">
        ${t.external_url ? `<a href="${esc(t.external_url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(t.external_id)}</a>` : esc(t.external_id)}
      </div>
      <div style="flex:1">
        <div>${esc(t.summary)}</div>
        <div class="row-meta">${t.finding_count} finding(s) · ${esc(t.severity || '')} · ${esc(t.provider)}</div>
      </div>
      <div class="sev ${statusCls}" style="min-width:90px;text-align:center">${esc(t.status.replace(/_/g, ' '))}</div>
      <div style="min-width:80px;text-align:right;font-size:12px;color:var(--muted)">${fmtDate(t.created_at)}</div>
    </div>
  </div>`;
}

async function openTicketDetail(id) {
  const el = $('detail');
  openDrawer(el);
  el.innerHTML = '<div class="spin">Loading…</div>';
  const t = await api(`/api/tickets/${id}`);

  el.innerHTML = `
    <div class="drawer-head">
      <div>
        <h2>${t.external_url ? `<a href="${esc(t.external_url)}" target="_blank" rel="noopener">${esc(t.external_id)}</a>` : esc(t.external_id)}</h2>
        <p>${esc(t.summary)}</p>
      </div>
      <button class="x" onclick="closeDrawers()">×</button>
    </div>
    <div class="drawer-body">
      <dl class="kv">
        <dt>Status</dt><dd><strong>${esc(t.status.replace(/_/g, ' '))}</strong></dd>
        <dt>Provider</dt><dd>${esc(t.provider)}</dd>
        <dt>Priority</dt><dd>${esc(t.priority || 'none')}</dd>
        <dt>Assignee</dt><dd>${esc(t.assignee || 'unassigned')}</dd>
        <dt>Severity</dt><dd>${esc(t.severity || 'unknown')}</dd>
        <dt>Findings</dt><dd>${t.finding_count}</dd>
        <dt>Created</dt><dd>${fmtDate(t.created_at)} by ${esc(t.created_by)}</dd>
        ${t.resolved_at ? `<dt>Resolved</dt><dd>${fmtDate(t.resolved_at)}</dd>` : ''}
        ${t.synced_at ? `<dt>Last synced</dt><dd>${fmtDate(t.synced_at)}</dd>` : ''}
      </dl>
      ${t.description ? `<div class="sec" style="margin-top:16px"><h3>Description</h3><div class="prose" style="white-space:pre-wrap;font-size:12px">${esc(t.description)}</div></div>` : ''}

      <div class="sec" style="margin-top:16px">
        <h3>Linked findings</h3>
        <div style="font-size:12px">${(t.finding_ids || []).map(fid => `<a href="#" onclick="event.preventDefault();closeDrawers();openDetail(${fid})" style="margin-right:8px">Finding #${fid}</a>`).join('')}</div>
      </div>

      <div class="sec" style="margin-top:16px">
        <h3>Vulnerability IDs</h3>
        <div class="mono" style="font-size:12px">${(t.vuln_ids || []).join(', ') || 'none'}</div>
      </div>

      <div style="margin-top:20px;display:flex;gap:8px">
        ${t.provider === 'jira' ? `<button class="btn-ghost" onclick="syncTicket(${t.id})">Sync from Jira</button>` : ''}
        <button class="btn-ghost" onclick="updateTicketStatus(${t.id}, '${t.status}')">Update status</button>
      </div>
    </div>`;
}

async function syncTicket(id) {
  try {
    const res = await fetch(`/api/tickets/${id}/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-RiskDesk-User': currentUser() },
    });
    const r = await res.json();
    if (res.ok && r.ok !== false) { toast('Synced from Jira'); openTicketDetail(id); }
    else toast(r.error || 'Sync failed', true);
  } catch (e) { toast(e.message, true); }
}

async function updateTicketStatus(id, current) {
  const statuses = ['open', 'in_progress', 'resolved', 'closed', "won't_fix"];
  const next = prompt(`Update status (current: ${current}).\nOptions: ${statuses.join(', ')}`, current);
  if (!next || next === current) return;
  try {
    await api(`/api/tickets/${id}`, { method: 'PUT', body: JSON.stringify({ status: next }) });
    toast('Status updated');
    openTicketDetail(id);
    if (state.view === 'tickets') loadTickets();
  } catch (e) { toast(e.message, true); }
}

async function verifyFinding(id) {
  const note = prompt('Mark this finding as verified fixed.\nHow was the fix confirmed? (optional)', '');
  if (note === null) return;
  try {
    await api(`/api/findings/${id}/verify`, { method: 'POST', body: JSON.stringify({ note }) });
    toast('Finding verified as fixed');
    openDetail(id);
  } catch (e) { toast(e.message || 'Verification failed', true); }
}

async function loadFindingTickets(findingId) {
  const el = $('findingTicketList');
  if (!el) return;
  try {
    const tickets = await api(`/api/tickets/for-finding/${findingId}`);
    if (!tickets.length) {
      el.innerHTML = '<span class="na">No tickets linked to this finding</span>';
      return;
    }
    el.innerHTML = tickets.map(t => `
      <div style="margin-bottom:6px;font-size:12px">
        ${t.external_url ? `<a href="${esc(t.external_url)}" target="_blank" rel="noopener">${esc(t.external_id)}</a>` : esc(t.external_id)}
        <span class="mono">${esc(t.status.replace(/_/g, ' '))}</span>
        · ${esc(t.summary).slice(0, 80)}
        ${t.provider === 'jira' ? `<button class="link" style="font-size:11px" onclick="syncTicket(${t.id})">sync</button>` : ''}
      </div>`).join('');
  } catch (_) { el.innerHTML = '<span class="na">Could not load tickets</span>'; }
}

function openCreateTicket(findingIds) {
  $('detail').hidden = true;
  const el = $('decide');
  openDrawer(el);
  el.innerHTML = `
    <div class="drawer-head">
      <div><h2>Create ticket</h2><p>${findingIds.length} finding(s) selected</p></div>
      <button class="x" onclick="closeDrawers()">×</button>
    </div>
    <div class="drawer-body">
      <div class="field-group">
        <label class="micro-label">Provider</label>
        <select id="ticketProvider" class="field-sm">
          <option value="jira">Jira (auto-create)</option>
          <option value="manual">Manual / external</option>
        </select>
      </div>
      <div class="field-group">
        <label class="micro-label">Summary</label>
        <input id="ticketSummary" class="field" placeholder="Auto-generated if blank">
      </div>
      <div class="field-group">
        <label class="micro-label">Project key</label>
        <input id="ticketProject" class="field-sm" placeholder="e.g. VULN">
      </div>
      <div class="field-group">
        <label class="micro-label">Issue type</label>
        <input id="ticketIssueType" class="field-sm" value="Bug">
      </div>
      <div class="field-group">
        <label class="micro-label">Priority</label>
        <select id="ticketPriority" class="field-sm">
          <option value="">Auto (from severity)</option>
          <option value="P1">P1 - Critical</option>
          <option value="P2">P2 - High</option>
          <option value="P3">P3 - Medium</option>
          <option value="P4">P4 - Low</option>
        </select>
      </div>
      <div id="manualTicketFields" hidden>
        <div class="field-group">
          <label class="micro-label">External ID</label>
          <input id="ticketExtId" class="field-sm" placeholder="e.g. VULN-1234">
        </div>
        <div class="field-group">
          <label class="micro-label">External URL</label>
          <input id="ticketExtUrl" class="field" placeholder="https://jira.example.com/browse/VULN-1234">
        </div>
      </div>
      <div id="createTicketError" class="hint" style="color:var(--seal);margin-top:8px" hidden></div>
      <button class="btn btn-seal" style="margin-top:16px" onclick="_submitTicket(${JSON.stringify(findingIds)})">Create ticket</button>
    </div>`;

  $('ticketProvider').onchange = () => {
    $('manualTicketFields').hidden = $('ticketProvider').value !== 'manual';
  };
}

async function _submitTicket(findingIds) {
  const provider = $('ticketProvider').value;
  const payload = {
    finding_ids: findingIds,
    provider,
    summary: $('ticketSummary').value || undefined,
    project_key: $('ticketProject').value || undefined,
    issue_type: $('ticketIssueType').value || undefined,
    priority: $('ticketPriority').value || undefined,
  };
  if (provider === 'manual') {
    payload.external_id = $('ticketExtId').value || undefined;
    payload.external_url = $('ticketExtUrl').value || undefined;
  }
  try {
    const res = await fetch('/api/tickets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-RiskDesk-User': currentUser() },
      body: JSON.stringify(payload),
    });
    const r = await res.json();
    if (!res.ok || r.ok === false) {
      $('createTicketError').textContent = r.error || r.detail || `Error ${res.status}`;
      $('createTicketError').hidden = false;
      return;
    }
    toast(`Ticket ${r.external_id} created`);
    closeDrawers();
    if (state.view === 'tickets') loadTickets();
  } catch (e) {
    $('createTicketError').textContent = e.message;
    $('createTicketError').hidden = false;
  }
}

// --- ticket tab wiring ---

(function wireTicketTab() {
  const stateButtons = document.querySelectorAll('#ticketState button');
  stateButtons.forEach(b => b.onclick = () => {
    stateButtons.forEach(x => x.classList.remove('is-active'));
    b.classList.add('is-active');
    _ticketFilter.status = b.dataset.state;
    loadTickets();
  });
  const search = $('ticketSearch');
  if (search) {
    let _t;
    search.oninput = () => { clearTimeout(_t); _t = setTimeout(() => { _ticketFilter.q = search.value; loadTickets(); }, 300); };
  }
  const btn = $('newTicketBtn');
  if (btn) btn.onclick = () => {
    if (state.selected.size) openCreateTicket([...state.selected]);
    else toast('Select findings first on the Findings tab, or open a finding detail to create a ticket.', true);
  };
})();

// ---------------------------------------------------------------- Wiz file import

(function wireWizImport() {
  const input = $('wizImportFile');
  if (!input) return;
  input.onchange = async () => {
    const file = input.files[0];
    if (!file) return;
    const status = $('wizImportStatus');
    status.innerHTML = '<div class="spin">Importing…</div>';
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      const r = await api('/api/wiz/import-file', { method: 'POST', body: JSON.stringify(data) });
      if (r.ok === false) {
        status.innerHTML = `<div class="hint" style="color:var(--seal)"><strong>Import failed:</strong> ${esc(r.error)}</div>`;
        if (r.mapping_errors && r.mapping_errors.length) {
          status.innerHTML += `<pre style="font-size:11px;max-height:200px;overflow:auto">${esc(JSON.stringify(r.mapping_errors, null, 2))}</pre>`;
        }
        return;
      }
      status.innerHTML = `<div class="hint" style="color:var(--ink)"><strong>Import successful:</strong>
        ${r.findings} findings processed, ${r.new} new, ${r.assets} assets.
        ${r.mapping_errors && r.mapping_errors.length ? `<br>${r.mapping_errors.length} nodes could not be mapped.` : ''}
      </div>`;
      toast(`Imported ${r.findings} findings from Wiz export`);
    } catch (e) {
      status.innerHTML = `<div class="hint" style="color:var(--seal)"><strong>Error:</strong> ${esc(e.message)}</div>`;
    }
    input.value = '';
  };
})();

// ---------------------------------------------------------------- Historical remediation import

(function wireHistoricalImport() {
  const input = $('historicalImportFile');
  if (!input) return;
  input.onchange = async () => {
    const file = input.files[0];
    if (!file) return;
    const status = $('historicalImportStatus');
    status.innerHTML = '<div class="spin">Importing…</div>';
    try {
      const form = new FormData();
      form.append('file', file);
      const r = await fetch('/api/findings/import-historical', {
        method: 'POST', body: form, headers: { 'X-RiskDesk-User': currentUser() },
      });
      const data = await r.json();
      if (!r.ok || data.ok === false) {
        status.innerHTML = `<div class="hint" style="color:var(--seal)"><strong>Import had errors.</strong>
          ${data.created || 0} created, ${data.skipped || 0} already existed, ${data.errors || 0} failed.</div>`;
        const errs = (data.results || []).filter((x) => x.status === 'error').slice(0, 10);
        if (errs.length) {
          status.innerHTML += `<pre style="font-size:11px;max-height:200px;overflow:auto">${esc(JSON.stringify(errs, null, 2))}</pre>`;
        }
      } else {
        status.innerHTML = `<div class="hint"><strong>Import successful:</strong>
          ${data.created} created, ${data.skipped} already existed from ${data.processed} rows.</div>`;
        toast(`Imported ${data.created} historical findings`);
      }
    } catch (e) {
      status.innerHTML = `<div class="hint" style="color:var(--seal)"><strong>Error:</strong> ${esc(e.message)}</div>`;
    }
    input.value = '';
  };
})();

// ---------------------------------------------------------------- GitHub Advanced Security diagnostics

let _ghLastResult = null;

async function runGhTestSuite() {
  const btn = $('ghTestSuiteBtn');
  const el = $('ghTestSuiteResult');
  btn.disabled = true;
  btn.textContent = 'Running…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Running test suite — checking config, auth, org access, alert family probes, repos, and sample mapping…</div>';
  try {
    const res = await api('/api/github/test-suite', { method: 'POST' });
    el.innerHTML = _renderGhTestSuite(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${_esc(e.message || e)}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Run Test Suite';
}

function _renderGhTestSuite(res) {
  const summary = `<div style="display:flex;gap:12px;margin-bottom:12px;font-size:13px;font-weight:600">
    <span style="color:var(--success)">${res.passed} passed</span>
    <span style="color:var(--danger)">${res.failed} failed</span>
    <span style="color:var(--muted)">${res.skipped} skipped</span>
  </div>`;
  const rows = res.steps.map(s => {
    const icon = s.status === 'pass' ? '✓' : s.status === 'fail' ? '✗' : '—';
    const color = s.status === 'pass' ? 'var(--success)' : s.status === 'fail' ? 'var(--danger)' : 'var(--muted)';
    const timing = s.elapsed_s != null ? ` (${s.elapsed_s}s)` : '';
    let detail = '';
    if (s.status === 'fail') {
      detail = `<div style="color:var(--danger);font-size:12px;margin:4px 0 4px 24px;white-space:pre-wrap">${_esc(s.error)}</div>`;
      if (s.traceback) {
        detail += `<details style="margin:0 0 4px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Stack trace</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;margin:4px 0">${_esc(s.traceback)}</pre></details>`;
      }
    } else if (s.status === 'skip') {
      detail = `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">${_esc(s.reason)}</div>`;
    } else if (s.status === 'pass') {
      const extras = [];
      if (s.config) extras.push(`Org: ${s.config.org}, API: ${s.config.api_url}`);
      if (s.user) extras.push(`User: ${s.user}`);
      if (s.token_type) extras.push(`Token: ${s.token_type}`);
      if (s.scopes) extras.push(`Scopes: ${s.scopes}`);
      if (s.rate_limit) extras.push(`Rate limit remaining: ${s.rate_limit}`);
      if (s.org_name) extras.push(`Org: ${s.org_display || s.org_name}`);
      if (s.plan) extras.push(`Plan: ${s.plan}`);
      if (s.ghas_enabled != null) extras.push(`GHAS for new repos: ${s.ghas_enabled}`);
      if (s.alerts_in_page != null) extras.push(`Alerts in page: ${s.alerts_in_page}`);
      if (s.note) extras.push(s.note);
      if (s.total_fetched != null) extras.push(`Repos fetched: ${s.total_fetched}`);
      if (s.sample) extras.push(`Sample: ${JSON.stringify(s.sample).substring(0, 150)}`);
      if (s.family) extras.push(`Family: ${s.family}`);
      if (s.mapped) extras.push(`Mapped: ${s.mapped.canonical_id} → ${s.mapped.severity}`);
      if (extras.length) detail += `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">${extras.join(' · ')}</div>`;
      if (s.repos && s.repos.length) {
        detail += `<details style="margin:2px 0 2px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">${s.repos.length} repos</summary>`;
        detail += '<div style="font-size:11px;color:var(--muted)">';
        for (const r of s.repos.slice(0, 10)) {
          detail += `<div>${_esc(r.name)} — GHAS: ${r.advanced_security || '?'}, secrets: ${r.secret_scanning || '?'}, push protection: ${r.secret_scanning_push_protection || '?'}</div>`;
        }
        if (s.repos.length > 10) detail += `<div>… and ${s.repos.length - 10} more</div>`;
        detail += '</div></details>';
      }
      if (s.raw_alert) {
        detail += `<details style="margin:2px 0 2px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Raw alert</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:200px;overflow:auto">${_esc(JSON.stringify(s.raw_alert, null, 2))}</pre></details>`;
      }
    }
    return `<div style="padding:4px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="color:${color};font-weight:700;width:14px;text-align:center">${icon}</span>
        <span style="font-size:13px;font-weight:500">${_esc(s.step)}</span>
        <span style="font-size:12px;color:var(--muted)">${_esc(s.description)}${timing}</span>
      </div>
      ${detail}
    </div>`;
  }).join('');
  return summary + '<div style="border:1px solid var(--border);border-radius:6px;padding:8px 12px">' + rows + '</div>';
}

async function runGhDryRun() {
  const btn = $('ghDryRunBtn');
  const el = $('ghDryRunResult');
  btn.disabled = true;
  btn.textContent = 'Running…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Fetching sample alerts from GitHub (no database writes)…</div>';
  try {
    const res = await api('/api/github/dry-run', { method: 'POST' });
    el.innerHTML = _renderGhDryRun(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${_esc(e.message || e)}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Dry Run (preview sync)';
}

function _renderGhDryRun(res) {
  if (!res.ok) {
    return `<div style="color:var(--danger);font-size:13px;margin-bottom:8px">${_esc(res.error)}</div>`;
  }
  let html = `<div style="display:flex;gap:16px;margin-bottom:12px;font-size:13px">
    <span><strong>${res.total}</strong> fetched &amp; mapped</span>
  </div>`;

  if (res.by_family && Object.keys(res.by_family).length) {
    html += '<div style="display:flex;gap:8px;margin-bottom:8px">';
    for (const [fam, count] of Object.entries(res.by_family)) {
      html += `<span style="font-size:12px;padding:2px 8px;border-radius:4px;background:var(--panel);border:1px solid var(--border)">${_esc(fam)}: ${count}</span>`;
    }
    html += '</div>';
  }
  if (res.by_severity && Object.keys(res.by_severity).length) {
    html += '<div style="display:flex;gap:8px;margin-bottom:12px">';
    for (const [sev, count] of Object.entries(res.by_severity)) {
      const color = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)',info:'var(--muted)'}[sev] || 'var(--fg)';
      html += `<span style="font-size:12px;padding:2px 8px;border-radius:4px;background:color-mix(in srgb, ${color} 15%, transparent);color:${color}">${sev}: ${count}</span>`;
    }
    html += '</div>';
  }

  if (res.errors && res.errors.length) {
    html += '<details style="margin-bottom:8px"><summary style="font-size:12px;color:var(--danger);cursor:pointer">Errors (' + res.errors.length + ')</summary>';
    html += res.errors.map(e => `<div style="font-size:12px;padding:2px 0;color:var(--muted)">${_esc(e.family || '')}: ${_esc(e.error)}</div>`).join('');
    html += '</details>';
  }

  if (res.records && res.records.length) {
    html += '<div style="overflow-x:auto"><table style="width:100%;font-size:12px;border-collapse:collapse">';
    html += '<thead><tr style="text-align:left;border-bottom:2px solid var(--border)">';
    html += '<th style="padding:4px 8px">CVE / ID</th><th style="padding:4px 8px">Family</th><th style="padding:4px 8px">Severity</th><th style="padding:4px 8px">Asset</th><th style="padding:4px 8px">Component</th><th style="padding:4px 8px">Fix</th>';
    html += '</tr></thead><tbody>';
    for (const r of res.records) {
      const sevColor = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)',info:'var(--muted)'}[r.severity] || 'var(--fg)';
      html += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-family:monospace">${_esc(r.canonical_id || '')}</td>
        <td style="padding:4px 8px">${_esc(r.family || '')}</td>
        <td style="padding:4px 8px;color:${sevColor}">${_esc(r.severity)}</td>
        <td style="padding:4px 8px">${_esc(r.asset || '')}</td>
        <td style="padding:4px 8px">${_esc(r.component || '—')}</td>
        <td style="padding:4px 8px">${r.fix_available ? _esc(r.fix_version || 'yes') : '—'}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }
  return html;
}

async function loadGhOverview() {
  const btn = $('ghOverviewBtn');
  const el = $('ghOverviewResult');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Fetching security overview…</div>';
  try {
    const res = await api('/api/github/security-overview');
    el.innerHTML = _renderGhOverview(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${_esc(e.message || e)}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Load Overview';
}

function _renderGhOverview(res) {
  if (!res.ok) {
    return `<div style="color:var(--danger);font-size:13px">${_esc(res.error)}</div>`;
  }
  let html = `<div style="font-size:13px;margin-bottom:12px"><strong>Organization:</strong> ${_esc(res.org)}</div>`;

  if (res.families) {
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px">';
    const labels = { dependabot: 'Dependabot', code_scanning: 'Code Scanning', secret_scanning: 'Secret Scanning' };
    for (const [fam, states] of Object.entries(res.families)) {
      const openInfo = states.open || {};
      const fixedInfo = states.fixed || {};
      const openCount = openInfo.error ? openInfo.error : (openInfo.count || 0) + (openInfo.has_more ? '+' : '');
      const fixedCount = fixedInfo.error ? fixedInfo.error : (fixedInfo.count || 0) + (fixedInfo.has_more ? '+' : '');
      html += `<div style="border:1px solid var(--border);border-radius:6px;padding:12px">
        <div style="font-size:13px;font-weight:600;margin-bottom:6px">${_esc(labels[fam] || fam)}</div>
        <div style="font-size:12px">Open: <strong>${openCount}</strong></div>
        <div style="font-size:12px;color:var(--muted)">Fixed: ${fixedCount}</div>
      </div>`;
    }
    html += '</div>';
  }

  if (res.dependabot_by_severity) {
    html += '<div style="margin-bottom:16px"><div style="font-size:12px;font-weight:600;margin-bottom:6px">Dependabot by severity (open)</div>';
    html += '<div style="display:flex;gap:8px">';
    for (const [sev, count] of Object.entries(res.dependabot_by_severity)) {
      const color = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)'}[sev] || 'var(--fg)';
      html += `<span style="font-size:12px;padding:2px 8px;border-radius:4px;background:color-mix(in srgb, ${color} 15%, transparent);color:${color}">${sev}: ${count}</span>`;
    }
    html += '</div></div>';
  }

  if (res.top_repos && res.top_repos.length) {
    html += '<div style="font-size:12px;font-weight:600;margin-bottom:6px">Top repos by alert count</div>';
    html += '<div style="overflow-x:auto"><table style="width:100%;font-size:12px;border-collapse:collapse">';
    html += '<thead><tr style="text-align:left;border-bottom:2px solid var(--border)">';
    html += '<th style="padding:4px 8px">Repository</th><th style="padding:4px 8px">Dependabot</th><th style="padding:4px 8px">Code Scanning</th><th style="padding:4px 8px">Secret Scanning</th>';
    html += '</tr></thead><tbody>';
    for (const r of res.top_repos) {
      html += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-family:monospace">${_esc(r.repo)}</td>
        <td style="padding:4px 8px">${r.dependabot}</td>
        <td style="padding:4px 8px">${r.code_scanning}</td>
        <td style="padding:4px 8px">${r.secret_scanning}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }
  return html;
}

async function loadGhRepos() {
  const btn = $('ghReposBtn');
  const el = $('ghReposResult');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Fetching repos…</div>';
  try {
    const res = await api('/api/github/repos');
    el.innerHTML = _renderGhRepos(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${_esc(e.message || e)}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Load Repos';
}

function _renderGhRepos(res) {
  if (!res.repos || !res.repos.length) {
    return '<div class="hint">No repos found.</div>';
  }
  let html = `<div style="font-size:12px;margin-bottom:8px"><strong>${res.total}</strong> repos in <strong>${_esc(res.org)}</strong></div>`;
  html += '<div style="overflow-x:auto"><table style="width:100%;font-size:12px;border-collapse:collapse">';
  html += '<thead><tr style="text-align:left;border-bottom:2px solid var(--border)">';
  html += '<th style="padding:4px 8px">Repository</th><th style="padding:4px 8px">Language</th><th style="padding:4px 8px">GHAS</th><th style="padding:4px 8px">Secret Scan</th><th style="padding:4px 8px">Push Protect</th><th style="padding:4px 8px">Dependabot</th><th style="padding:4px 8px">Last Push</th>';
  html += '</tr></thead><tbody>';
  for (const r of res.repos) {
    const ghasColor = r.advanced_security === 'enabled' ? 'var(--success)' : 'var(--muted)';
    const secretColor = r.secret_scanning === 'enabled' ? 'var(--success)' : 'var(--muted)';
    const pushColor = r.push_protection === 'enabled' ? 'var(--success)' : 'var(--muted)';
    const depColor = r.dependabot_updates === 'enabled' ? 'var(--success)' : 'var(--muted)';
    html += `<tr style="border-bottom:1px solid var(--border)">
      <td style="padding:4px 8px;font-family:monospace">${r.html_url ? `<a href="${_esc(r.html_url)}" target="_blank" rel="noopener">${_esc(r.full_name)}</a>` : _esc(r.full_name)}${r.archived ? ' <span style="color:var(--muted)">(archived)</span>' : ''}</td>
      <td style="padding:4px 8px">${_esc(r.language || '—')}</td>
      <td style="padding:4px 8px;color:${ghasColor}">${_esc(r.advanced_security || '—')}</td>
      <td style="padding:4px 8px;color:${secretColor}">${_esc(r.secret_scanning || '—')}</td>
      <td style="padding:4px 8px;color:${pushColor}">${_esc(r.push_protection || '—')}</td>
      <td style="padding:4px 8px;color:${depColor}">${_esc(r.dependabot_updates || '—')}</td>
      <td style="padding:4px 8px;color:var(--muted)">${r.pushed_at ? fmtDate(r.pushed_at) : '—'}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  return html;
}

async function runGhQuery() {
  const path = $('ghQueryPath').value.trim();
  if (!path) { toast('Enter an API path', true); return; }
  let params = {};
  const paramsText = $('ghQueryParams').value.trim();
  if (paramsText) {
    try { params = JSON.parse(paramsText); }
    catch (e) { toast('Params must be valid JSON', true); return; }
  }
  $('ghQueryBtn').disabled = true;
  $('ghQueryBtn').textContent = 'Running…';
  $('ghQueryStatus').textContent = '';
  $('ghQueryResult').style.display = 'none';
  try {
    const t0 = Date.now();
    const res = await api('/api/github/query', { method: 'POST', body: JSON.stringify({ method: 'GET', path, params }) });
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    if (!res.ok) {
      $('ghQueryResult').textContent = JSON.stringify(res.data || res.error, null, 2);
      $('ghQueryResult').style.display = 'block';
      $('ghQueryStatus').textContent = `HTTP ${res.status_code} — ${elapsed}s`;
      $('ghExportJSON').disabled = true;
      $('ghCopyResult').disabled = true;
    } else {
      _ghLastResult = res.data;
      $('ghQueryResult').textContent = JSON.stringify(res.data, null, 2);
      $('ghQueryResult').style.display = 'block';
      $('ghQueryStatus').textContent = `HTTP ${res.status_code} — ${elapsed}s — Rate limit: ${res.headers?.['x-ratelimit-remaining'] || '?'}`;
      $('ghExportJSON').disabled = false;
      $('ghCopyResult').disabled = false;
    }
  } catch (e) {
    $('ghQueryResult').textContent = e.message || String(e);
    $('ghQueryResult').style.display = 'block';
    $('ghQueryStatus').textContent = 'Query failed';
    $('ghExportJSON').disabled = true;
    $('ghCopyResult').disabled = true;
  }
  $('ghQueryBtn').disabled = false;
  $('ghQueryBtn').textContent = 'Run Query';
}

function ghExportJSON() {
  if (!_ghLastResult) return;
  const blob = new Blob([JSON.stringify(_ghLastResult, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'github-query-result.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

function ghCopyResult() {
  const text = $('ghQueryResult').textContent;
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard'));
}

$('ghTestSuiteBtn').onclick = runGhTestSuite;
$('ghDryRunBtn').onclick = runGhDryRun;
$('ghOverviewBtn').onclick = loadGhOverview;
$('ghReposBtn').onclick = loadGhRepos;
$('ghQueryBtn').onclick = runGhQuery;
$('ghExportJSON').onclick = ghExportJSON;
$('ghCopyResult').onclick = ghCopyResult;

$('ghQueryPath').addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runGhQuery(); }
});


// ===== GitHub query templates ================================================

async function loadGhTemplates() {
  const el = $('ghTemplates');
  if (!el) return;
  try {
    const res = await api('/api/github/query-templates');
    el.innerHTML = (res.templates || []).map(t =>
      `<button class="btn-ghost" style="font-size:11px;padding:3px 10px" onclick='_loadGhTemplate(${JSON.stringify(t.name)})' title="${_esc(t.description)}">${_esc(t.label)}</button>`
    ).join('');
    window._ghTemplateData = res.templates;
  } catch (e) {
    el.innerHTML = `<span style="font-size:11px;color:var(--muted)">Could not load templates</span>`;
  }
}

function _loadGhTemplate(name) {
  const tpl = (window._ghTemplateData || []).find(t => t.name === name);
  if (!tpl) return;
  $('ghQueryPath').value = tpl.path || '';
  $('ghQueryParams').value = tpl.params ? JSON.stringify(tpl.params, null, 2) : '';
}

loadGhTemplates();


// ===== CrowdStrike Falcon diagnostics ========================================

let _falconLastResult = null;

async function runFalconTestSuite() {
  const btn = $('falconTestSuiteBtn');
  const el = $('falconTestSuiteResult');
  btn.disabled = true;
  btn.textContent = 'Running…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Running test suite — checking config, auth, scope, probes, severity breakdown, and sample mapping…</div>';
  try {
    const res = await api('/api/falcon/test-suite', { method: 'POST' });
    el.innerHTML = _renderFalconTestSuite(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${_esc(e.message || e)}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Run Test Suite';
}

function _renderFalconTestSuite(res) {
  const summary = `<div style="display:flex;gap:12px;margin-bottom:12px;font-size:13px;font-weight:600">
    <span style="color:var(--success)">${res.passed} passed</span>
    <span style="color:var(--danger)">${res.failed} failed</span>
    <span style="color:var(--muted)">${res.skipped} skipped</span>
  </div>`;
  const rows = res.steps.map(s => {
    const icon = s.status === 'pass' ? '✓' : s.status === 'fail' ? '✗' : '—';
    const color = s.status === 'pass' ? 'var(--success)' : s.status === 'fail' ? 'var(--danger)' : 'var(--muted)';
    const timing = s.elapsed_s != null ? ` (${s.elapsed_s}s)` : '';
    let detail = '';
    if (s.status === 'fail') {
      detail = `<div style="color:var(--danger);font-size:12px;margin:4px 0 4px 24px;white-space:pre-wrap">${_esc(s.error)}</div>`;
      if (s.traceback) {
        detail += `<details style="margin:0 0 4px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Stack trace</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;margin:4px 0">${_esc(s.traceback)}</pre></details>`;
      }
    } else if (s.status === 'skip') {
      detail = `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">${_esc(s.reason)}</div>`;
    } else if (s.status === 'pass') {
      const extras = [];
      if (s.config) {
        extras.push(`Base URL: ${s.config.base_url}`);
        extras.push(`CID prefix: ${s.config.client_id_prefix}`);
        if (s.config.member_cid) extras.push(`Member CID: ${s.config.member_cid}`);
        extras.push(`FQL: ${s.config.filter_fql}`);
      }
      if (s.token_preview) extras.push(`Token: ${s.token_preview}`);
      if (s.total_matches != null) extras.push(`Total matching: ${s.total_matches}`);
      if (s.trace_id) extras.push(`Trace: ${s.trace_id}`);
      if (s.total != null) extras.push(`Total: ${s.total}`);
      if (s.returned != null) extras.push(`Returned: ${s.returned}`);
      if (s.note) extras.push(s.note);
      if (s.fql) extras.push(`FQL: ${s.fql}`);
      if (s.matching_count != null) extras.push(`Matching: ${s.matching_count}`);
      if (s.by_severity) {
        const sevStr = Object.entries(s.by_severity).map(([k, v]) => `${k}: ${v}`).join(', ');
        extras.push(`Severities: ${sevStr}`);
      }
      if (s.total_open != null) extras.push(`Total open: ${s.total_open}`);
      if (s.mapped) extras.push(`Mapped: ${s.mapped.canonical_id} → ${s.mapped.severity}`);
      if (extras.length) detail += `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">${extras.join(' · ')}</div>`;
      if (s.sample && typeof s.sample === 'object') {
        const sampleStr = Object.entries(s.sample).filter(([,v]) => v != null).map(([k, v]) => `${k}: ${v}`).join(', ');
        detail += `<div style="color:var(--muted);font-size:12px;margin:2px 0 2px 24px">Sample: ${_esc(sampleStr)}</div>`;
      }
      if (s.raw_resource) {
        detail += `<details style="margin:2px 0 2px 24px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Raw resource</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:200px;overflow:auto">${_esc(JSON.stringify(s.raw_resource, null, 2))}</pre></details>`;
      }
    }
    return `<div style="padding:4px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="color:${color};font-weight:700;width:14px;text-align:center">${icon}</span>
        <span style="font-size:13px;font-weight:500">${_esc(s.step)}</span>
        <span style="font-size:12px;color:var(--muted)">${_esc(s.description)}${timing}</span>
      </div>
      ${detail}
    </div>`;
  }).join('');
  return summary + '<div style="border:1px solid var(--border);border-radius:6px;padding:8px 12px">' + rows + '</div>';
}

async function runFalconDryRun() {
  const btn = $('falconDryRunBtn');
  const el = $('falconDryRunResult');
  btn.disabled = true;
  btn.textContent = 'Running…';
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--muted)">Fetching sample vulnerabilities from Falcon Spotlight (no database writes)…</div>';
  try {
    const res = await api('/api/falcon/dry-run', { method: 'POST' });
    el.innerHTML = _renderFalconDryRun(res);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--danger);padding:8px">${_esc(e.message || e)}</div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Dry Run (preview sync)';
}

function _renderFalconDryRun(res) {
  if (!res.ok) {
    let html = `<div style="color:var(--danger);font-size:13px;margin-bottom:8px">${_esc(res.error)}</div>`;
    if (res.traceback) {
      html += `<details><summary style="font-size:11px;color:var(--muted);cursor:pointer">Stack trace</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap">${_esc(res.traceback)}</pre></details>`;
    }
    return html;
  }
  let html = `<div style="display:flex;gap:16px;margin-bottom:12px;font-size:13px">
    <span><strong>${res.mapped}</strong> mapped of <strong>${res.fetched}</strong> fetched</span>
    <span style="color:var(--muted)">Total in Falcon: ${res.total_in_falcon != null ? res.total_in_falcon : '?'}</span>
  </div>`;

  if (res.by_severity && Object.keys(res.by_severity).length) {
    html += '<div style="display:flex;gap:8px;margin-bottom:12px">';
    for (const [sev, count] of Object.entries(res.by_severity)) {
      const color = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)',info:'var(--muted)'}[sev] || 'var(--fg)';
      html += `<span style="font-size:12px;padding:2px 8px;border-radius:4px;background:color-mix(in srgb, ${color} 15%, transparent);color:${color}">${sev}: ${count}</span>`;
    }
    html += '</div>';
  }

  if (res.errors && res.errors.length) {
    html += '<details style="margin-bottom:8px"><summary style="font-size:12px;color:var(--danger);cursor:pointer">Mapping errors (' + res.errors.length + ')</summary>';
    html += res.errors.map(e => `<div style="font-size:12px;padding:2px 0;color:var(--muted)">Resource ${_esc(e.resource_id || '?')}: ${_esc(e.error)}</div>`).join('');
    html += '</details>';
  }

  if (res.records && res.records.length) {
    html += '<div style="overflow-x:auto"><table style="width:100%;font-size:12px;border-collapse:collapse">';
    html += '<thead><tr style="text-align:left;border-bottom:2px solid var(--border)">';
    html += '<th style="padding:4px 8px">CVE / ID</th><th style="padding:4px 8px">Severity</th><th style="padding:4px 8px">Hostname</th><th style="padding:4px 8px">OS</th><th style="padding:4px 8px">Component</th><th style="padding:4px 8px">Fix</th>';
    html += '</tr></thead><tbody>';
    for (const r of res.records) {
      const sevColor = {critical:'var(--danger)',high:'#e65100',medium:'var(--warning,#e6a700)',low:'var(--success)',info:'var(--muted)'}[r.severity] || 'var(--fg)';
      html += `<tr style="border-bottom:1px solid var(--border)">
        <td style="padding:4px 8px;font-family:monospace">${_esc(r.vuln?.canonical_id || '')}</td>
        <td style="padding:4px 8px;color:${sevColor}">${_esc(r.severity)}</td>
        <td style="padding:4px 8px">${_esc(r.asset?.name || '')}</td>
        <td style="padding:4px 8px;color:var(--muted)">${_esc(r.asset?.os || '')}</td>
        <td style="padding:4px 8px">${_esc(r.component || '—')}</td>
        <td style="padding:4px 8px">${r.fix_available ? _esc(r.fix_version || 'yes') : '—'}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }

  if (res.raw_sample) {
    html += `<details style="margin-top:8px"><summary style="font-size:11px;color:var(--muted);cursor:pointer">Raw API response (first record)</summary><pre style="font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:300px;overflow:auto">${_esc(JSON.stringify(res.raw_sample, null, 2))}</pre></details>`;
  }
  return html;
}

async function loadFalconTemplates() {
  const el = $('falconTemplates');
  if (!el) return;
  try {
    const res = await api('/api/falcon/query-templates');
    el.innerHTML = (res.templates || []).map(t =>
      `<button class="btn-ghost" style="font-size:11px;padding:3px 10px" onclick='_loadFalconTemplate(${JSON.stringify(t.name)})' title="${_esc(t.description)}">${_esc(t.label)}</button>`
    ).join('');
    window._falconTemplateData = res.templates;
  } catch (e) {
    el.innerHTML = `<span style="font-size:11px;color:var(--muted)">Could not load templates</span>`;
  }
}

function _loadFalconTemplate(name) {
  const tpl = (window._falconTemplateData || []).find(t => t.name === name);
  if (!tpl) return;
  $('falconQueryFilter').value = tpl.filter || '';
  $('falconQueryLimit').value = tpl.limit || 5;
}

async function runFalconQuery() {
  const filter = $('falconQueryFilter').value.trim();
  if (!filter) { toast('Enter an FQL filter', true); return; }
  const limit = parseInt($('falconQueryLimit').value) || 5;
  $('falconQueryBtn').disabled = true;
  $('falconQueryBtn').textContent = 'Running…';
  $('falconQueryStatus').textContent = '';
  $('falconQueryResult').style.display = 'none';
  try {
    const t0 = Date.now();
    const res = await api('/api/falcon/query', { method: 'POST', body: JSON.stringify({ filter, limit }) });
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    if (!res.ok) {
      $('falconQueryResult').textContent = JSON.stringify(res.error || res, null, 2);
      $('falconQueryResult').style.display = 'block';
      $('falconQueryStatus').textContent = `Error — ${elapsed}s`;
      $('falconExportJSON').disabled = true;
      $('falconCopyResult').disabled = true;
    } else {
      _falconLastResult = res;
      const meta = res.meta || {};
      const total = (meta.pagination || {}).total;
      $('falconQueryResult').textContent = JSON.stringify(res.resources || res, null, 2);
      $('falconQueryResult').style.display = 'block';
      $('falconQueryStatus').textContent = `${(res.resources || []).length} returned${total != null ? ` of ${total} total` : ''} — ${elapsed}s`;
      $('falconExportJSON').disabled = false;
      $('falconCopyResult').disabled = false;
    }
  } catch (e) {
    $('falconQueryResult').textContent = e.message || String(e);
    $('falconQueryResult').style.display = 'block';
    $('falconQueryStatus').textContent = 'Query failed';
    $('falconExportJSON').disabled = true;
    $('falconCopyResult').disabled = true;
  }
  $('falconQueryBtn').disabled = false;
  $('falconQueryBtn').textContent = 'Run Query';
}

function falconExportJSON() {
  if (!_falconLastResult) return;
  const blob = new Blob([JSON.stringify(_falconLastResult, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'falcon-query-result.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

function falconCopyResult() {
  const text = $('falconQueryResult').textContent;
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard'));
}

$('falconTestSuiteBtn').onclick = runFalconTestSuite;
$('falconDryRunBtn').onclick = runFalconDryRun;
$('falconQueryBtn').onclick = runFalconQuery;
$('falconExportJSON').onclick = falconExportJSON;
$('falconCopyResult').onclick = falconCopyResult;

$('falconQueryFilter').addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runFalconQuery(); }
});

loadFalconTemplates();


boot().catch((e) => {
  document.body.innerHTML = `<div class="empty" style="padding-top:120px">
    <b>RiskDesk could not start.</b>${esc(e.message)}</div>`;
});
