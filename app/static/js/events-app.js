/**
 * events-app.js — Main state manager for the Events Investigation page.
 *
 * Architecture:
 *   App (singleton)
 *   ├── FilterBar   — structured query chips, emits filtered chips
 *   ├── EventTable  — virtual-scroll table, emits row:select
 *   ├── EventDetails— tree panel, handles actions
 *   ├── RawLogViewer— raw log syntax highlighter
 *   └── TimelineChart — Chart.js timeline
 *
 * State:
 *   allEvents[]     — full dataset loaded from API (up to 10 000)
 *   filteredEvents[]— after applying chips
 *   selectedEvent   — currently selected event object
 */

import FilterBar     from './components/FilterBar.js';
import EventTable    from './components/EventTable.js';
import EventDetails  from './components/EventDetails.js';
import RawLogViewer  from './components/RawLogViewer.js';
import TimelineChart from './components/TimelineChart.js';

/* ═══════════════════════════════════════════════════════════════════════════
   State
   ═══════════════════════════════════════════════════════════════════════════ */
const state = {
    allEvents:      [],
    filteredEvents: [],
    selectedEvent:  null,
    chips:          [],
    loading:        false,
    threatIntel:    new Map(),
    projects:       [],
    activeProjectId: localStorage.getItem('ls_active_project_id') || '',
    bulkLimit: 1500,
    pollIntervalMs: 12000,
    realtimePollInFlight: false,
};

/* ═══════════════════════════════════════════════════════════════════════════
   Component instances
   ═══════════════════════════════════════════════════════════════════════════ */
let filterBar, eventTable, eventDetails, rawViewer, timeline;
let ws = null;
let wsRetryTimer = null;
let pollTimer = null;

/* ═══════════════════════════════════════════════════════════════════════════
   Boot
   ═══════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
    initComponents();
    bindActions();
    initializeActiveProjectFromUrl();
    await loadProjects();
    await loadData();
    timeline.load(24, projectQuery());
    initRealtime();

    // ── Pre-apply filters from the URL query string ─────────────────────
    // Supports:  /events?ip=185.220.101.23&type=ssh_failed&user=root
    // Used by the "Investigate IP" button on the Alerts page.
    const urlParams = new URLSearchParams(window.location.search);
    const paramMap  = { ip: 'ip', type: 'type', user: 'user',
                        source: 'source', severity: 'severity' };
    let didAddChip  = false;
    for (const [param, field] of Object.entries(paramMap)) {
        const val = urlParams.get(param);
        if (val) { filterBar.addChip(field, val); didAddChip = true; }
    }
    if (didAddChip) {
        toast(`Filters applied from URL`, 'info');
    }
});

function initComponents() {
    /* FilterBar */
    filterBar = new FilterBar('#ls-filterbar', {
        onFilter: chips => {
            state.chips = chips;
            applyFilters();
        },
    });

    /* EventTable */
    eventTable = new EventTable('#ls-table-pane', {
        onSelect: ev => onRowSelect(ev),
        onCtxMenu: (ev, x, y) => onTableCtxMenu(ev, x, y),
    });

    /* EventDetails */
    eventDetails = new EventDetails('#ls-event-details', {
        onAction: (key, ev, extra) => onDetailAction(key, ev, extra),
    });

    /* RawLogViewer */
    rawViewer = new RawLogViewer('#ls-raw-pane');

    /* TimelineChart */
    timeline = new TimelineChart('timelineCanvas');
}

function bindActions() {
    const seedBtn = document.getElementById('ls-seed-demo');
    if (seedBtn) {
        seedBtn.addEventListener('click', seedDemoEvents);
    }

    const projectSelect = document.getElementById('ls-project-select');
    if (projectSelect) {
        projectSelect.addEventListener('change', async (event) => {
            state.activeProjectId = event.target.value || '';
            if (state.activeProjectId) localStorage.setItem('ls_active_project_id', state.activeProjectId);
            else localStorage.removeItem('ls_active_project_id');
            syncProjectInUrl(state.activeProjectId);
            await loadData();
            timeline.load(24, projectQuery());
            renderProjectSelect();
        });
    }

    document.getElementById('ls-project-new')?.addEventListener('click', createProject);
    document.getElementById('ls-project-delete')?.addEventListener('click', deleteSelectedProject);
}

async function loadProjects() {
    const projects = await apiFetch('/api/projects/');
    state.projects = Array.isArray(projects) ? projects : [];
    if (state.activeProjectId && !state.projects.some(p => String(p.id) === String(state.activeProjectId))) {
        state.activeProjectId = '';
        localStorage.removeItem('ls_active_project_id');
        syncProjectInUrl('');
    }
    renderProjectSelect();
}

function renderProjectSelect() {
    const select = document.getElementById('ls-project-select');
    if (!select) return;
    const options = ['<option value="">All visible</option>'];
    for (const project of state.projects) {
        const selected = String(project.id) === String(state.activeProjectId) ? ' selected' : '';
        options.push(`<option value="${esc(project.id)}"${selected}>${esc(project.name)}</option>`);
    }
    select.innerHTML = options.join('');

    const active = state.projects.find(p => String(p.id) === String(state.activeProjectId));
    const deleteBtn = document.getElementById('ls-project-delete');
    if (deleteBtn) deleteBtn.disabled = !active || !!active.is_default;
}

async function createProject() {
    const name = window.prompt('New project name:');
    if (!name || !name.trim()) return;
    try {
        const resp = await fetch('/api/projects/', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name.trim() }),
        });
        if (resp.status === 401) {
            const next = encodeURIComponent(window.location.pathname + window.location.search);
            window.location.href = `/login?next=${next}`;
            return;
        }
        if (!resp.ok) throw new Error(await safeErrorMessage(resp, 'Failed to create project'));

        const project = await resp.json();
        state.activeProjectId = String(project.id);
        localStorage.setItem('ls_active_project_id', state.activeProjectId);
        syncProjectInUrl(state.activeProjectId);
        await loadProjects();
        await loadData();
        timeline.load(24, projectQuery());
        toast(`Project created: ${project.name}`, 'success');
    } catch (err) {
        toast(err.message || 'Failed to create project', 'error');
    }
}

async function deleteSelectedProject() {
    const active = state.projects.find(p => String(p.id) === String(state.activeProjectId));
    if (!active) {
        toast('Select a project first', 'info');
        return;
    }
    if (active.is_default) {
        toast('Default project cannot be deleted', 'info');
        return;
    }
    if (!window.confirm(`Delete project "${active.name}"? Data will be reassigned to Default.`)) return;

    try {
        const resp = await fetch(`/api/projects/${active.id}`, {
            method: 'DELETE',
            credentials: 'same-origin',
        });
        if (resp.status === 401) {
            const next = encodeURIComponent(window.location.pathname + window.location.search);
            window.location.href = `/login?next=${next}`;
            return;
        }
        if (!resp.ok) throw new Error(await safeErrorMessage(resp, 'Failed to delete project'));

        state.activeProjectId = '';
        localStorage.removeItem('ls_active_project_id');
        syncProjectInUrl('');
        await loadProjects();
        await loadData();
        timeline.load(24, projectQuery());
        toast(`Project deleted: ${active.name}`, 'success');
    } catch (err) {
        toast(err.message || 'Failed to delete project', 'error');
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   Data loading
   ═══════════════════════════════════════════════════════════════════════════ */
async function loadData() {
    setLoading(true);
    try {
        const query = projectQuery();
        const results = await Promise.allSettled([
            apiFetch(`/api/events/bulk?limit=${state.bulkLimit}${query ? `&${query}` : ''}`),
            apiFetch(`/api/events/ips${query ? `?${query}` : ''}`),
            apiFetch(`/api/events/types${query ? `?${query}` : ''}`),
            apiFetch(`/api/events/users${query ? `?${query}` : ''}`),
        ]);

        const [eventsRes, ipsRes, typesRes, usersRes] = results;
        if (eventsRes.status !== 'fulfilled') {
            throw eventsRes.reason;
        }

        const events = Array.isArray(eventsRes.value) ? eventsRes.value : [];
        const ips = ipsRes.status === 'fulfilled' && Array.isArray(ipsRes.value) ? ipsRes.value : [];
        const types = typesRes.status === 'fulfilled' && Array.isArray(typesRes.value) ? typesRes.value : [];
        const users = usersRes.status === 'fulfilled' && Array.isArray(usersRes.value) ? usersRes.value : [];

        const failedHints = [
            ipsRes.status !== 'fulfilled' ? 'ips' : null,
            typesRes.status !== 'fulfilled' ? 'types' : null,
            usersRes.status !== 'fulfilled' ? 'users' : null,
        ].filter(Boolean);
        if (failedHints.length) {
            toast(`Loaded events with partial metadata (${failedHints.join(', ')})`, 'info');
        }

        // Enrich events with computed severity + matched rule
        state.allEvents = events.map(enrichEvent);

        const seedBtn = document.getElementById('ls-seed-demo');
        if (seedBtn) {
            seedBtn.style.display = events.length > 0 ? 'none' : '';
        }

        // Provide autocomplete hints to filter bar
        filterBar.setHints({ ips, types, users });

        applyFilters();
        toast(`Loaded ${events.length.toLocaleString()} events`, 'info');
    } catch (err) {
        toast(`Failed to load events: ${err.message}`, 'error');
        console.error('[events-app]', err);
    } finally {
        setLoading(false);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   Filtering
   ═══════════════════════════════════════════════════════════════════════════ */
function applyFilters() {
    const chips = state.chips;
    if (!chips.length) {
        state.filteredEvents = [...state.allEvents];
    } else {
        state.filteredEvents = state.allEvents.filter(ev => matchChips(ev, chips));
    }
    eventTable.setData(state.filteredEvents);

    // If selected event is still in filtered set, keep selection
    if (state.selectedEvent) {
        const idx = state.filteredEvents.findIndex(e => e.id === state.selectedEvent.id);
        if (idx >= 0) eventTable.selectIndex(idx);
        else {
            eventDetails.clear();
            rawViewer.clear();
            state.selectedEvent = null;
        }
    }
}

function matchChips(ev, chips) {
    return chips.every(chip => {
        const v = chip.value.toLowerCase();
        switch (chip.field) {
            case 'ip':       return (ev.source_ip   || '').toLowerCase().includes(v);
            case 'type':     return (ev.event_type  || '').toLowerCase().includes(v);
            case 'user':     return (ev.username    || '').toLowerCase().includes(v);
            case 'source':   return (ev.log_source  || '').toLowerCase() === v;
            case 'severity': return (ev._severity   || '').toLowerCase() === v;
            case 'rule':     return (ev._rule       || '').toLowerCase().includes(v);
            case 'text':     return JSON.stringify(ev).toLowerCase().includes(v);
            default:         return true;
        }
    });
}

/* ═══════════════════════════════════════════════════════════════════════════
   Event enrichment — adds _severity and _rule from known patterns
   Maps must include the exact event_type values produced by the parsers.
   ═══════════════════════════════════════════════════════════════════════════ */
const SEVERITY_MAP = {
    // auth.log parser values
    ssh_failed_login    : 'high',
    ssh_invalid_user    : 'medium',
    ssh_accepted_login  : 'info',
    ssh_connection_closed:'info',
    ssh_other           : 'info',
    // legacy / alias keys kept for backward compatibility
    ssh_failed          : 'high',
    ssh_brute_force     : 'critical',
    invalid_user        : 'medium',
    // nginx parser values
    http_server_error   : 'high',
    http_client_error   : 'low',
    http_forbidden      : 'medium',
    http_ok             : 'info',
    http_redirect       : 'info',
    // closed/accepted aliases
    ssh_closed          : 'info',
    ssh_accepted        : 'info',
};

const RULE_MAP = {
    ssh_failed_login    : 'SSH Brute Force (candidate)',
    ssh_invalid_user    : 'Invalid User Login',
    ssh_failed          : 'SSH Brute Force (candidate)',
    ssh_brute_force     : 'SSH Brute Force',
    invalid_user        : 'Invalid User Login',
    http_server_error   : 'Nginx Server Error',
    http_client_error   : 'Nginx Client Error',
    http_forbidden      : 'Nginx Forbidden',
};

function enrichEvent(ev) {
    const et = (ev.event_type || '').toLowerCase();
    const sev = SEVERITY_MAP[et] || 'none';
    const rule = RULE_MAP[et] || null;
    return {
        ...ev,
        _severity: sev,
        _rule: rule,
        _reason: rule ? `Event type "${ev.event_type}" matched rule "${rule}"` : null,
    };
}

/* ═══════════════════════════════════════════════════════════════════════════
   Row selection
   ═══════════════════════════════════════════════════════════════════════════ */
function onRowSelect(ev) {
    state.selectedEvent = ev;
    eventDetails.show(ev);
    rawViewer.show(ev);
    enrichThreatIntel(ev);
}

async function enrichThreatIntel(ev) {
    if (!ev || !ev.source_ip) return;
    const ip = ev.source_ip;
    const cached = state.threatIntel.get(ip);
    if (cached) {
        ev._threat = cached;
        eventDetails.show(ev);
        return;
    }
    try {
        const intel = await apiFetch(`/api/threat-intel/${encodeURIComponent(ip)}`);
        state.threatIntel.set(ip, intel);
        ev._threat = intel;
        if (state.selectedEvent && state.selectedEvent.id === ev.id) {
            eventDetails.show(ev);
        }
    } catch (err) {
        console.warn('[events-app] threat intel fetch failed', err);
    }
}

function initRealtime() {
    if (isVercelRuntime()) {
        startPollingRealtime('vercel');
        return;
    }

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${proto}://${window.location.host}/ws/events`;
    ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
        try {
            const incoming = JSON.parse(event.data);
            if (!Array.isArray(incoming) || !incoming.length) return;
            const enriched = incoming.map(enrichEvent).filter(matchesActiveProject);
            const existingIds = new Set(state.allEvents.map(e => e.id));
            const fresh = enriched.filter(e => !existingIds.has(e.id));
            if (!fresh.length) return;
            state.allEvents = [...fresh, ...state.allEvents];
            applyFilters();
            toast(`Live update: ${fresh.length} new event${fresh.length > 1 ? 's' : ''}`, 'info');
            timeline.load(24, projectQuery());
        } catch (err) {
            console.warn('[events-app] websocket parse failed', err);
        }
    };

    ws.onclose = () => {
        if (wsRetryTimer) clearTimeout(wsRetryTimer);
        wsRetryTimer = setTimeout(() => {
            startPollingRealtime('fallback');
        }, 3000);
    };

    ws.onerror = () => {
        ws?.close();
    };
}

function startPollingRealtime(mode = 'fallback') {
    if (pollTimer) return;
    if (mode === 'vercel') {
        toast('Realtime disabled on Vercel; using polling', 'info');
    } else {
        toast('Realtime websocket unavailable; switched to polling', 'info');
    }
    pollTimer = setInterval(() => {
        void pollRealtimeUpdates();
    }, state.pollIntervalMs);
}

async function pollRealtimeUpdates() {
    if (state.loading || state.realtimePollInFlight) return;
    state.realtimePollInFlight = true;
    try {
        const query = projectQuery();
        const latest = await apiFetch(`/api/events/bulk?limit=250${query ? `&${query}` : ''}`);
        if (!Array.isArray(latest) || !latest.length) {
            timeline.load(24, projectQuery());
            return;
        }

        const existingIds = new Set(state.allEvents.map(e => e.id));
        const fresh = latest
            .map(enrichEvent)
            .filter(matchesActiveProject)
            .filter(ev => !existingIds.has(ev.id));

        if (fresh.length) {
            state.allEvents = [...fresh, ...state.allEvents].slice(0, state.bulkLimit);
            applyFilters();
            toast(`Live update: ${fresh.length} new event${fresh.length > 1 ? 's' : ''}`, 'info');
        }
        timeline.load(24, projectQuery());
    } catch (err) {
        console.warn('[events-app] polling update failed', err);
    } finally {
        state.realtimePollInFlight = false;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   Table context menu
   ═══════════════════════════════════════════════════════════════════════════ */
function onTableCtxMenu(ev, x, y) {
    document.querySelector('.ls-ctx-menu')?.remove();
    const menu = document.createElement('div');
    menu.className = 'ls-ctx-menu';
    menu.style.left = `${x}px`;
    menu.style.top  = `${y}px`;
    menu.innerHTML = `
        <div class="ls-ctx-item" data-action="filter_ip">
            <i class="bi bi-funnel"></i> Filter by IP: ${esc(ev.source_ip)}
        </div>
        <div class="ls-ctx-item" data-action="filter_type">
            <i class="bi bi-tag"></i> Filter by Type: ${esc(ev.event_type)}
        </div>
        ${ev.username ? `<div class="ls-ctx-item" data-action="filter_user">
            <i class="bi bi-person"></i> Filter by User: ${esc(ev.username)}
        </div>` : ''}
        <div class="ls-ctx-divider"></div>
        <div class="ls-ctx-item" data-action="pivot_ip">
            <i class="bi bi-diagram-3"></i> Show all events for this IP
        </div>
        <div class="ls-ctx-item" data-action="investigate_ip">
            <i class="bi bi-search"></i> Investigate IP timeline
        </div>
        <div class="ls-ctx-item" data-action="copy_raw">
            <i class="bi bi-clipboard"></i> Copy raw line
        </div>
    `;
    document.body.appendChild(menu);
    menu.querySelectorAll('.ls-ctx-item').forEach(item => {
        item.addEventListener('click', () => {
            onDetailAction(item.dataset.action, ev);
            menu.remove();
        });
    });
    const dismiss = e => {
        if (!menu.contains(e.target)) {
            menu.remove();
            document.removeEventListener('mousedown', dismiss);
        }
    };
    setTimeout(() => document.addEventListener('mousedown', dismiss), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Detail/action handler
   ═══════════════════════════════════════════════════════════════════════════ */
function onDetailAction(key, ev, extra = {}) {
    switch (key) {
        case 'filter_ip':
        case 'filter':
            if (ev.source_ip) filterBar.addChip('ip', ev.source_ip);
            else if (extra.key === 'source_ip' && extra.value) filterBar.addChip('ip', extra.value);
            break;
        case 'filter_type':
            if (ev.event_type) filterBar.addChip('type', ev.event_type);
            break;
        case 'filter_user':
            if (ev.username) filterBar.addChip('user', ev.username);
            break;
        case 'pivot_ip':
            filterBar.clearAll();
            if (ev.source_ip) filterBar.addChip('ip', ev.source_ip);
            toast(`Pivoting to IP ${ev.source_ip}`, 'info');
            break;
        case 'timeline_ip':
        case 'investigate_ip':
            if (ev.source_ip) {
                const query = projectQuery();
                const suffix = query ? `?${query}` : '';
                window.location.assign(`/investigate/ip/${encodeURIComponent(ev.source_ip)}${suffix}`);
            }
            break;
        case 'copy_raw':
            navigator.clipboard.writeText(ev.raw_line || '').then(() => toast('Raw line copied!', 'success'));
            break;
        case 'copy':
            navigator.clipboard.writeText(String(extra.value ?? '')).then(() => toast('Copied!', 'success'));
            break;
        case 'false_pos':
            toast(`Marked as false positive: #${ev.id}`, 'info');
            break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════════════════════ */
async function apiFetch(url) {
    const r = await fetch(url, { credentials: 'same-origin' });
    if (r.status === 401) {
        // Session expired — redirect to login, preserving current page
        console.warn(`[apiFetch] 401 on ${url} — redirecting to /login`);
        toast('Session expired — please log in again.', 'error');
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = `/login?next=${next}`;
        throw new Error(`Unauthorized: ${url}`);
    }
    if (!r.ok) {
        console.error(`[apiFetch] ${r.status} ${r.statusText} on ${url}`);
        throw new Error(`Request failed for ${url}: ${r.status} ${r.statusText}`);
    }
    try {
        return await r.json();
    } catch (err) {
        console.error(`[apiFetch] Invalid JSON from ${url}`, err);
        throw new Error(`Invalid JSON response from ${url}`);
    }
}

function projectQuery() {
    if (!state.activeProjectId) return '';
    return `project_id=${encodeURIComponent(state.activeProjectId)}`;
}

function initializeActiveProjectFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const urlProjectId = params.get('project_id');
    if (urlProjectId) {
        state.activeProjectId = urlProjectId;
        localStorage.setItem('ls_active_project_id', urlProjectId);
    }
}

function syncProjectInUrl(projectId) {
    const url = new URL(window.location.href);
    if (projectId) url.searchParams.set('project_id', projectId);
    else url.searchParams.delete('project_id');
    window.history.replaceState({}, '', `${url.pathname}${url.search}`);
}

function isVercelRuntime() {
    const page = document.getElementById('ls-events-page');
    if (page?.dataset?.onVercel === '1') return true;
    return window.location.host.endsWith('vercel.app');
}

function matchesActiveProject(ev) {
    if (!state.activeProjectId) return true;
    return String(ev.project_id ?? '') === String(state.activeProjectId);
}

async function loadMoreEvents() {
    state.bulkLimit = Math.min(10000, state.bulkLimit + 1000);
    await loadData();
    timeline.load(24, projectQuery());
    toast(`Load limit increased to ${state.bulkLimit.toLocaleString()} events`, 'info');
}

async function safeErrorMessage(resp, fallback) {
    try {
        const body = await resp.json();
        return body?.detail || fallback;
    } catch {
        return fallback;
    }
}

async function seedDemoEvents() {
    const btn = document.getElementById('ls-seed-demo');
    let originalLabel = '';
    if (btn) {
        originalLabel = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Seeding...';
    }
    try {
        const query = projectQuery();
        const seedUrl = `/api/events/seed?count=50${query ? `&${query}` : ''}`;
        const r = await fetch(seedUrl, {
            method: 'POST',
            credentials: 'same-origin',
        });
        if (r.status === 401) {
            const next = encodeURIComponent(window.location.pathname + window.location.search);
            window.location.href = `/login?next=${next}`;
            throw new Error('Unauthorized');
        }
        if (!r.ok) {
            throw new Error(`Seed failed: ${r.status} ${r.statusText}`);
        }
        const data = await r.json();
        toast(`Seeded ${data.seeded ?? 0} demo events`, 'success');
        await loadProjects();
        await loadData();
        timeline.load(24, projectQuery());
    } catch (err) {
        toast(`Failed to seed demo events: ${err.message}`, 'error');
        console.error('[events-app] seed failed', err);
    } finally {
        if (btn) {
            btn.innerHTML = originalLabel || '<i class="bi bi-stars"></i> Seed Demo Events';
            btn.disabled = false;
        }
    }
}

function setLoading(show) {
    state.loading = show;
    eventTable?.setLoading(show);
}

function toast(msg, type = 'info') {
    const area = document.getElementById('ls-toast-area');
    if (!area) return;
    const el = document.createElement('div');
    el.className = `ls-toast ${type}`;
    el.innerHTML = `<i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'x-circle' : 'info-circle'} me-2"></i>${msg}`;
    area.appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* Export for potential toolbar button access from inline HTML handlers */
window.lsApp = { filterBar: () => filterBar, reload: loadData, loadMore: loadMoreEvents };
