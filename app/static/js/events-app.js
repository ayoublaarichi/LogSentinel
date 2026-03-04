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
};

/* ═══════════════════════════════════════════════════════════════════════════
   Component instances
   ═══════════════════════════════════════════════════════════════════════════ */
let filterBar, eventTable, eventDetails, rawViewer, timeline;

/* ═══════════════════════════════════════════════════════════════════════════
   Boot
   ═══════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
    initComponents();
    bindActions();
    await loadData();
    timeline.load(24);

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
}

/* ═══════════════════════════════════════════════════════════════════════════
   Data loading
   ═══════════════════════════════════════════════════════════════════════════ */
async function loadData() {
    setLoading(true);
    try {
        const [events, ips, types, users] = await Promise.all([
            apiFetch('/api/events/bulk?limit=5000'),
            apiFetch('/api/events/ips'),
            apiFetch('/api/events/types'),
            apiFetch('/api/events/users'),
        ]);

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
            timeline.load(24);
            toast(`Timeline filtered for ${ev.source_ip}`, 'info');
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

async function seedDemoEvents() {
    const btn = document.getElementById('ls-seed-demo');
    let originalLabel = '';
    if (btn) {
        originalLabel = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Seeding...';
    }
    try {
        const r = await fetch('/api/events/seed?count=50', {
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
        await loadData();
        timeline.load(24);
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
window.lsApp = { filterBar: () => filterBar, reload: loadData };
