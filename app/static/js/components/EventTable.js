/**
 * EventTable — high-performance virtual-scroll events table.
 *
 * Supports: virtual scrolling (10 000+ rows), column sorting, keyboard nav,
 * selectable rows, row colouring, column resize, sticky header.
 *
 * Usage:
 *   const table = new EventTable('#ls-table-pane', { onSelect: ev => ... });
 *   table.setData(events);           // replace entire dataset
 *   table.setFiltered(filtered);     // after client-side filtering
 */
export default class EventTable {
    /* ── Column definitions ─────────────────────────────────────────────── */
    static COLUMNS = [
        { id: 'num',       label: '#',         width: 42,  noSort: true  },
        { id: 'timestamp', label: 'Timestamp', width: 152, sortKey: 'timestamp' },
        { id: 'source_ip', label: 'Source IP', width: 130, sortKey: 'source_ip' },
        { id: 'event_type',label: 'Event Type',width: 140, sortKey: 'event_type' },
        { id: 'username',  label: 'User',      width: 100, sortKey: 'username' },
        { id: 'log_source',label: 'Source',    width: 70,  sortKey: 'log_source' },
        { id: '_severity', label: 'Severity',  width: 82,  sortKey: '_severity' },
    ];

    static ROW_H = 34;       // px per row
    static BUFFER = 15;      // extra rows above/below viewport

    /* ── Wireshark-style color rules ─────────────────────────────────────── */
    static COLOR_RULES = [
        { test: e => e._severity === 'critical',                    cls: 'row-critical' },
        { test: e => e._severity === 'high',                        cls: 'row-high' },
        { test: e => e._severity === 'medium',                      cls: 'row-medium' },
        { test: e => e._severity === 'low',                         cls: 'row-low' },
        { test: e => e.event_type?.includes('accepted'),            cls: 'row-accepted' },
        { test: e => e.username === 'root' || e.username === 'admin', cls: 'row-root' },
        { test: e => EventTable.isPublicIP(e.source_ip),            cls: 'row-public-ip' },
    ];

    #data = [];          // filtered+sorted events
    #sortCol = 'timestamp';
    #sortDir = 'desc';
    #selIdx = -1;
    #onSelect = null;
    #onCtxMenu = null;
    #colWidths = [];     // mutable widths
    #scrollEl = null;
    #innerEl = null;
    #pane = null;
    #renderedStart = 0;
    #renderedEnd = 0;

    constructor(paneSel, { onSelect, onCtxMenu } = {}) {
        this.#onSelect = onSelect || (() => {});
        this.#onCtxMenu = onCtxMenu || (() => {});
        this.#colWidths = EventTable.COLUMNS.map(c => c.width);
        this.#pane = document.querySelector(paneSel);
        this.#buildDOM();
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    setData(events) {
        this.#data = events;
        this.#selIdx = -1;
        this.#updateColVar();
        this.#updateInnerHeight();
        this.#renderVisible();
        this.#updateFooter();
    }

    getSelected() {
        return this.#selIdx >= 0 ? this.#data[this.#selIdx] : null;
    }

    selectIndex(idx) {
        this.#selectRow(idx, true);
    }

    /* ── DOM Construction ───────────────────────────────────────────────── */

    #buildDOM() {
        // Toolbar
        const toolbar = document.createElement('div');
        toolbar.id = 'ls-table-toolbar';
        toolbar.innerHTML = `
            <span id="ls-result-info">
                <span id="ls-result-count" class="fw-bold">0</span> events
            </span>
            <span class="ms-auto text-secondary" id="ls-sel-hint" style="font-size:0.72rem">
                Click row or use ↑↓ keys
            </span>
        `;
        this.#pane.appendChild(toolbar);

        // Column headers
        const headRow = document.createElement('div');
        headRow.id = 'ls-col-headers';
        EventTable.COLUMNS.forEach((col, ci) => {
            const th = document.createElement('div');
            th.className = 'ls-col-head';
            th.dataset.col = col.id;
            th.innerHTML = `${col.label}<span class="sort-arrow"></span>
                <span class="ls-col-resize" data-ci="${ci}"></span>`;
            if (!col.noSort) {
                th.addEventListener('click', e => {
                    if (e.target.classList.contains('ls-col-resize')) return;
                    this.#sortBy(col.sortKey || col.id);
                });
            }
            headRow.appendChild(th);
        });
        this.#pane.appendChild(headRow);
        this.#updateColVar();

        // Scroll container (the virtual list)
        const scroll = document.createElement('div');
        scroll.id = 'ls-table-scroll';
        scroll.tabIndex = 0;
        scroll.setAttribute('role', 'grid');
        scroll.setAttribute('aria-label', 'Events table');
        this.#scrollEl = scroll;

        const inner = document.createElement('div');
        inner.id = 'ls-table-inner';
        this.#innerEl = inner;
        scroll.appendChild(inner);
        this.#pane.appendChild(scroll);

        // Loading overlay (inside scroll)
        const overlay = document.createElement('div');
        overlay.id = 'ls-loading-overlay';
        overlay.className = 'hidden';
        overlay.innerHTML = `<div class="spinner-border text-info" style="width:1.5rem;height:1.5rem"><span class="visually-hidden">Loading</span></div>`;
        scroll.appendChild(overlay);

        // Footer
        const footer = document.createElement('div');
        footer.id = 'ls-table-footer';
        footer.innerHTML = `
            <span id="ls-footer-left">—</span>
            <span id="ls-footer-right" class="text-secondary">Keyboard: ↑↓ Navigate · Enter Select</span>
        `;
        this.#pane.appendChild(footer);

        // Events
        scroll.addEventListener('scroll', () => this.#renderVisible());
        scroll.addEventListener('keydown', e => this.#onKeyDown(e));

        this.#wireColumnResize();
    }

    /* ── Virtual Rendering ──────────────────────────────────────────────── */

    #renderVisible() {
        const scrollTop = this.#scrollEl.scrollTop;
        const viewH = this.#scrollEl.clientHeight;
        const RH = EventTable.ROW_H;
        const BUFFER = EventTable.BUFFER;
        const total = this.#data.length;

        const start = Math.max(0, Math.floor(scrollTop / RH) - BUFFER);
        const end   = Math.min(total, Math.ceil((scrollTop + viewH) / RH) + BUFFER);

        // Only re-render if range changed
        if (start === this.#renderedStart && end === this.#renderedEnd) return;
        this.#renderedStart = start;
        this.#renderedEnd = end;

        if (total === 0) {
            this.#innerEl.innerHTML = `
                <div class="ls-placeholder" style="height:200px">
                    <i class="bi bi-funnel"></i>
                    <span>No events match the current filters.</span>
                </div>`;
            return;
        }

        // Remove rows that are out of range
        const existing = new Map();
        this.#innerEl.querySelectorAll('.ls-row').forEach(el => {
            const idx = +el.dataset.idx;
            if (idx < start || idx >= end) el.remove();
            else existing.set(idx, el);
        });

        // Add new rows
        const frag = document.createDocumentFragment();
        for (let i = start; i < end; i++) {
            if (existing.has(i)) {
                // update selected state only
                existing.get(i).classList.toggle('selected', i === this.#selIdx);
                continue;
            }
            const el = this.#buildRow(this.#data[i], i);
            frag.appendChild(el);
        }
        this.#innerEl.appendChild(frag);
    }

    #buildRow(ev, idx) {
        const el = document.createElement('div');
        el.className = 'ls-row';
        el.dataset.idx = idx;
        el.style.top = `${idx * EventTable.ROW_H}px`;
        el.setAttribute('role', 'row');
        el.setAttribute('aria-rowindex', idx + 1);

        // Color rules (first match wins)
        for (const rule of EventTable.COLOR_RULES) {
            if (rule.test(ev)) { el.classList.add(rule.cls); break; }
        }
        if (idx === this.#selIdx) el.classList.add('selected');

        el.innerHTML = this.#buildRowHTML(ev, idx);
        el.addEventListener('click', () => this.#selectRow(idx, true));
        el.addEventListener('contextmenu', e => {
            e.preventDefault();
            this.#selectRow(idx, false);
            this.#onCtxMenu(ev, e.clientX, e.clientY);
        });
        return el;
    }

    #buildRowHTML(ev, idx) {
        const ts = ev.timestamp
            ? new Date(ev.timestamp).toLocaleString('en-GB', {
                year:'2-digit', month:'2-digit', day:'2-digit',
                hour:'2-digit', minute:'2-digit', second:'2-digit' })
            : '—';
        const sev = ev._severity || 'none';
        const srcBadge = ev.log_source
            ? `<span class="sev-badge src-${ev.log_source}">${ev.log_source}</span>` : '—';
        const sevBadge = sev !== 'none'
            ? `<span class="sev-badge sev-${sev}">${sev}</span>` : '';

        return `
            <div class="ls-cell ls-cell-num">${idx + 1}</div>
            <div class="ls-cell ls-cell-ts">${ts}</div>
            <div class="ls-cell ls-cell-ip">${EventTable.esc(ev.source_ip || '—')}</div>
            <div class="ls-cell ls-cell-type">${EventTable.esc(ev.event_type || '—')}</div>
            <div class="ls-cell ls-cell-user">${EventTable.esc(ev.username || '—')}</div>
            <div class="ls-cell">${srcBadge}</div>
            <div class="ls-cell">${sevBadge}</div>
        `;
    }

    /* ── Sorting ─────────────────────────────────────────────────────────── */

    #sortBy(key) {
        if (this.#sortCol === key) {
            this.#sortDir = this.#sortDir === 'asc' ? 'desc' : 'asc';
        } else {
            this.#sortCol = key;
            this.#sortDir = 'asc';
        }
        this.#applySort();
        this.#updateSortHeaders();
        this.#selIdx = -1;
        this.#updateInnerHeight();
        this.#renderVisible();
    }

    #applySort() {
        const { col: _c, dir } = { col: this.#sortCol, dir: this.#sortDir };
        const key = this.#sortCol;
        const mul = dir === 'asc' ? 1 : -1;
        this.#data.sort((a, b) => {
            const va = a[key] ?? '';
            const vb = b[key] ?? '';
            if (va < vb) return -1 * mul;
            if (va > vb) return  1 * mul;
            return 0;
        });
    }

    #updateSortHeaders() {
        const head = document.getElementById('ls-col-headers');
        if (!head) return;
        head.querySelectorAll('.ls-col-head').forEach(th => {
            const col = EventTable.COLUMNS.find(c => c.id === th.dataset.col);
            if (!col) return;
            th.classList.remove('sort-asc', 'sort-desc');
            if (col.sortKey === this.#sortCol || col.id === this.#sortCol) {
                th.classList.add(this.#sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
            }
        });
    }

    /* ── Selection ──────────────────────────────────────────────────────── */

    #selectRow(idx, fire = true) {
        this.#selIdx = idx;
        // Update all visible rows' selected class
        this.#innerEl.querySelectorAll('.ls-row').forEach(el => {
            el.classList.toggle('selected', +el.dataset.idx === idx);
        });
        this.#updateFooter();
        if (fire && idx >= 0) this.#onSelect(this.#data[idx], idx);
    }

    /* ── Keyboard navigation ────────────────────────────────────────────── */

    #onKeyDown(e) {
        if (!this.#data.length) return;
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            const delta = e.key === 'ArrowDown' ? 1 : -1;
            const next = Math.max(0, Math.min(this.#data.length - 1, this.#selIdx + delta));
            this.#selectRow(next, true);
            this.#scrollToRow(next);
        }
        if (e.key === 'Enter' && this.#selIdx >= 0) {
            this.#onSelect(this.#data[this.#selIdx], this.#selIdx);
        }
        if (e.key === 'Home') { e.preventDefault(); this.#selectRow(0, true); this.#scrollToRow(0); }
        if (e.key === 'End')  { e.preventDefault(); const l = this.#data.length - 1; this.#selectRow(l, true); this.#scrollToRow(l); }
    }

    #scrollToRow(idx) {
        const top = idx * EventTable.ROW_H;
        const viewH = this.#scrollEl.clientHeight;
        const scrollTop = this.#scrollEl.scrollTop;
        if (top < scrollTop) this.#scrollEl.scrollTop = top;
        else if (top + EventTable.ROW_H > scrollTop + viewH)
            this.#scrollEl.scrollTop = top + EventTable.ROW_H - viewH;
        this.#renderVisible();
    }

    /* ── Column resize ──────────────────────────────────────────────────── */

    #wireColumnResize() {
        const head = document.getElementById('ls-col-headers');
        if (!head) return;
        head.addEventListener('mousedown', e => {
            const handle = e.target.closest('.ls-col-resize');
            if (!handle) return;
            const ci = +handle.dataset.ci;
            const startX = e.clientX;
            const startW = this.#colWidths[ci];
            document.body.classList.add('col-resizing');
            const onMove = mv => {
                this.#colWidths[ci] = Math.max(40, startW + mv.clientX - startX);
                this.#updateColVar();
            };
            const onUp = () => {
                document.body.classList.remove('col-resizing');
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
            };
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
        });
    }

    /* ── Helpers ────────────────────────────────────────────────────────── */

    #updateColVar() {
        const val = this.#colWidths.map(w => `${w}px`).join(' ');
        this.#pane.style.setProperty('--ls-col-widths', val);
    }

    #updateInnerHeight() {
        this.#innerEl.style.height = `${this.#data.length * EventTable.ROW_H}px`;
    }

    #updateFooter() {
        const left = document.getElementById('ls-footer-left');
        const cnt  = document.getElementById('ls-result-count');
        if (cnt) cnt.textContent = this.#data.length.toLocaleString();
        if (left) {
            if (this.#selIdx >= 0) {
                const ev = this.#data[this.#selIdx];
                left.textContent = `Selected #${this.#selIdx + 1} — ${ev.event_type || ''} from ${ev.source_ip || '—'}`;
            } else {
                left.textContent = `${this.#data.length.toLocaleString()} events loaded`;
            }
        }
    }

    setLoading(show) {
        const overlay = document.getElementById('ls-loading-overlay');
        if (overlay) overlay.classList.toggle('hidden', !show);
    }

    /* ── Static helpers ─────────────────────────────────────────────────── */

    static esc(s) {
        return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    static isPublicIP(ip) {
        if (!ip) return false;
        // Private ranges: 10.x, 192.168.x, 172.16-31.x, 127.x
        return !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|localhost)/.test(ip);
    }
}
