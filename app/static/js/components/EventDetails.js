/**
 * EventDetails — expandable tree panel showing all event fields grouped
 * into sections (Summary, Source, Authentication, HTTP, Rule, Metadata).
 *
 * Usage:
 *   const det = new EventDetails('#ls-detail-pane', { onAction });
 *   det.show(event);
 *   det.clear();
 */
export default class EventDetails {
    #pane = null;
    #actionBar = null;
    #treeEl = null;
    #currentEvent = null;
    #onAction = null;
    /* collapse state per section */
    #collapsed = {};

    static SECTIONS = [
        {
            id: 'summary',
            icon: 'bi-card-text',
            label: 'Summary',
            fields: ev => [
                { k: 'id',         label: 'Event ID',   v: ev.id,         type: 'int'  },
                { k: 'timestamp',  label: 'Timestamp',  v: ev.timestamp,  type: 'date' },
                { k: 'event_type', label: 'Event Type', v: ev.event_type, type: 'badge_etype' },
                { k: 'file_name',  label: 'File',       v: ev.file_name               },
            ],
        },
        {
            id: 'source',
            icon: 'bi-hdd-network',
            label: 'Source',
            fields: ev => [
                { k: 'source_ip',  label: 'IP Address', v: ev.source_ip,  type: 'ip'            },
                { k: 'log_source', label: 'Log Source', v: ev.log_source, type: 'badge_source'  },
                { k: '_public',    label: 'IP Scope',   v: EventDetails.ipScope(ev.source_ip)   },
            ],
        },
        {
            id: 'auth',
            icon: 'bi-key',
            label: 'Authentication',
            visible: ev => ev.log_source === 'auth' || ev.username,
            fields: ev => [
                { k: 'username', label: 'Username', v: ev.username, type: 'user' },
                { k: 'event_type', label: 'Auth Result', v: ev.event_type, type: 'auth_result' },
            ],
        },
        {
            id: 'http',
            icon: 'bi-globe2',
            label: 'HTTP',
            visible: ev => ev.log_source === 'nginx',
            fields: ev => [
                { k: 'event_type', label: 'Method/Status', v: ev.event_type },
                { k: 'username',   label: 'Identity',      v: ev.username || '-' },
            ],
        },
        {
            id: 'rule',
            icon: 'bi-shield-exclamation',
            label: 'Rule Evaluation',
            fields: ev => [
                { k: '_severity', label: 'Severity',     v: ev._severity || 'none', type: 'severity' },
                { k: '_rule',     label: 'Matched Rule', v: ev._rule || 'No rule matched' },
                { k: '_reason',   label: 'Reason',       v: ev._reason || '—' },
            ],
        },
        {
            id: 'meta',
            icon: 'bi-info-circle',
            label: 'Metadata',
            fields: ev => [
                { k: 'created_at', label: 'Ingested At', v: ev.created_at, type: 'date' },
                { k: 'file_name',  label: 'Source File', v: ev.file_name              },
            ],
        },
        {
            id: 'threat',
            icon: 'bi-shield-fill-exclamation',
            label: 'Threat Intel',
            visible: ev => !!ev._threat,
            fields: ev => [
                { k: 'country',          label: 'Country',         v: ev._threat?.country || 'Unknown' },
                { k: 'asn',              label: 'ASN',             v: ev._threat?.asn || '—' },
                { k: 'isp',              label: 'ISP',             v: ev._threat?.isp || '—' },
                { k: 'is_tor',           label: 'Tor / Proxy',     v: ev._threat?.is_tor ? 'Yes' : 'No' },
                { k: 'reputation_score', label: 'Reputation Score',v: ev._threat?.reputation_score ?? '—' },
            ],
        },
    ];

    constructor(paneSel, { onAction } = {}) {
        this.#onAction = onAction || (() => {});
        this.#pane = document.querySelector(paneSel);
        this.#buildDOM();
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    show(ev) {
        this.#currentEvent = ev;
        this.#renderHeader(ev);
        this.#renderTree(ev);
        this.#renderActions(ev);
    }

    clear() {
        this.#currentEvent = null;
        const tree = document.getElementById('ls-detail-tree');
        if (tree) tree.innerHTML = `
            <div class="ls-placeholder">
                <i class="bi bi-cursor"></i>
                <span>Click a row to inspect event details</span>
            </div>`;
        const hdr = document.getElementById('ls-detail-header-title');
        if (hdr) hdr.textContent = 'No event selected';
        const ab = document.getElementById('ls-action-bar');
        if (ab) ab.style.display = 'none';
    }

    /* ── Build DOM ──────────────────────────────────────────────────────── */

    #buildDOM() {
        // Header
        const header = document.createElement('div');
        header.id = 'ls-detail-header';
        header.innerHTML = `
            <i class="bi bi-card-checklist text-info"></i>
            <span id="ls-detail-header-title" class="ls-detail-header-title">No event selected</span>
        `;
        this.#pane.appendChild(header);

        // Action bar
        const ab = document.createElement('div');
        ab.id = 'ls-action-bar';
        ab.style.display = 'none';
        this.#pane.appendChild(ab);

        // Tree
        const tree = document.createElement('div');
        tree.id = 'ls-detail-tree';
        tree.innerHTML = `<div class="ls-placeholder"><i class="bi bi-cursor"></i><span>Click a row to inspect event details</span></div>`;
        this.#pane.appendChild(tree);
        this.#treeEl = tree;
    }

    #renderHeader(ev) {
        const hdr = document.getElementById('ls-detail-header-title');
        if (!hdr) return;
        const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—';
        hdr.innerHTML = `<span class="text-info">${EventDetails.esc(ev.event_type)}</span>
            <span class="text-secondary ms-2" style="font-size:0.72rem">${ts}</span>`;
    }

    #renderTree(ev) {
        const tree = this.#treeEl;
        if (!tree) return;
        tree.innerHTML = '';

        for (const section of EventDetails.SECTIONS) {
            if (section.visible && !section.visible(ev)) continue;
            const fields = section.fields(ev);
            if (!fields.length) continue;

            const sec = document.createElement('div');
            sec.className = 'ls-tree-section';
            const isCollapsed = this.#collapsed[section.id] || false;

            const head = document.createElement('div');
            head.className = `ls-tree-section-head${isCollapsed ? ' collapsed' : ''}`;
            head.innerHTML = `<i class="bi ${section.icon}"></i>${section.label}
                <span class="chevron ms-auto">&#9660;</span>`;
            head.addEventListener('click', () => {
                this.#collapsed[section.id] = !this.#collapsed[section.id];
                head.classList.toggle('collapsed', this.#collapsed[section.id]);
                body.classList.toggle('hidden', this.#collapsed[section.id]);
            });

            const body = document.createElement('div');
            body.className = `ls-tree-section-body${isCollapsed ? ' hidden' : ''}`;

            for (const f of fields) {
                body.appendChild(this.#buildTreeRow(f.label, f.v, f.type, ev));
            }
            sec.appendChild(head);
            sec.appendChild(body);
            tree.appendChild(sec);
        }
    }

    #buildTreeRow(key, value, type, ev) {
        const row = document.createElement('div');
        row.className = 'ls-tree-row';

        const valHtml = this.#formatValue(value, type);
        row.innerHTML = `
            <span class="ls-tree-key" title="${EventDetails.esc(key)}">${EventDetails.esc(key)}</span>
            <span class="ls-tree-sep"> : </span>
            <span class="ls-tree-val">${valHtml}</span>
        `;

        // Right-click context menu on value
        const valEl = row.querySelector('.ls-tree-val');
        valEl.addEventListener('contextmenu', e => {
            e.preventDefault();
            this.#showCtxMenu(e.clientX, e.clientY, value, key, ev);
        });

        return row;
    }

    #formatValue(v, type) {
        if (v === null || v === undefined || v === '' || v === '—') {
            return `<span class="val-null">null</span>`;
        }
        const sv = String(v);
        switch (type) {
            case 'date':
                try { return `<span class="val-date">${new Date(v).toLocaleString()}</span>`; }
                catch { return EventDetails.esc(sv); }
            case 'int':
                return `<span class="val-int">${sv}</span>`;
            case 'ip':
                return `<span class="val-ip" title="Click to filter by this IP" data-ip="${EventDetails.esc(sv)}">${EventDetails.esc(sv)}</span>`;
            case 'user':
                return `<span class="val-user">${EventDetails.esc(sv)}</span>`;
            case 'severity':
                return `<span class="sev-badge sev-${sv.toLowerCase()}">${sv}</span>`;
            case 'badge_source':
                return `<span class="sev-badge src-${sv}">${sv}</span>`;
            case 'auth_result': {
                const lower = sv.toLowerCase();
                if (lower.includes('fail') || lower.includes('invalid'))
                    return `<span class="val-fail">${EventDetails.esc(sv)}</span>`;
                if (lower.includes('accept') || lower.includes('success'))
                    return `<span class="val-ok">${EventDetails.esc(sv)}</span>`;
                return EventDetails.esc(sv);
            }
            case 'badge_etype':
                return `<code style="font-size:0.78rem;color:#79c0ff">${EventDetails.esc(sv)}</code>`;
            default:
                return `<span>${EventDetails.esc(sv)}</span>`;
        }
    }

    #renderActions(ev) {
        const ab = document.getElementById('ls-action-bar');
        if (!ab) return;
        ab.style.display = 'flex';

        const actions = [
            { icon: 'bi-funnel-fill',  label: 'Add IP to filter',   key: 'filter_ip',    show: !!ev.source_ip },
            { icon: 'bi-diagram-3',    label: 'Pivot to IP',         key: 'pivot_ip',     show: !!ev.source_ip },
            { icon: 'bi-clock-history',label: 'IP timeline',         key: 'timeline_ip',  show: !!ev.source_ip },
            { icon: 'bi-clipboard',    label: 'Copy raw line',       key: 'copy_raw',     show: true },
            { icon: 'bi-slash-circle', label: 'Mark false positive',  key: 'false_pos',    show: true, cls: 'danger' },
        ];

        ab.innerHTML = actions
            .filter(a => a.show)
            .map(a => `
                <button class="ls-action-btn ${a.cls || ''}" data-key="${a.key}" title="${a.label}">
                    <i class="bi ${a.icon}"></i> ${a.label}
                </button>`)
            .join('');

        ab.querySelectorAll('.ls-action-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.#onAction(btn.dataset.key, ev);
            });
        });
    }

    /* ── Context menu ───────────────────────────────────────────────────── */

    #showCtxMenu(x, y, value, key, ev) {
        document.querySelector('.ls-ctx-menu')?.remove();
        const menu = document.createElement('div');
        menu.className = 'ls-ctx-menu';
        menu.innerHTML = `
            <div class="ls-ctx-item" data-action="copy">
                <i class="bi bi-clipboard"></i> Copy value
            </div>
            <div class="ls-ctx-item" data-action="filter">
                <i class="bi bi-funnel"></i> Add to filter (${EventDetails.esc(key)})
            </div>
            ${key === 'source_ip' && value ? `
            <div class="ls-ctx-divider"></div>
            <div class="ls-ctx-item" data-action="pivot">
                <i class="bi bi-diagram-3"></i> Pivot to IP
            </div>` : ''}
        `;
        menu.style.left = `${x}px`;
        menu.style.top  = `${y}px`;
        document.body.appendChild(menu);

        menu.querySelectorAll('.ls-ctx-item').forEach(item => {
            item.addEventListener('click', () => {
                const action = item.dataset.action;
                this.#onAction(action, ev, { key, value });
                menu.remove();
            });
        });

        const dismiss = e => {
            if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('mousedown', dismiss); }
        };
        setTimeout(() => document.addEventListener('mousedown', dismiss), 0);
    }

    /* ── Static helpers ─────────────────────────────────────────────────── */

    static ipScope(ip) {
        if (!ip) return '—';
        if (/^10\./.test(ip)) return 'Private (Class A)';
        if (/^192\.168\./.test(ip)) return 'Private (Class C)';
        if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return 'Private (Class B)';
        if (/^127\./.test(ip)) return 'Loopback';
        return 'Public';
    }

    static esc(s) {
        return String(s ?? '')
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
}
