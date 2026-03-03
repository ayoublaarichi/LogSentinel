/**
 * FilterBar — structured query input with autocomplete + chip rendering.
 *
 * Supported syntax:  ip:<value>  type:<value>  user:<value>
 *                    source:<value>  severity:<value>  rule:<value>
 *                    <freetext>
 *
 * Usage:
 *   const fb = new FilterBar('#ls-filterbar', { onFilter: chips => ... });
 *   fb.setHints({ ips, types, users });
 */
export default class FilterBar {
    /** @type {Array<{field:string, value:string}>} */
    #chips = [];
    #hints = { ips: [], types: [], users: [] };
    #acIndex = -1;
    #acItems = [];
    #onFilter = null;

    static FIELDS = ['ip', 'type', 'user', 'source', 'severity', 'rule'];
    static SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
    static SOURCES = ['auth', 'nginx'];

    constructor(containerSel, { onFilter } = {}) {
        this.#onFilter = onFilter || (() => {});
        this.#render(containerSel);
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    setHints({ ips = [], types = [], users = [] } = {}) {
        this.#hints = { ips, types, users };
    }

    getChips() { return [...this.#chips]; }

    clearAll() {
        this.#chips = [];
        this.#renderChips();
        this.#onFilter(this.#chips);
    }

    addChip(field, value) {
        if (!value) return;
        // deduplicate
        const exists = this.#chips.find(c => c.field === field && c.value === value);
        if (!exists) {
            this.#chips.push({ field, value });
            this.#renderChips();
            this.#onFilter([...this.#chips]);
        }
    }

    /* ── Render ─────────────────────────────────────────────────────────── */

    #render(sel) {
        const container = document.querySelector(sel);
        if (!container) return;

        // Input row
        const inputRow = document.createElement('div');
        inputRow.id = 'ls-filter-input-row';
        inputRow.style.position = 'relative';
        inputRow.innerHTML = `
            <i class="bi bi-funnel text-secondary" style="font-size:0.95rem;flex-shrink:0"></i>
            <input id="ls-filter-input" type="text" autocomplete="off" spellcheck="false"
                   placeholder="Filter: ip:192.168.x.x  type:ssh_failed  user:root  severity:high" />
            <div id="ls-autocomplete" style="display:none"></div>
            <button class="ls-action-btn" id="btnClearFilters" title="Clear all filters">
                <i class="bi bi-x-circle"></i> Clear
            </button>
        `;
        container.appendChild(inputRow);

        // Chips row
        const chipsRow = document.createElement('div');
        chipsRow.id = 'ls-chips-row';
        container.appendChild(chipsRow);

        // Wire events
        const inp = document.getElementById('ls-filter-input');
        const ac  = document.getElementById('ls-autocomplete');

        inp.addEventListener('input', () => this.#onInput(inp, ac));
        inp.addEventListener('keydown', e => this.#onKeyDown(e, inp, ac));
        inp.addEventListener('blur', () => setTimeout(() => { ac.style.display = 'none'; }, 150));

        document.getElementById('btnClearFilters').addEventListener('click', () => this.clearAll());
    }

    #onInput(inp, ac) {
        const raw = inp.value.trim();
        const suggestions = this.#getSuggestions(raw);
        this.#acItems = suggestions;
        this.#acIndex = -1;
        if (!suggestions.length || !raw) { ac.style.display = 'none'; return; }
        this.#renderAc(ac, suggestions, inp);
    }

    #onKeyDown(e, inp, ac) {
        if (ac.style.display !== 'none' && this.#acItems.length) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.#acIndex = Math.min(this.#acIndex + 1, this.#acItems.length - 1);
                this.#renderAc(ac, this.#acItems, inp);
                return;
            }
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.#acIndex = Math.max(this.#acIndex - 1, -1);
                this.#renderAc(ac, this.#acItems, inp);
                return;
            }
            if (e.key === 'Tab' || e.key === 'Enter') {
                if (this.#acIndex >= 0) {
                    e.preventDefault();
                    this.#selectAc(this.#acItems[this.#acIndex], inp, ac);
                    return;
                }
            }
        }
        if (e.key === 'Enter') {
            e.preventDefault();
            this.#commitInput(inp, ac);
        }
        if (e.key === 'Escape') {
            ac.style.display = 'none';
        }
        if (e.key === 'Backspace' && !inp.value && this.#chips.length) {
            this.#chips.pop();
            this.#renderChips();
            this.#onFilter([...this.#chips]);
        }
    }

    #getSuggestions(raw) {
        const { ips, types, users } = this.#hints;
        const suggestions = [];

        // If user typed a known field prefix...
        const fieldMatch = raw.match(/^(\w+):(.*)$/);
        if (fieldMatch) {
            const [, field, partial] = fieldMatch;
            const lp = partial.toLowerCase();
            if (field === 'ip') {
                ips.filter(v => v.includes(lp)).slice(0, 8).forEach(v =>
                    suggestions.push({ field: 'ip', value: v, display: `ip:${v}` }));
            } else if (field === 'type') {
                types.filter(v => v.toLowerCase().includes(lp)).slice(0, 8).forEach(v =>
                    suggestions.push({ field: 'type', value: v, display: `type:${v}` }));
            } else if (field === 'user') {
                users.filter(v => v.toLowerCase().includes(lp)).slice(0, 8).forEach(v =>
                    suggestions.push({ field: 'user', value: v, display: `user:${v}` }));
            } else if (field === 'source') {
                FilterBar.SOURCES.filter(v => v.includes(lp)).forEach(v =>
                    suggestions.push({ field: 'source', value: v, display: `source:${v}` }));
            } else if (field === 'severity') {
                FilterBar.SEVERITIES.filter(v => v.includes(lp)).forEach(v =>
                    suggestions.push({ field: 'severity', value: v, display: `severity:${v}` }));
            }
            return suggestions;
        }

        // Show field completions if partial word
        const lraw = raw.toLowerCase();
        FilterBar.FIELDS.filter(f => f.startsWith(lraw) || lraw === '').forEach(f =>
            suggestions.push({ field: '__key__', value: f + ':', display: `${f}:…`, isKey: true }));

        return suggestions.slice(0, 8);
    }

    #renderAc(ac, items, inp) {
        ac.innerHTML = items.map((it, i) => `
            <div class="ls-ac-item ${i === this.#acIndex ? 'active' : ''}" data-i="${i}">
                ${it.isKey
                    ? `<span class="ls-ac-key">${it.display}</span>`
                    : `<span class="ls-ac-key">${it.field}</span><span class="ls-ac-sep">:</span><span class="ls-ac-val">${it.value}</span>`
                }
            </div>
        `).join('');
        ac.style.display = 'block';
        ac.querySelectorAll('.ls-ac-item').forEach((el, i) => {
            el.addEventListener('mousedown', e => {
                e.preventDefault();
                this.#selectAc(items[i], inp, ac);
            });
        });
    }

    #selectAc(item, inp, ac) {
        if (item.isKey) {
            inp.value = item.value;
            ac.style.display = 'none';
            inp.focus();
            // re-trigger suggestions for the selected key
            this.#onInput(inp, ac);
        } else {
            inp.value = '';
            ac.style.display = 'none';
            this.addChip(item.field, item.value);
        }
    }

    #commitInput(inp, ac) {
        const raw = inp.value.trim();
        if (!raw) return;
        ac.style.display = 'none';

        const m = raw.match(/^(\w+):(.+)$/);
        if (m) {
            const [, field, value] = m;
            if (FilterBar.FIELDS.includes(field)) {
                inp.value = '';
                this.addChip(field, value.replace(/^"|"$/g, '').trim());
                return;
            }
        }
        // freetext
        inp.value = '';
        this.addChip('text', raw);
    }

    #renderChips() {
        const row = document.getElementById('ls-chips-row');
        if (!row) return;
        if (!this.#chips.length) {
            row.innerHTML = '<span style="color:#484f58;font-size:0.74rem">No active filters</span>';
            return;
        }
        row.innerHTML = this.#chips.map((c, i) => `
            <span class="ls-chip" data-i="${i}">
                <span class="ls-chip-key">${this.#escHtml(c.field)}</span>
                <span class="ls-chip-sep">:</span>
                <span class="ls-chip-val">${this.#escHtml(c.value)}</span>
                <button class="ls-chip-rm" data-i="${i}" title="Remove filter">&#x2715;</button>
            </span>
        `).join('');
        row.querySelectorAll('.ls-chip-rm').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const idx = +btn.dataset.i;
                this.#chips.splice(idx, 1);
                this.#renderChips();
                this.#onFilter([...this.#chips]);
            });
        });
    }

    #escHtml(s) {
        return String(s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
}
