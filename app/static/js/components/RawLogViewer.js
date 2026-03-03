/**
 * RawLogViewer — syntax-highlighted raw log line display.
 *
 * Applies regex-based highlighting matching common syslog and nginx formats.
 * Renders inside the bottom section of the detail pane.
 *
 * Usage:
 *   const raw = new RawLogViewer('#ls-raw-pane');
 *   raw.show(event);
 *   raw.clear();
 */
export default class RawLogViewer {
    #pane = null;
    #body = null;

    constructor(paneSel) {
        this.#pane = document.querySelector(paneSel);
        this.#buildDOM();
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    show(ev) {
        if (!ev?.raw_line) { this.clear(); return; }
        this.#body.innerHTML = RawLogViewer.highlight(ev.raw_line, ev.log_source);
    }

    clear() {
        if (this.#body)
            this.#body.innerHTML = '<span class="raw-empty">No event selected — click a table row to see its raw log entry.</span>';
    }

    /* ── Build DOM ──────────────────────────────────────────────────────── */

    #buildDOM() {
        const header = document.createElement('div');
        header.id = 'ls-raw-header';
        header.innerHTML = `
            <i class="bi bi-terminal text-warning" style="font-size:0.85rem"></i>
            <span>Raw Log Entry</span>
            <button id="btnCopyRaw" class="ms-auto ls-action-btn" title="Copy raw line">
                <i class="bi bi-clipboard"></i> Copy
            </button>
            <button id="btnWrapRaw" class="ls-action-btn" title="Toggle line wrap">
                <i class="bi bi-text-wrap"></i> Wrap
            </button>
        `;
        this.#pane.appendChild(header);

        const body = document.createElement('div');
        body.id = 'ls-raw-body';
        body.innerHTML = '<span class="raw-empty">No event selected — click a table row to see its raw log entry.</span>';
        this.#pane.appendChild(body);
        this.#body = body;

        // Wire buttons
        document.getElementById('btnCopyRaw')?.addEventListener('click', () => {
            const text = body.innerText;
            navigator.clipboard.writeText(text).then(() => RawLogViewer.toast('Copied!'));
        });
        let wrapped = true;
        document.getElementById('btnWrapRaw')?.addEventListener('click', () => {
            wrapped = !wrapped;
            body.style.whiteSpace = wrapped ? 'pre-wrap' : 'pre';
        });
    }

    /* ── Syntax highlight ───────────────────────────────────────────────── */

    static highlight(line, src) {
        if (!line) return '';

        if (src === 'nginx') return RawLogViewer.#highlightNginx(line);
        if (src === 'auth')  return RawLogViewer.#highlightSyslog(line);

        // Auto-detect
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.+\[.+\].+"/.test(line))
            return RawLogViewer.#highlightNginx(line);
        return RawLogViewer.#highlightSyslog(line);
    }

    static #highlightSyslog(line) {
        // Syslog: Jan  1 00:00:00 host proc[pid]: message
        let hl = RawLogViewer.esc(line);

        // Timestamp prefix (MMM DD HH:MM:SS)
        hl = hl.replace(
            /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,
            '<span class="rw-ts">$1</span>'
        );
        // Hostname
        hl = hl.replace(
            /(<\/span> )(\S+)/,
            '$1<span class="rw-host">$2</span>'
        );
        // Process name[pid]:
        hl = hl.replace(
            /(\w+(?:\[\d+\])?:)/,
            '<span class="rw-proc">$1</span>'
        );
        // IP addresses
        hl = hl.replace(
            /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g,
            '<span class="rw-ip" title="Click to see details">$1</span>'
        );
        // Failed / Invalid / error keywords
        hl = hl.replace(
            /\b(Failed|Invalid|error|refused|BREAK-IN|illegal|Bad|disabled)\b/gi,
            '<span class="rw-kw-fail">$1</span>'
        );
        // Accepted / Successful
        hl = hl.replace(
            /\b(Accepted|success|opened|Connected)\b/gi,
            '<span class="rw-kw-ok">$1</span>'
        );
        // Username (from|for \w+)
        hl = hl.replace(
            /\b(from|for|user)\s+(\S+)/g,
            '<span class="rw-str">$1</span> <span class="rw-user">$2</span>'
        );
        // Port numbers
        hl = hl.replace(
            /\bport (\d+)\b/g,
            'port <span class="rw-num">$1</span>'
        );
        return hl;
    }

    static #highlightNginx(line) {
        // Nginx combined: IP - user [date] "method path proto" status size "ref" "ua"
        let hl = RawLogViewer.esc(line);

        // Leading IP
        hl = hl.replace(
            /^(\d{1,3}(?:\.\d{1,3}){3})/,
            '<span class="rw-ip">$1</span>'
        );
        // Date block [...]
        hl = hl.replace(
            /\[([^\]]+)\]/,
            '[<span class="rw-ts">$1</span>]'
        );
        // HTTP method + path
        hl = hl.replace(
            /"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^"]+)"/,
            '"<span class="rw-kw-ok">$1</span> <span class="rw-str">$2</span>"'
        );
        // Status code
        hl = hl.replace(
            /\b(2\d{2})\b/g, '<span class="rw-status-2xx">$1</span>'
        ).replace(
            /\b(3\d{2})\b/g, '<span class="rw-status-3xx">$1</span>'
        ).replace(
            /\b(4\d{2})\b/g, '<span class="rw-status-4xx">$1</span>'
        ).replace(
            /\b(5\d{2})\b/g, '<span class="rw-status-5xx">$1</span>'
        );
        // Numbers
        hl = hl.replace(/\b(\d+)\b/g, '<span class="rw-num">$1</span>');
        return hl;
    }

    static esc(s) {
        return String(s ?? '')
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    static toast(msg) {
        const area = document.getElementById('ls-toast-area');
        if (!area) return;
        const el = document.createElement('div');
        el.className = 'ls-toast success';
        el.textContent = msg;
        area.appendChild(el);
        setTimeout(() => el.remove(), 2000);
    }
}
