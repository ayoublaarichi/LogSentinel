/**
 * TimelineChart — events-over-time bar chart using Chart.js.
 *
 * Renders a compact sparkline-style bar chart in the timeline strip.
 * Fetches data from  GET /api/events/timeline?hours=24
 *
 * Usage:
 *   const chart = new TimelineChart('timelineCanvas');
 *   chart.load();      // fetch and render
 *   chart.destroy();   // cleanup
 */
export default class TimelineChart {
    #canvasId = '';
    #chart = null;
    #toggleBtn = null;

    constructor(canvasId) {
        this.#canvasId = canvasId;
        const strip = document.getElementById('ls-timeline-bar');
        if (strip) {
            this.#toggleBtn = document.getElementById('ls-timeline-toggle');
            this.#toggleBtn?.addEventListener('click', () => this.#toggle(strip));
        }
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    async load(hours = 24) {
        try {
            const resp = await fetch(`/api/events/timeline?hours=${hours}`, { credentials: 'same-origin' });
            if (resp.status === 401) { window.location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search); return; }
            if (!resp.ok) return;
            const data = await resp.json();
            this.#render(data, hours);
        } catch (e) {
            console.warn('[TimelineChart] failed to load:', e);
        }
    }

    destroy() {
        this.#chart?.destroy();
        this.#chart = null;
    }

    /* ── Render ─────────────────────────────────────────────────────────── */

    #render(data, hours) {
        const canvas = document.getElementById(this.#canvasId);
        if (!canvas) return;

        // Fill gaps — one bar per hour
        const filled = TimelineChart.#fillHours(data, hours);
        const labels = filled.map(d => TimelineChart.#fmtHour(d.bucket));
        const counts = filled.map(d => d.count);
        const total  = counts.reduce((a, b) => a + b, 0);
        const maxVal = Math.max(...counts, 1);

        // Update title
        const titleEl = document.getElementById('ls-timeline-title');
        if (titleEl) titleEl.textContent = `${total.toLocaleString()} events · last ${hours}h`;

        this.#chart?.destroy();

        // Gradient fill
        const ctx = canvas.getContext('2d');
        const grad = ctx.createLinearGradient(0, 0, 0, 70);
        grad.addColorStop(0, 'rgba(88,166,255,0.6)');
        grad.addColorStop(1, 'rgba(88,166,255,0.05)');

        // Bar colours (high-count bars highlighted)
        const threshold = maxVal * 0.75;
        const barColors = counts.map(c =>
            c >= threshold ? 'rgba(248,81,73,0.8)' : 'rgba(88,166,255,0.7)'
        );

        this.#chart = new Chart(canvas, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    data: counts,
                    backgroundColor: barColors,
                    borderColor: 'transparent',
                    borderRadius: 2,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: false,
                animation: { duration: 300 },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#1c2128',
                        borderColor: '#30363d',
                        borderWidth: 1,
                        titleColor: '#8b949e',
                        bodyColor: '#c9d1d9',
                        callbacks: {
                            title: items => items[0].label,
                            label: item => ` ${item.raw.toLocaleString()} events`,
                        },
                    },
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(48,54,61,0.5)', drawBorder: false },
                        ticks: {
                            color: '#484f58',
                            font: { size: 9 },
                            maxTicksLimit: 12,
                            maxRotation: 0,
                        },
                    },
                    y: {
                        grid: { color: 'rgba(48,54,61,0.4)', drawBorder: false },
                        ticks: {
                            color: '#484f58',
                            font: { size: 9 },
                            maxTicksLimit: 4,
                            callback: v => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v,
                        },
                        beginAtZero: true,
                    },
                },
            },
        });
    }

    #toggle(strip) {
        strip.classList.toggle('collapsed');
        const collapsed = strip.classList.contains('collapsed');
        if (this.#toggleBtn) {
            this.#toggleBtn.innerHTML = collapsed
                ? '<i class="bi bi-chevron-down"></i> Show'
                : '<i class="bi bi-chevron-up"></i> Hide';
        }
    }

    /* ── Static helpers ─────────────────────────────────────────────────── */

    static #fillHours(data, hours) {
        const now = new Date();
        const map = new Map(data.map(d => [d.bucket.slice(0, 13), d.count]));
        const result = [];
        for (let h = hours - 1; h >= 0; h--) {
            const d = new Date(now);
            d.setMinutes(0, 0, 0);
            d.setHours(d.getHours() - h);
            const key = d.toISOString().slice(0, 13);
            result.push({ bucket: key + ':00:00', count: map.get(key) || 0 });
        }
        return result;
    }

    static #fmtHour(bucket) {
        try {
            const d = new Date(bucket);
            return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
        } catch { return bucket; }
    }
}
