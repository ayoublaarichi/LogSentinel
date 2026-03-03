/* ═══════════════════════════════════════════════════════════════════════════
   LogSentinel — Client-side utilities
   ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Live clock in the navbar
 */
function updateClock() {
    const el = document.getElementById('clock');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleString('en-GB', {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false,
    });
}

setInterval(updateClock, 1000);
updateClock();
