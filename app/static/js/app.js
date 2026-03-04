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

function activeProjectId() {
    return localStorage.getItem('ls_active_project_id') || '';
}

function applyProjectToNavLinks() {
    const projectId = activeProjectId();
    if (!projectId) return;

    const navPaths = ['/', '/upload', '/events', '/alerts', '/search'];
    document.querySelectorAll('.navbar .nav-link[href]').forEach(link => {
        try {
            const url = new URL(link.getAttribute('href'), window.location.origin);
            if (!navPaths.includes(url.pathname)) return;
            url.searchParams.set('project_id', projectId);
            link.setAttribute('href', url.pathname + url.search);
        } catch (_) {
        }
    });
}

async function initGlobalProjectSelector() {
    const select = document.getElementById('ls-global-project');
    if (!select) return;

    const params = new URLSearchParams(window.location.search);
    const urlProjectId = params.get('project_id');
    if (urlProjectId) {
        localStorage.setItem('ls_active_project_id', urlProjectId);
    }

    const activeProjectId = localStorage.getItem('ls_active_project_id') || '';
    try {
        const resp = await fetch('/api/projects/', { credentials: 'same-origin' });
        if (resp.status === 401 || !resp.ok) return;
        const projects = await resp.json();
        const list = Array.isArray(projects) ? projects : [];

        const hasActive = activeProjectId && list.some(p => String(p.id) === String(activeProjectId));
        if (activeProjectId && !hasActive) {
            localStorage.removeItem('ls_active_project_id');
        }

        const effectiveProjectId = hasActive ? String(activeProjectId) : '';
        const options = ['<option value="">All visible</option>'];
        for (const project of list) {
            const selected = String(project.id) === effectiveProjectId ? ' selected' : '';
            options.push(`<option value="${String(project.id)}"${selected}>${String(project.name)}</option>`);
        }
        select.innerHTML = options.join('');

        if (window.location.pathname === '/' && effectiveProjectId && !params.get('project_id')) {
            const url = new URL(window.location.href);
            url.searchParams.set('project_id', effectiveProjectId);
            window.location.replace(url.toString());
            return;
        }

        applyProjectToNavLinks();

        select.addEventListener('change', () => {
            const nextId = select.value || '';
            if (nextId) localStorage.setItem('ls_active_project_id', nextId);
            else localStorage.removeItem('ls_active_project_id');

            const url = new URL(window.location.href);
            if (nextId) url.searchParams.set('project_id', nextId);
            else url.searchParams.delete('project_id');
            window.location.assign(url.toString());
        });
    } catch (_) {
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initGlobalProjectSelector();
});
