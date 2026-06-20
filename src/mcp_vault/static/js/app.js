/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — App (Navigation, Sidebar, Init)
   ═══════════════════════════════════════════════════════════════════════ */

/* ─── Sidebar builder ─── */
function buildSidebar() {
    const nav = document.getElementById('sidebarNav');
    let html = `
        <button onclick="navigate('dashboard')" id="nav-dashboard" class="active">📊 <span>${t('nav.dashboard')}</span></button>
        <button onclick="navigate('vaults')" id="nav-vaults">🗄️ <span>${t('nav.vaults')}</span></button>`;

    if (isAdmin()) {
        html += `
        <div class="sidebar-section">${t('nav.administration')}</div>
        <button onclick="navigate('policies')" id="nav-policies">📋 <span>${t('nav.policies')}</span></button>
        <button onclick="navigate('tokens')" id="nav-tokens">🔑 <span>${t('nav.tokens')}</span></button>
        <button onclick="navigate('pki')" id="nav-pki">🔐 <span>${t('nav.pki')}</span></button>`;
    }

    html += `
        <div class="sidebar-section">${t('nav.monitoring')}</div>
        <button onclick="navigate('activity')" id="nav-activity">📡 <span>${t('nav.activity')}</span></button>`;

    nav.innerHTML = html;
}

/* ─── Navigation ─── */
function navigate(page) {
    STATE.currentPage = page;
    if (STATE.activityTimer) { clearInterval(STATE.activityTimer); STATE.activityTimer = null; }

    // Hide all pages
    document.querySelectorAll('[id^="page-"]').forEach(el => el.classList.add('hidden'));
    // Deactivate all nav
    document.querySelectorAll('.sidebar-nav button').forEach(el => el.classList.remove('active'));

    // Show target
    const target = document.getElementById(`page-${page}`);
    if (target) target.classList.remove('hidden');
    const nav = document.getElementById(`nav-${page}`);
    if (nav) nav.classList.add('active');

    // Load data
    if (page === 'dashboard') loadDashboard();
    else if (page === 'vaults') loadVaults();
    else if (page === 'policies') loadPolicies();
    else if (page === 'tokens') loadTokens();
    else if (page === 'activity') { loadActivity(); STATE.activityTimer = setInterval(loadActivity, 5000); }
    else if (page === 'pki') loadPki();

    window.location.hash = page;
}

/* ─── Init ─── */
document.addEventListener('DOMContentLoaded', () => {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = document.getElementById('loginToken').value.trim();
        if (!token) return;
        const ok = await doLogin(token);
        if (!ok) {
            const err = document.getElementById('loginError');
            err.textContent = t('auth.invalidToken');
            setTimeout(() => err.textContent = '', 3000);
        }
    });

    // Modal backdrop close
    document.querySelectorAll('.modal-overlay').forEach(el => {
        el.addEventListener('click', (e) => { if (e.target === el) el.classList.remove('active'); });
    });

    // i18n: translate the static shell now, and re-render dynamic chrome on language change
    if (window.I18N) {
        window.I18N.onChange(() => {
            window.I18N.applyI18n(document);
            if (STATE.token) { buildSidebar(); navigate(STATE.currentPage); }
        });
        window.I18N.applyI18n(document);
    }

    // Auto-login
    tryAutoLogin();
});
