/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — PKI Certificate Authority
   ═══════════════════════════════════════════════════════════════════════ */

async function loadPki() {
    const page = document.getElementById('page-pki');
    page.innerHTML = `<div class="loading">${t('pki.loadingPki')}</div>`;

    const status = await api('/pki/status');

    if (status.status === 'not_initialized') {
        page.innerHTML = _renderPkiSetupPanel();
        return;
    }
    if (status.status === 'error') {
        page.innerHTML = `<div class="error-banner">${t('pki.errorPki')} ${esc(status.message)}</div>`;
        return;
    }

    // Charger certs et rôles en parallèle
    const [certs, roles] = await Promise.all([
        api('/pki/certs'),
        api('/pki/roles'),
    ]);

    if (certs.status === 'error') {
        page.innerHTML = `<div class="error-banner">${t('pki.errorInventory')} ${esc(certs.message)}</div>`;
        return;
    }
    if (roles.status === 'error') {
        page.innerHTML = `<div class="error-banner">${t('pki.errorAcmeRoles')} ${esc(roles.message)}</div>`;
        return;
    }

    // Détails du rôle ACME principal (acme-servers)
    let roleDetail = null;
    if (roles.roles && roles.roles.length > 0) {
        const d = await api(`/pki/roles/${encodeURIComponent(roles.roles[0])}`);
        if (d.status === 'ok') roleDetail = d;
    }

    page.innerHTML = _renderPkiPage(status, certs, roles, roleDetail);
}

/* ─── Rendu page PKI initialisée ─── */
function _renderPkiPage(s, certs, roles, roleDetail) {
    const now = new Date();
    const rootExp = s.root_expires !== 'inconnu' ? new Date(s.root_expires) : null;
    const intExp  = s.int_expires  !== 'inconnu' ? new Date(s.int_expires)  : null;

    function expBadge(dt) {
        if (!dt) return `<span class="badge badge-warn">${t('pki.unknown')}</span>`;
        const days = Math.round((dt - now) / 86400000);
        const cls  = days < 30 ? 'badge-danger' : days < 90 ? 'badge-warn' : 'badge-ok';
        return `<span class="badge ${cls}">${fmtDate(dt.toISOString())} (J-${days})</span>`;
    }

    const certRows = (certs.certs || []).map(c => {
        const sans = (c.sans || []).join(', ') || '—';
        const exp  = c.not_after ? fmtDate(c.not_after) : '—';
        const rev  = c.revoked
            ? `<span class="badge badge-danger">${t('pki.revoked')}</span>`
            : `<span class="badge badge-ok">${t('pki.active')}</span>`;
        // SÉCURITÉ : JSON.stringify évite le XSS onclick (esc() n'échappe pas les quotes simples)
        const revokeBtn = (!c.revoked && isAdmin())
            ? `<button class="btn btn-sm btn-danger" onclick="pkiRevoke(${JSON.stringify(c.serial)})">${t('pki.revoke')}</button>`
            : '';
        return `<tr>
            <td class="mono-small">${esc(c.serial)}</td>
            <td>${esc(sans)}</td>
            <td>${exp}</td>
            <td>${rev}</td>
            <td>${revokeBtn}</td>
        </tr>`;
    }).join('') || `<tr><td colspan="5" class="empty-row">${t('pki.noCertsIssued')}</td></tr>`;

    const actions = isAdmin()
        ? `<div class="page-header-actions">
               <button class="btn btn-primary" onclick="openModal('modalPkiIssue')">${t('pki.generateCert')}</button>
               <button class="btn btn-warn" onclick="pkiRotate()">${t('pki.rotateIntermediate')}</button>
           </div>`
        : '';

    return `
    <div class="page-header">
        <h2>PKI Certificate Authority</h2>
        ${actions}
    </div>

    <!-- Statut CA -->
    <div class="card-grid">
        <div class="card">
            <div class="card-label">${t('pki.rootCa')}</div>
            <div class="card-value">${expBadge(rootExp)}</div>
            <div class="card-sub">SHA-256 : <code class="mono-tiny">${esc(s.root_fingerprint_sha256 || '—')}</code></div>
        </div>
        <div class="card">
            <div class="card-label">${t('pki.intermediateCa')}</div>
            <div class="card-value">${expBadge(intExp)}</div>
        </div>
        <div class="card">
            <div class="card-label">${t('pki.certsIssued')}</div>
            <div class="card-value card-value-big">${s.cert_count !== undefined ? s.cert_count : '—'}</div>
        </div>
        <div class="card">
            <div class="card-label">${t('pki.acmeServer')}</div>
            <div class="card-value">${s.acme_enabled
                ? `<span class="badge badge-ok">${t('pki.statusActive')}</span>`
                : `<span class="badge badge-warn">${t('pki.statusInactive')}</span>`}</div>
        </div>
        <div class="card">
            <div class="card-label">${t('pki.eabEnrollment')}</div>
            <div class="card-value">${s.eab_required
                ? `<span class="badge badge-ok">${t('pki.required')}</span> <span class="help-text">${esc(s.eab_policy || '')}</span>`
                : `<span class="badge badge-warn">${t('pki.notRequired')}</span> <span class="help-text">${esc(s.eab_policy || '')}</span>`}</div>
        </div>
    </div>

    <!-- URLs de distribution -->
    <div class="section-title">${t('pki.distributionUrls')}</div>
    <div class="url-list">
        ${_urlRow(t('pki.rootCaPem'), s.root_pem_url)}
        ${_urlRow(t('pki.fullChainPem'), s.chain_pem_url)}
        ${_urlRow(t('pki.crlPem'), s.crl_url)}
        ${_urlRow(t('pki.acmeDirectory'), s.acme_directory)}
    </div>

    <!-- Rôles ACME -->
    <div class="section-title">${t('pki.acmeRolePolicy')}</div>
    ${_renderAcmeRoles(roles, roleDetail)}

    <!-- Inventaire certs -->
    <div class="section-title">${t('pki.certInventory')}</div>
    <div class="table-wrapper">
        <table>
            <thead><tr>
                <th>${t('pki.serialNumber')}</th><th>SANs</th><th>${t('pki.expiration')}</th>
                <th>${t('common.status')}</th><th>${t('common.actions')}</th>
            </tr></thead>
            <tbody>${certRows}</tbody>
        </table>
    </div>`;
}

function _renderAcmeRoles(roles, detail) {
    if (!roles || roles.status === 'error' || !roles.roles || roles.roles.length === 0) {
        return `<div class="empty-state" style="padding:0.5rem">${t('pki.noAcmeRoles')}</div>`;
    }
    const roleList = roles.roles.map(r => `<code>${esc(r)}</code>`).join(', ');
    if (!detail) return `<div class="help-text">${t('pki.rolesLabel')} ${roleList}</div>`;

    const domains = (detail.allowed_domains || []).join(', ') || '—';
    const flags = [
        detail.server_flag ? 'server' : null,
        detail.allow_subdomains ? 'subdomains' : null,
        detail.allow_wildcard_certificates ? 'wildcard' : null,
    ].filter(Boolean).join(', ') || '—';

    return `<div class="url-list" style="gap:0.3rem">
        <div class="url-row"><span class="url-label">${t('pki.activeRole')}</span><code class="url-value">${esc(detail.role_name)}</code></div>
        <div class="url-row"><span class="url-label">${t('pki.allowedDomains')}</span><code class="url-value">${esc(domains)}</code></div>
        <div class="url-row"><span class="url-label">${t('pki.maxTtl')}</span><code class="url-value">${esc(detail.max_ttl || '—')}</code></div>
        <div class="url-row"><span class="url-label">${t('pki.flags')}</span><code class="url-value">${esc(flags)}</code></div>
        <div class="url-row"><span class="url-label">IP SANs</span><code class="url-value">${detail.allow_ip_sans ? '✅ ' + t('pki.allowed') : '❌ ' + t('pki.denied')}</code></div>
        <div class="url-row"><span class="url-label">Localhost</span><code class="url-value">${detail.allow_localhost ? '✅ ' + t('pki.allowedM') : '❌ ' + t('pki.deniedM')}</code></div>
    </div>`;
}

function _urlRow(label, url) {
    if (!url) return '';
    return `<div class="url-row">
        <span class="url-label">${esc(label)}</span>
        <code class="url-value">${esc(url)}</code>
        <button class="btn-copy" onclick="navigator.clipboard.writeText(${JSON.stringify(url)})" title="${t('common.copy')}">⎘</button>
    </div>`;
}

/* ─── Rendu panneau setup ─── */
function _renderPkiSetupPanel() {
    return `
    <div class="page-header"><h2>PKI Certificate Authority</h2></div>
    <div class="empty-state">
        <p>${t('pki.notInitialized')}</p>
        <p>${t('pki.setupHelp')}</p>
        ${isAdmin() ? `<button class="btn btn-primary" onclick="openModal('modalPkiSetup')">${t('pki.initializePki')}</button>` : `<p class="help-text">${t('pki.contactAdmin')}</p>`}
    </div>`;
}

/* ─── Actions PKI ─── */
async function pkiRevoke(serial) {
    if (!confirm(t('pki.confirmRevoke', { serial }))) return;
    const result = await api(`/pki/certs/${encodeURIComponent(serial)}/revoke`, { method: 'POST', body: '{}' });
    if (result.status === 'ok') {
        loadPki();
    } else {
        _pkiShowError(t('pki.errorRevoke') + ' ' + (result.message || t('pki.failed')));
    }
}

async function pkiRotate() {
    if (!confirm(t('pki.confirmRotate'))) return;
    const result = await api('/pki/ca/rotate', {
        method: 'POST',
        body: JSON.stringify({ keep_old_issuer: true, overlap_ttl: '48h' }),
    });
    if (result.status === 'ok') {
        _pkiShowError(t('pki.rotateDone') + ' ' + (result.new_issuer_id || '?'), 'info');
        loadPki();
    } else {
        _pkiShowError(t('pki.errorRotate') + ' ' + (result.message || '—'));
    }
}

function _pkiShowError(message, type = 'error') {
    const page = document.getElementById('page-pki');
    const div = document.createElement('div');
    div.className = type === 'info' ? 'success-banner' : 'error-banner';
    div.textContent = message;  // textContent = safe, pas de XSS
    page.prepend(div);
    setTimeout(() => div.remove(), 6000);
}

async function doPkiSetup() {
    const labMode  = document.getElementById('pkiLabMode').value === 'true';
    const domains  = document.getElementById('pkiDomains').value.trim();
    const leafTtl  = document.getElementById('pkiLeafTtl').value.trim() || '720h';

    if (!domains) { alert(t('pki.allowedDomainsRequired')); return; }

    const btn = document.querySelector('#modalPkiSetup .btn-primary');
    btn.disabled = true;
    btn.textContent = t('pki.initializing');

    const result = await api('/pki/setup', {
        method: 'POST',
        body: JSON.stringify({ lab_mode: labMode, allowed_domains: domains, leaf_ttl: leafTtl }),
    });

    btn.disabled = false;
    btn.textContent = t('pki.initialize');

    if (result.status === 'ok') {
        closeModal('modalPkiSetup');
        loadPki();
    } else {
        alert(t('common.error') + ' : ' + (result.message || '—'));
    }
}

/* ─── Génération de certificat (émission manuelle) ─── */
async function doPkiIssue() {
    const cn       = document.getElementById('pkiIssueCn').value.trim();
    const ttl      = document.getElementById('pkiIssueTtl').value.trim() || '720h';
    const altNames = document.getElementById('pkiIssueAltNames').value.trim();
    const ipSans   = document.getElementById('pkiIssueIpSans').value.trim();

    if (!cn) { alert(t('pki.commonNameRequired')); return; }

    const btn = document.querySelector('#modalPkiIssue .btn-primary');
    btn.disabled = true;
    btn.textContent = t('pki.issuing');

    const result = await api('/pki/issue', {
        method: 'POST',
        body: JSON.stringify({ common_name: cn, ttl, alt_names: altNames, ip_sans: ipSans }),
    });

    btn.disabled = false;
    btn.textContent = t('pki.generate');

    if (result.status === 'ok') {
        closeModal('modalPkiIssue');
        _pkiShowIssuedCert(result);
        loadPki();
    } else {
        alert(t('common.error') + ' : ' + (result.message || '—'));
    }
}

/* Affiche le cert émis + clé privée UNE FOIS — pas de copie automatique
   (la clé privée ne touche jamais le presse-papier sans action explicite). */
function _pkiShowIssuedCert(result) {
    const ov = document.createElement('div');
    ov.className = 'modal-overlay active';
    // textContent uniquement pour les blocs PEM → aucun risque XSS
    const cn = result.common_name || '?';
    const serial = result.serial_number || '?';
    const exp = result.expiration || '?';
    ov.innerHTML = `
        <div class="modal modal-lg">
            <h2>${t('pki.certIssued')} — ${esc(cn)}</h2>
            <div class="success-banner">${t('pki.serialLabel')} ${esc(serial)} — ${t('pki.expiresLabel')} ${esc(String(exp))}</div>
            <div class="error-banner">⚠️ ${t('pki.privateKeyWarning')}</div>
            <label>${t('pki.privateKey')}</label>
            <textarea class="mono-textarea" rows="7" readonly id="_issuedKey"></textarea>
            <label>${t('pki.certificate')}</label>
            <textarea class="mono-textarea" rows="6" readonly id="_issuedCert"></textarea>
            <label>${t('pki.caChain')}</label>
            <textarea class="mono-textarea" rows="4" readonly id="_issuedChain"></textarea>
            <div class="modal-actions">
                <button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">${t('common.close')}</button>
            </div>
        </div>`;
    document.body.appendChild(ov);
    // Injecter le PEM via .value (jamais innerHTML) — pas d'exécution, pas de clipboard auto
    ov.querySelector('#_issuedKey').value = result.private_key || '';
    ov.querySelector('#_issuedCert').value = result.certificate || '';
    ov.querySelector('#_issuedChain').value = result.ca_chain || '';
}
