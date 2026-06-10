/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — PKI Certificate Authority
   ═══════════════════════════════════════════════════════════════════════ */

async function loadPki() {
    const page = document.getElementById('page-pki');
    page.innerHTML = '<div class="loading">Chargement PKI...</div>';

    const status = await api('/pki/status');

    if (status.status === 'not_initialized') {
        page.innerHTML = _renderPkiSetupPanel();
        return;
    }
    if (status.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur PKI : ${esc(status.message)}</div>`;
        return;
    }

    const certs = await api('/pki/certs');
    if (certs.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur inventaire : ${esc(certs.message)}</div>`;
        return;
    }

    page.innerHTML = _renderPkiPage(status, certs);
}

/* ─── Rendu page PKI initialisée ─── */
function _renderPkiPage(s, certs) {
    const now = new Date();
    const rootExp = s.root_expires !== 'inconnu' ? new Date(s.root_expires) : null;
    const intExp  = s.int_expires  !== 'inconnu' ? new Date(s.int_expires)  : null;

    function expBadge(dt) {
        if (!dt) return '<span class="badge badge-warn">inconnu</span>';
        const days = Math.round((dt - now) / 86400000);
        const cls  = days < 30 ? 'badge-danger' : days < 90 ? 'badge-warn' : 'badge-ok';
        return `<span class="badge ${cls}">${fmtDate(dt.toISOString())} (J-${days})</span>`;
    }

    const certRows = (certs.certs || []).map(c => {
        const sans = (c.sans || []).join(', ') || '—';
        const exp  = c.not_after ? fmtDate(c.not_after) : '—';
        const rev  = c.revoked
            ? '<span class="badge badge-danger">révoqué</span>'
            : '<span class="badge badge-ok">actif</span>';
        // SÉCURITÉ : JSON.stringify évite le XSS onclick (esc() n'échappe pas les quotes simples)
        const revokeBtn = (!c.revoked && isAdmin())
            ? `<button class="btn btn-sm btn-danger" onclick="pkiRevoke(${JSON.stringify(c.serial)})">Révoquer</button>`
            : '';
        return `<tr>
            <td class="mono-small">${esc(c.serial)}</td>
            <td>${esc(sans)}</td>
            <td>${exp}</td>
            <td>${rev}</td>
            <td>${revokeBtn}</td>
        </tr>`;
    }).join('') || '<tr><td colspan="5" class="empty-row">Aucun certificat émis</td></tr>';

    const rotateBtn = isAdmin()
        ? `<button class="btn btn-warn" onclick="pkiRotate()">Rotation intermédiaire</button>`
        : '';

    return `
    <div class="page-header">
        <h2>PKI Certificate Authority</h2>
        ${rotateBtn}
    </div>

    <!-- Statut CA -->
    <div class="card-grid">
        <div class="card">
            <div class="card-label">CA Racine</div>
            <div class="card-value">${expBadge(rootExp)}</div>
            <div class="card-sub">SHA-256 : <code class="mono-tiny">${esc(s.root_fingerprint_sha256 || '—')}</code></div>
        </div>
        <div class="card">
            <div class="card-label">CA Intermédiaire</div>
            <div class="card-value">${expBadge(intExp)}</div>
        </div>
        <div class="card">
            <div class="card-label">Certificats émis</div>
            <div class="card-value card-value-big">${s.cert_count !== undefined ? s.cert_count : '—'}</div>
        </div>
        <div class="card">
            <div class="card-label">Serveur ACME</div>
            <div class="card-value">${s.acme_enabled
                ? '<span class="badge badge-ok">Actif</span>'
                : '<span class="badge badge-warn">Inactif</span>'}</div>
        </div>
    </div>

    <!-- URLs de distribution -->
    <div class="section-title">URLs de distribution (publiques)</div>
    <div class="url-list">
        ${_urlRow('CA Racine PEM', s.root_pem_url)}
        ${_urlRow('Chaîne complète PEM', s.chain_pem_url)}
        ${_urlRow('CRL PEM', s.crl_url)}
        ${_urlRow('Directory ACME', s.acme_directory)}
    </div>

    <!-- Inventaire certs -->
    <div class="section-title">Inventaire des certificats</div>
    <div class="table-wrapper">
        <table>
            <thead><tr>
                <th>Numéro de série</th><th>SANs</th><th>Expiration</th>
                <th>Statut</th><th>Action</th>
            </tr></thead>
            <tbody>${certRows}</tbody>
        </table>
    </div>`;
}

function _urlRow(label, url) {
    if (!url) return '';
    return `<div class="url-row">
        <span class="url-label">${esc(label)}</span>
        <code class="url-value">${esc(url)}</code>
        <button class="btn-copy" onclick="navigator.clipboard.writeText(${JSON.stringify(url)})" title="Copier">⎘</button>
    </div>`;
}

/* ─── Rendu panneau setup ─── */
function _renderPkiSetupPanel() {
    return `
    <div class="page-header"><h2>PKI Certificate Authority</h2></div>
    <div class="empty-state">
        <p>La PKI interne n'est pas encore initialisée.</p>
        <p>Une fois configurée, les WAF Caddy pourront obtenir leurs certificats TLS via ACME.</p>
        ${isAdmin() ? '<button class="btn btn-primary" onclick="openModal(\'modalPkiSetup\')">Initialiser la PKI</button>' : '<p class="help-text">Contactez un administrateur pour initialiser la PKI.</p>'}
    </div>`;
}

/* ─── Actions PKI ─── */
async function pkiRevoke(serial) {
    if (!confirm(`Révoquer le certificat ${serial} ?`)) return;
    const result = await api(`/pki/certs/${encodeURIComponent(serial)}/revoke`, { method: 'POST', body: '{}' });
    if (result.status === 'ok') {
        loadPki();
    } else {
        _pkiShowError('Erreur révocation : ' + (result.message || 'échec'));
    }
}

async function pkiRotate() {
    if (!confirm('Effectuer une rotation de la CA intermédiaire ? (les anciens certs restent valides)')) return;
    const result = await api('/pki/ca/rotate', {
        method: 'POST',
        body: JSON.stringify({ keep_old_issuer: true, overlap_ttl: '48h' }),
    });
    if (result.status === 'ok') {
        _pkiShowError('Rotation effectuée — nouvel issuer : ' + (result.new_issuer_id || '?'), 'info');
        loadPki();
    } else {
        _pkiShowError('Erreur rotation : ' + (result.message || '—'));
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

    if (!domains) { alert('Domaines autorisés requis'); return; }

    const btn = document.querySelector('#modalPkiSetup .btn-primary');
    btn.disabled = true;
    btn.textContent = 'Initialisation...';

    const result = await api('/pki/setup', {
        method: 'POST',
        body: JSON.stringify({ lab_mode: labMode, allowed_domains: domains, leaf_ttl: leafTtl }),
    });

    btn.disabled = false;
    btn.textContent = 'Initialiser';

    if (result.status === 'ok') {
        closeModal('modalPkiSetup');
        loadPki();
    } else {
        alert('Erreur : ' + (result.message || '—'));
    }
}
