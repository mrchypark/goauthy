(() => {
  'use strict';
  const dashboard = globalThis.accountDashboard;
  if (!dashboard || !dashboard.connectionDeps) return;
  const text = (value) => value === undefined || value === null ? '' : String(value);
  const quoted = (value) => `"${text(value)}"`;
  const safeError = (error) => text(error && error.message).includes('(409)') ? 'This grant changed elsewhere. Close and reopen to reload it.' : 'Unable to complete that grant action.';
  const expiryText = (value) => { const date = new Date(Number(value)); return Number.isFinite(date.getTime()) ? date.toISOString() : text(value); };

  dashboard.connectionGrantControl = function connectionGrantControl({ connection, definition, collection, current, busy, request, readJSON }) {
    const root = document.createElement('div'); root.className = 'connection-api-key';
    const manage = document.createElement('button'); manage.type = 'button'; manage.className = 'secondary'; manage.dataset.grantControl = ''; manage.dataset.connectionGrants = text(connection.id); manage.textContent = 'Manage service access';
    const panel = document.createElement('div'); panel.hidden = true; panel.dataset.grantPanel = text(connection.id);
    const heading = document.createElement('h3'); heading.textContent = 'Service access'; panel.append(heading);
    const list = document.createElement('div');
    const status = document.createElement('p'); status.className = 'hint'; status.dataset.grantStatus = text(connection.id); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
    const close = document.createElement('button'); close.type = 'button'; close.className = 'secondary'; close.dataset.grantControl = ''; close.dataset.grantClose = text(connection.id); close.textContent = 'Close';
    panel.append(list, close, status); root.append(manage, panel);
    const canCreateApiKey = Boolean(definition && definition.enabled && definition.auth_method === 'api_key' && Array.isArray(definition.provider_ids) && definition.provider_ids.length === 1);
    const canCreateOAuth = Boolean(definition && definition.enabled && definition.auth_method === 'oauth2' && Array.isArray(definition.provider_ids) && definition.provider_ids.length >= 1);
    const canCreate = canCreateApiKey || canCreateOAuth;
    let generation = 0, localBusy = false, loaded = false, grants = [], connectorDigest = '', oauth = null, settings = null;
    const isCurrent = () => typeof current === 'function' && current();
    const setBusy = (value) => { localBusy = value; manage.disabled = value; close.disabled = value; list.querySelectorAll('button').forEach((button) => { button.disabled = value; }); updateControls(); };
    const updateControls = () => { if (!createForm) return; createForm.querySelectorAll('input,textarea,button').forEach((control) => { control.disabled = localBusy || (control.dataset.grantReview !== undefined && (!loaded || (canCreateApiKey ? !connectorDigest : !oauth))) || (control.dataset.grantCreate !== undefined && (!loaded || (canCreateApiKey ? !connectorDigest : !oauth) || !reviewChecked())); }); };
    let reviewChecked = () => false;
    const message = (value, error) => { status.textContent = value; status.className = `hint${error ? ' error' : ''}`; };
    const path = `/auth/v1/account/connections/${encodeURIComponent(collection)}/${encodeURIComponent(connection.id)}`;
    const clearCreate = () => { connectorDigest = ''; oauth = null; if (createForm) { createForm.querySelectorAll('input,textarea').forEach((input) => { if (input.dataset.grantConsumer !== undefined || input.dataset.grantPurpose !== undefined || input.dataset.grantExpiry !== undefined) input.value = ''; }); createForm.querySelectorAll('[data-grant-review]').forEach((input) => { input.checked = false; }); createForm.querySelectorAll('[data-grant-refresh]').forEach((input) => { input.checked = false; }); updateControls(); } };
    const renderGrant = (grant) => {
      const row = document.createElement('article'); row.className = 'connection-row';
      const details = document.createElement('p'); details.textContent = `Grant ${text(grant.id)} · Consumer: ${text(grant.consumer_client_id)} · Mode: ${text(grant.mode)} · Purpose: ${text(grant.purpose)} · Resource: ${text(grant.resource)} · Expires: ${expiryText(grant.expires_at_unix_ms)} · ${grant.revoked ? 'Revoked' : 'Stored consent'}`;
      const note = document.createElement('p'); note.className = 'hint'; note.textContent = 'Stored consent; current policy is checked on each use.'; row.append(details, note);
      if (!grant.revoked) {
        const revoke = document.createElement('button'); revoke.type = 'button'; revoke.className = 'secondary'; revoke.dataset.grantControl = ''; revoke.dataset.grantRevoke = text(grant.id); revoke.textContent = 'Revoke access'; revoke.addEventListener('click', () => revokeGrant(grant)); row.append(revoke);
      }
      return row;
    };
    const render = () => { list.textContent = ''; grants.forEach((grant) => list.append(renderGrant(grant))); if (!grants.length) { const empty = document.createElement('p'); empty.className = 'hint'; empty.textContent = 'No service access grants.'; list.append(empty); } };
    const connector = async (token) => {
      if (!canCreateApiKey) return;
      try {
        const info = await request(`${path}/api-key/connector`).then(readJSON);
        if (token !== generation || !isCurrent()) return;
        const provider = definition.provider_ids[0];
        if (!info || info.id !== provider || typeof info.digest !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(info.digest) || !Array.isArray(info.operations) || !info.operations.length || info.operations.length > 32 || typeof info.header !== 'string' || typeof info.prefix !== 'string' || info.operations.some((op) => !op || typeof op.id !== 'string' || typeof op.method !== 'string' || typeof op.url !== 'string')) throw new Error('invalid connector');
        connectorDigest = info.digest;
        if (!settings) { settings = document.createElement('p'); settings.className = 'connection-key-settings'; panel.insertBefore(settings, createForm); } settings.hidden = false; settings.textContent = `Provider: ${text(info.id)}\nKey header: ${text(info.header)} (${text(info.prefix) || 'no prefix'})\nAllowed operations:\n${info.operations.map((op) => `${text(op.id)}: ${text(op.method)} ${text(op.url)}\nResponse fields: ${JSON.stringify(op.response_fields || {})}`).join('\n')}\nSettings digest: ${connectorDigest}`;
      } catch (_) { if (token === generation && isCurrent()) message('Unable to load provider settings. Close and reopen before creating access.', true); }
    };
    const oauthMetadata = async (token) => {
      if (!canCreateOAuth) return;
      try {
        const info = await request(`${path}/oauth2`).then(readJSON);
        if (token !== generation || !isCurrent()) return;
        if (!info || info.connected !== true || info.state !== 'ready' || !Number.isSafeInteger(info.version) || info.version <= 0 || typeof info.account_id !== 'string' || !info.account_id || typeof info.provider_id !== 'string' || !info.provider_id || !definition.provider_ids.includes(info.provider_id) || !Array.isArray(info.scopes) || !info.scopes.length || info.scopes.some((scope) => typeof scope !== 'string' || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) throw new Error('invalid oauth metadata');
        oauth = info;
        if (!settings) { settings = document.createElement('p'); settings.className = 'connection-key-settings'; panel.insertBefore(settings, createForm); }
        settings.hidden = false;
        settings.textContent = `Provider: ${text(info.provider_id)}\nAccount: ${text(info.account_id)}\nGranted scopes:\n${info.scopes.map(text).join('\n')}`;
        updateControls();
      } catch (_) { if (token === generation && isCurrent()) message('Unable to load connected OAuth access. Close and reopen before creating access.', true); }
    };
    let createForm = null;
    if (canCreate) {
      createForm = document.createElement('div');
      const consumerLabel = document.createElement('label'); consumerLabel.textContent = 'Consumer client ID (admin supplied ID; the server validates it)'; const consumer = document.createElement('input'); consumer.dataset.grantControl = ''; consumer.dataset.grantConsumer = text(connection.id); consumer.id = `grant-consumer-${connection.id}`; consumerLabel.htmlFor = consumer.id;
      const purposeLabel = document.createElement('label'); purposeLabel.textContent = 'Purpose'; const purpose = document.createElement('textarea'); purpose.maxLength = 256; purpose.rows = 2; purpose.dataset.grantControl = ''; purpose.dataset.grantPurpose = text(connection.id); purpose.id = `grant-purpose-${connection.id}`; purposeLabel.htmlFor = purpose.id;
      const expiryLabel = document.createElement('label'); expiryLabel.textContent = 'Expires'; const expiry = document.createElement('input'); expiry.type = 'datetime-local'; expiry.dataset.grantControl = ''; expiry.dataset.grantExpiry = text(connection.id); expiry.id = `grant-expiry-${connection.id}`; expiryLabel.htmlFor = expiry.id;
      const mode = document.createElement('p'); mode.textContent = canCreateOAuth ? 'Mode: credential delivery' : 'Mode: proxy';
      let refresh = null, refreshLabel = null;
      if (canCreateOAuth) { refreshLabel = document.createElement('label'); refresh = document.createElement('input'); refresh.type = 'checkbox'; refresh.dataset.grantControl = ''; refresh.dataset.grantRefresh = text(connection.id); const refreshText = document.createElement('span'); refreshText.textContent = 'Allow refresh-token use for future deliveries'; refreshLabel.append(refresh, refreshText); }
      const reviewLabel = document.createElement('label'); reviewLabel.className = 'connection-key-review'; const review = document.createElement('input'); review.type = 'checkbox'; review.dataset.grantControl = ''; review.dataset.grantReview = text(connection.id); const reviewText = document.createElement('span'); reviewText.textContent = 'I authorize this consumer to use all displayed operations until the expiry. No implicit consent is granted.'; reviewLabel.append(review, reviewText);
      if (canCreateOAuth) { const warning = document.createElement('p'); warning.className = 'hint error'; warning.textContent = 'Warning: this service receives an access token and can use all granted scopes, without proxy operation or response-field restrictions. The purpose is descriptive, not an access restriction. Refresh delegation is optional: the service may ask GoAuthy to refresh, while GoAuthy keeps the refresh token and client secret. Revoking stops future fetches but cannot recall an already delivered token.'; panel.insertBefore(warning, list); reviewText.textContent = 'I authorize this consumer to receive access tokens for the displayed account and scopes until the consent expires.'; }
      const create = document.createElement('button'); create.type = 'button'; create.className = 'secondary'; create.dataset.grantControl = ''; create.dataset.grantCreate = text(connection.id); create.textContent = 'Create service access'; create.disabled = true;
      createForm.append(consumerLabel, consumer, purposeLabel, purpose, expiryLabel, expiry, mode); if (refreshLabel) createForm.append(refreshLabel); createForm.append(reviewLabel, create); panel.insertBefore(createForm, list);
      reviewChecked = () => review.checked;
      const reset = () => { review.checked = false; updateControls(); };
      [consumer, purpose, expiry].forEach((input) => input.addEventListener('input', reset)); if (refresh) refresh.addEventListener('change', reset); review.addEventListener('change', updateControls);
      create.addEventListener('click', async () => {
        if (localBusy || (typeof busy === 'function' && busy()) || !loaded || !isCurrent() || !review.checked || (canCreateApiKey ? !connectorDigest : !oauth)) return;
        const expires = new Date(expiry.value).getTime(), now = Date.now();
        if (!consumer.value.trim() || !purpose.value.trim() || purpose.value !== purpose.value.trim() || new TextEncoder().encode(purpose.value).length > 256 || !Number.isFinite(expires) || expires <= now || expires > now + 30 * 24 * 60 * 60 * 1000) { message('Enter a consumer client ID, a purpose up to 256 bytes, and a future expiry within 30 days.', true); return; }
        const token = generation; setBusy(true); try {
          const grant = { consumer_client_id: consumer.value.trim(), mode: canCreateOAuth ? 'credential_delivery' : 'proxy', purpose: purpose.value, expires_at_unix_ms: expires };
          if (canCreateOAuth) { grant.credential_version = oauth.version; if (refresh.checked) grant.allow_refresh = true; } else grant.connector_digest = connectorDigest;
          await request(`${path}/grants`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf }, body: JSON.stringify(grant) });
          if (token !== generation || !isCurrent()) return; clearCreate(); if (await load(token)) message('Service access created.');
        } catch (error) { if (token === generation && isCurrent()) { review.checked = false; create.disabled = true; message(safeError(error), true); if (text(error && error.message).includes('(409)')) { loaded = false; clearCreate(); if (settings) settings.hidden = true; } } } finally { if (token === generation && isCurrent()) setBusy(false); }
      });
    } else { const pending = document.createElement('p'); pending.className = 'hint'; pending.textContent = 'Creation is pending for this collection; existing service access can still be reviewed and revoked.'; panel.insertBefore(pending, list); }
    async function load(token = generation) { try { const result = await request(`${path}/grants`).then(readJSON); if (token !== generation || !isCurrent()) return false; grants = Array.isArray(result) ? result : []; loaded = true; render(); updateControls(); return true; } catch (_) { if (token === generation && isCurrent()) message('Unable to load service access grants.', true); return false; } }
    async function revokeGrant(grant) {
      if (localBusy || (typeof busy === 'function' && busy()) || !isCurrent() || !globalThis.confirm || !globalThis.confirm(`Revoke service access for ${text(grant.consumer_client_id)}? This cannot recall requests or credentials already delivered.`)) return;
      const token = generation; setBusy(true); try { const response = await request(`${path}/grants/${encodeURIComponent(text(grant.id))}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf, 'If-Match': quoted(grant.revision) }, body: '' }); if (response.status !== 204) throw new Error(`Request failed (${response.status}).`); if (token !== generation || !isCurrent()) return; if (await load(token)) message('Service access revoked.'); } catch (error) { if (token === generation && isCurrent()) message(safeError(error), true); } finally { if (token === generation && isCurrent()) setBusy(false); }
    }
    manage.addEventListener('click', async () => { if (localBusy || (typeof busy === 'function' && busy()) || !isCurrent()) return; panel.hidden = false; manage.hidden = true; generation++; const token = generation; loaded = false; clearCreate(); setBusy(true); await load(token); await connector(token); await oauthMetadata(token); if (token === generation && isCurrent()) setBusy(false); });
    close.addEventListener('click', () => { if (localBusy || (typeof busy === 'function' && busy())) return; generation++; panel.hidden = true; manage.hidden = false; grants = []; loaded = false; clearCreate(); if (settings) settings.hidden = true; list.textContent = ''; message(''); });
    return root;
  };
})();
