(() => {
  'use strict';
  const dashboard = globalThis.accountDashboard;
  if (!dashboard || !dashboard.connectionDeps) return;
  const { request, status } = dashboard.connectionDeps;
  const state = { definitions: [], selected: '', connections: [], editing: null, busy: false, generation: 0 };
  const $ = (selector) => document.querySelector(selector);
  const section = $('#connections-section');
  if (!section) return;
  const select = $('#connections-collection');
  const form = $('#connections-form');
  const fields = $('#connections-fields');
  const list = $('#connections-list');
  const save = $('#connections-save');
  // Native JSON source context preserves int64 metadata without IEEE-754 rounding.
  const readJSON = async response => JSON.parse(await response.text(), (_key, value, context) => {
    if (typeof value !== 'number' || Number.isSafeInteger(value)) return value;
    if (!context?.source || !/^-?[0-9]+$/.test(context.source)) throw new Error('This browser cannot read the connection integer safely.');
    return BigInt(context.source);
  });

  function setBusy(busy) {
    state.busy = busy;
    $('#connections-refresh').disabled = busy;
    select.disabled = busy || !state.definitions.length;
    save.disabled = busy || !definition()?.enabled;
    $('#connections-cancel').disabled = busy;
    fields.querySelectorAll('input,select,textarea,button').forEach((el) => { el.disabled = busy; });
    list.querySelectorAll('button').forEach((el) => { if (el.dataset.oauth2Control !== undefined || el.dataset.grantControl !== undefined || el.dataset.apiKeySave !== undefined || el.dataset.apiKeyRevoke !== undefined || el.dataset.apiKeyCancel !== undefined) return; el.disabled = busy || (el.dataset.connectionEdit !== undefined && !definition()?.enabled); });
  }
  function quoted(revision) { return `"${String(revision)}"`; }
  function definition() { return state.definitions.find((item) => item.id === state.selected) || null; }
  function fieldValue(field, input) {
    if (field.type === 'boolean') return input.tagName === 'SELECT' ? input.value : (input.checked ? 'true' : 'false');
    if (field.type === 'integer') {
      const raw = input.value.trim();
      if (!/^-?(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`Enter a valid integer for ${field.name}.`);
      try { const number = BigInt(raw); if (number < -9223372036854775808n || number > 9223372036854775807n) throw new Error(); } catch (_) { throw new Error(`Enter a valid 64-bit integer for ${field.name}.`); }
      return raw;
    }
    return JSON.stringify(input.value);
  }
  function metadataJSON() {
    const def = definition();
    if (!def) throw new Error('Choose a collection first.');
    const parts = [];
    def.fields.forEach((field) => {
      const input = [...fields.querySelectorAll('[data-connection-field]')].find((candidate) => candidate.dataset.connectionField === field.name);
      if (!input) return;
      if ((field.type !== 'boolean' && input.value === '') || (field.type === 'boolean' && input.tagName === 'SELECT' && input.value === '')) {
        if (field.type === 'string' && (field.required || Object.hasOwn(state.editing?.metadata || {}, field.name))) {
          parts.push(`${JSON.stringify(field.name)}:""`);
          return;
        }
        if (field.required) throw new Error(`${field.name} is required.`);
        return;
      }
      parts.push(`${JSON.stringify(field.name)}:${fieldValue(field, input)}`);
    });
    return `{${parts.join(',')}}`;
  }
  function renderFields(values) {
    const def = definition(); fields.textContent = ''; form.hidden = !def;
    if (!def) return;
    def.fields.forEach((field) => {
      const label = document.createElement('label'); label.textContent = field.name;
      let input;
      if (field.type === 'enum') {
        input = document.createElement('select');
        if (!field.required) { const empty = document.createElement('option'); empty.value = ''; empty.textContent = 'Not set'; input.append(empty); }
        field.options.forEach((option) => { const item = document.createElement('option'); item.value = option; item.textContent = option; input.append(item); });
      } else if (field.type === 'boolean' && !field.required) {
        input = document.createElement('select'); [['', 'Not set'], ['true', 'True'], ['false', 'False']].forEach(([value, text]) => { const item = document.createElement('option'); item.value = value; item.textContent = text; input.append(item); });
      } else if (field.type === 'string') { input = document.createElement('textarea'); input.rows = 2; if (field.max_length > 0) input.maxLength = field.max_length; }
      else { input = document.createElement('input'); input.type = field.type === 'boolean' ? 'checkbox' : 'text'; }
      input.dataset.connectionField = field.name;
      const value = values && values[field.name];
      if (field.type === 'boolean' && input.tagName !== 'SELECT') input.checked = value === true;
      else if (value !== undefined && value !== null) input.value = String(value);
      label.htmlFor = `connection-field-${field.name}`; input.id = label.htmlFor;
      fields.append(label, input);
    });
    save.textContent = state.editing ? 'Save connection' : 'Create connection';
    save.disabled = state.busy || !def.enabled;
    $('#connections-cancel').hidden = !state.editing;
  }
  function renderCollections() {
    select.textContent = '';
    state.definitions.forEach((def) => { const option = document.createElement('option'); option.value = def.id; option.textContent = def.enabled ? def.name : `${def.name} (disabled)`; select.append(option); });
    select.value = state.selected;
    select.disabled = state.busy || !state.definitions.length;
  }
  function renderConnections() {
    list.textContent = '';
    if (!state.connections.length) { const empty = document.createElement('p'); empty.className = 'hint'; empty.textContent = 'No saved connections.'; list.append(empty); return; }
    state.connections.forEach((connection) => {
      const row = document.createElement('div'); row.className = 'connection-row';
      const name = document.createElement('span'); name.textContent = `${connection.id} (${connection.state || 'draft'})`;
      const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'secondary'; edit.dataset.connectionEdit = connection.id; edit.textContent = 'Edit'; edit.disabled = state.busy || !definition()?.enabled || unsafeIntegerMetadata(connection); edit.addEventListener('click', () => { if (unsafeIntegerMetadata(connection)) { status('connections-status', 'This connection contains an integer outside the browser safe range; editing is disabled.', true); return; } state.editing = connection; renderFields(connection.metadata || {}); });
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'secondary'; remove.dataset.connectionDelete = connection.id; remove.textContent = 'Delete'; remove.addEventListener('click', () => deleteConnection(connection));
      row.append(name, edit, remove);
      if (definition()?.auth_method === 'api_key' && definition()?.enabled) row.append(apiKeyControl(connection, state.generation));
      if (definition()?.auth_method === 'oauth2') row.append(connectionOauth2(connection, state.generation));
      if (dashboard.connectionGrantControl) {
        const generation = state.generation, collection = state.selected;
        row.append(dashboard.connectionGrantControl({ connection, definition: definition(), collection,
          current: () => generation === state.generation && collection === state.selected && state.connections.includes(connection),
          busy: () => state.busy, request, readJSON }));
      }
      list.append(row);
    });
  }
  function clearAPIKeyInputs() { list.querySelectorAll('[data-api-key-input]').forEach((input) => { input.value = ''; }); }
  function apiKeyError(error) { return error && String(error.message || '').includes('(409)') ? 'This API key changed elsewhere. Reload and try again.' : 'Unable to manage this API key.'; }
  function safeVersion(value) { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function apiKeyControl(connection, generation) {
    const wrapper = document.createElement('div'); wrapper.className = 'connection-api-key';
    const manage = document.createElement('button'); manage.type = 'button'; manage.className = 'secondary'; manage.dataset.connectionApiKey = String(connection.id); manage.textContent = 'Manage API key';
    const panel = document.createElement('div'); panel.hidden = true; panel.dataset.apiKeyPanel = String(connection.id);
    const label = document.createElement('label'); label.textContent = 'API key';
    const input = document.createElement('input'); input.type = 'password'; input.maxLength = 2048; input.autocomplete = 'off'; input.dataset.apiKeyInput = String(connection.id); input.disabled = true; input.id = `connection-api-key-${connection.id}`; label.htmlFor = input.id;
    const saveKey = document.createElement('button'); saveKey.type = 'button'; saveKey.className = 'secondary'; saveKey.dataset.apiKeySave = String(connection.id); saveKey.textContent = 'Save API key'; saveKey.disabled = true;
    const revoke = document.createElement('button'); revoke.type = 'button'; revoke.className = 'secondary'; revoke.dataset.apiKeyRevoke = String(connection.id); revoke.textContent = 'Revoke API key'; revoke.disabled = true;
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'secondary'; cancel.dataset.apiKeyCancel = String(connection.id); cancel.textContent = 'Cancel';
    const message = document.createElement('p'); message.className = 'hint'; message.dataset.apiKeyStatus = String(connection.id); message.setAttribute('role', 'status'); message.setAttribute('aria-live', 'polite');
    const provider = definition()?.provider_ids?.[0] || '';
    const connectorInfo = document.createElement('div'); connectorInfo.className = 'connection-key-settings'; connectorInfo.dataset.apiKeyConnector = String(connection.id); connectorInfo.hidden = !provider;
    const reviewLabel = document.createElement('label'); reviewLabel.className = 'connection-key-review'; reviewLabel.hidden = !provider;
    const review = document.createElement('input'); review.type = 'checkbox'; review.checked = false; review.disabled = true; review.dataset.apiKeyReview = String(connection.id); review.id = `connection-api-key-review-${connection.id}`; reviewLabel.htmlFor = review.id;
    const reviewText = document.createElement('span'); reviewText.textContent = 'I reviewed this provider and its allowed operations. Store my key with these settings. This does not authorize a consumer service to use it.';
    reviewLabel.append(review, reviewText);
    panel.append(connectorInfo, reviewLabel, label, input, saveKey, revoke, cancel, message); wrapper.append(manage, panel);
    let connectorDigest = '';
    let version = null; let registered = false; let loaded = false; let localBusy = false;
    const collection = state.selected; const current = () => generation === state.generation && state.selected === collection && state.connections.includes(connection);
    const clear = () => { input.value = ''; };
    const reviewed = () => !provider || (connectorDigest !== '' && review.checked);
    const setPanelBusy = (busy) => { const writable = registered || version === 0; localBusy = busy; input.disabled = busy || !loaded || !writable || !current() || !reviewed(); saveKey.disabled = input.disabled; review.disabled = busy || !loaded || !writable || !current() || !connectorDigest; revoke.disabled = busy || !loaded || !registered || version === null || !current() || version < 1; cancel.disabled = busy; manage.disabled = busy; };
    const statusText = (text, error) => { message.textContent = text; message.className = `hint${error ? ' error' : ''}`; };
    async function readStatus() {
      loaded = false; registered = false; version = null; connectorDigest = ''; review.checked = false; connectorInfo.textContent = ''; clear(); setPanelBusy(true); statusText('Checking API key status…');
      try {
        const response = await request(`/auth/v1/account/connections/${encodeURIComponent(state.selected)}/${encodeURIComponent(connection.id)}/api-key`).then(readJSON);
        if (!current()) return;
        const next = safeVersion(response && response.version); if (next === null || typeof response.registered !== 'boolean') throw new Error('unsupported status');
        if (response.registered && next < 1) throw new Error('unsupported status');
        version = next; registered = response.registered; loaded = true; input.value = '';
        if (registered) statusText('API key registered. Saving a new key rotates it.');
        else if (version > 0) statusText('API key revoked. It cannot be registered again.');
        else statusText('No API key registered.');
        if (provider) {
          try {
            const info = await request(`/auth/v1/account/connections/${encodeURIComponent(collection)}/${encodeURIComponent(connection.id)}/api-key/connector`).then(readJSON);
            if (!current()) return;
            if (info?.id !== provider || typeof info.digest !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(info.digest) || !Array.isArray(info.operations) || !info.operations.length || info.operations.length > 32 || typeof info.header !== 'string' || typeof info.prefix !== 'string' || info.operations.some(op => typeof op.id !== 'string' || typeof op.method !== 'string' || typeof op.url !== 'string')) throw new Error('unsupported connector');
            connectorInfo.textContent = `Provider: ${info.id}\nKey header: ${info.header} (${info.prefix || 'no prefix'})\nAllowed operations:\n${info.operations.map(op => `${op.id}: ${op.method} ${op.url}\nResponse fields: ${JSON.stringify(op.response_fields || {})}`).join('\n')}\nSettings digest: ${info.digest}`;
            connectorDigest = info.digest;
          } catch (_) { if (current()) statusText('Unable to load provider settings. Close and reopen to review them before saving. An existing key can still be revoked.', true); }
        }
      } catch (error) { if (current()) statusText('Unable to load API key status.', true); }
      finally { if (current()) setPanelBusy(false); }
    }
    async function saveKeyValue() {
      const key = input.value; input.value = '';
      if (state.busy || localBusy || !loaded || version === null || version > Number.MAX_SAFE_INTEGER || !(registered || version === 0) || !current() || !reviewed()) return;
      if (!key || key.length > 2048) { statusText('Enter an API key up to 2048 characters.', true); return; }
      setPanelBusy(true); try {
        const body = JSON.stringify({ api_key: key, version, ...(provider ? { connector_digest: connectorDigest } : {}) });
        const response = await request(`/auth/v1/account/connections/${encodeURIComponent(state.selected)}/${encodeURIComponent(connection.id)}/api-key`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf }, body }).then(readJSON);
        if (!current()) return;
        const next = safeVersion(response && response.version); if (next === null || next !== version + 1 || response.registered !== true) throw new Error('unsupported response');
        version = next; registered = true; statusText('API key saved.'); input.value = '';
      } catch (error) { if (current()) { review.checked = false; if (provider) connectorDigest = ''; statusText(apiKeyError(error) + (provider ? ' Close and reopen to review provider settings again.' : ''), true); } }
      finally { clear(); if (current()) setPanelBusy(false); }
    }
    async function revokeKey() {
      clear(); if (state.busy || localBusy || !loaded || !registered || version === null || version < 1 || !current() || !globalThis.confirm || !globalThis.confirm('Revoke this API key locally? This only revokes it in GoAuthy; the provider key is unchanged.')) return;
      setPanelBusy(true); try {
        await request(`/auth/v1/account/connections/${encodeURIComponent(state.selected)}/${encodeURIComponent(connection.id)}/api-key`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf }, body: JSON.stringify({ version }) });
        if (!current()) return; registered = false; loaded = true; statusText('API key revoked locally. It cannot be registered again.');
      } catch (error) { if (current()) statusText(apiKeyError(error), true); }
      finally { clear(); if (current()) setPanelBusy(false); }
    }
    manage.addEventListener('click', async () => { if (state.busy || localBusy || !current()) return; panel.hidden = false; manage.hidden = true; await readStatus(); });
    cancel.addEventListener('click', () => { if (localBusy) return; clear(); review.checked = false; connectorDigest = ''; panel.hidden = true; manage.hidden = false; statusText(''); });
    review.addEventListener('change', () => { if (!localBusy) { clear(); setPanelBusy(false); } });
    saveKey.addEventListener('click', saveKeyValue); revoke.addEventListener('click', revokeKey);
    return wrapper;
  }
  function connectionOauth2(connection, generation) {
    const def = definition();
    const wrapper = document.createElement('div'); wrapper.className = 'connection-api-key';
    const mark = (button) => { button.dataset.oauth2Control = String(connection.id); return button; };
    const manage = mark(document.createElement('button')); manage.type = 'button'; manage.className = 'secondary'; manage.dataset.connectionOauth2 = String(connection.id); manage.textContent = 'Manage OAuth';
    const panel = document.createElement('div'); panel.hidden = true; panel.dataset.oauth2Panel = String(connection.id);
    const clearMetadata = () => { delete panel.dataset.oauth2State; delete panel.dataset.oauth2Version; };
    const statusMessage = document.createElement('p'); statusMessage.className = 'hint'; statusMessage.dataset.oauth2Status = String(connection.id); statusMessage.setAttribute('role', 'status'); statusMessage.setAttribute('aria-live', 'polite');
    const providerLabel = document.createElement('label'); providerLabel.textContent = 'Provider'; providerLabel.htmlFor = `connection-oauth2-provider-${connection.id}`;
    const provider = document.createElement('select'); provider.id = providerLabel.htmlFor; provider.dataset.oauth2Provider = String(connection.id);
    const providerIds = Array.isArray(def?.provider_ids) ? def.provider_ids.filter((id) => typeof id === 'string' && id !== '') : [];
    providerIds.forEach((id) => { const option = document.createElement('option'); option.value = id; option.textContent = id; provider.append(option); });
    provider.value = providerIds[0] || '';
    const start = mark(document.createElement('button')); start.type = 'button'; start.className = 'secondary'; start.dataset.oauth2Start = String(connection.id); start.textContent = 'Start authorization';
    const continueButton = document.createElement('a'); continueButton.dataset.oauth2Continue = String(connection.id); continueButton.textContent = 'Open provider authorization'; continueButton.target = '_blank'; continueButton.rel = 'noopener noreferrer'; continueButton.hidden = true;
    const check = mark(document.createElement('button')); check.type = 'button'; check.className = 'secondary'; check.dataset.oauth2Check = String(connection.id); check.textContent = 'Check status';
    const refresh = mark(document.createElement('button')); refresh.type = 'button'; refresh.className = 'secondary'; refresh.dataset.oauth2Refresh = String(connection.id); refresh.textContent = 'Refresh access';
    const revoke = mark(document.createElement('button')); revoke.type = 'button'; revoke.className = 'secondary'; revoke.dataset.oauth2Revoke = String(connection.id); revoke.textContent = 'Revoke locally';
    const reconnect = mark(document.createElement('button')); reconnect.type = 'button'; reconnect.className = 'secondary'; reconnect.dataset.oauth2Reconnect = String(connection.id); reconnect.textContent = 'Prepare reconnect';
    const close = mark(document.createElement('button')); close.type = 'button'; close.className = 'secondary'; close.dataset.oauth2Close = String(connection.id); close.textContent = 'Close';
    const collection = state.selected; const current = () => generation === state.generation && state.selected === collection && state.connections.includes(connection);
    let loaded = false; let localBusy = false; let failed = false; let version = null; let oauthState = ''; let oauthProvider = '';
    const clearLink = () => { continueButton.hidden = true; continueButton.removeAttribute('href'); };
    const statusText = (text, error) => { statusMessage.textContent = text; statusMessage.className = `hint${error ? ' error' : ''}`; };
    const validURL = (value) => { if (typeof value !== 'string' || value.length > 4096 || /[\x00-\x20\x7f]/.test(value)) return false; try { const url = new URL(value); return url.protocol === 'https:' && url.hostname !== '' && url.username === '' && url.password === '' && !url.hash; } catch (_) { return false; } };
    const validStatus = (value) => {
      if (!value || typeof value !== 'object' || !['draft', 'ready', 'refreshing', 'uncertain', 'revoked', 'reconnecting'].includes(value.state)) return false;
      const next = safeVersion(value.version); if (next === null || (value.state !== 'draft' && next < 1) || (value.state === 'draft' && next !== 0)) return false;
      if (typeof value.connected !== 'boolean' || typeof value.provider_id !== 'string' || !Array.isArray(value.scopes) || value.scopes.length > 64 || value.scopes.some((scope) => typeof scope !== 'string' || scope.length > 256 || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) return false;
      if (value.state === 'ready' && (!value.connected || typeof value.account_id !== 'string' || !value.account_id || !value.provider_id)) return false;
      if (value.state !== 'ready' && value.connected) return false;
      return true;
    };
    const setPanelBusy = (busy) => {
      localBusy = busy;
      const blocked = busy || state.busy || !current() || !loaded || failed;
      provider.disabled = blocked || !providerIds.length;
      start.disabled = blocked || !def.enabled || !providerIds.length || !['draft', 'reconnecting'].includes(oauthState);
      check.disabled = busy || state.busy || !current();
      refresh.disabled = blocked || !def.enabled || !providerIds.includes(oauthProvider) || oauthState !== 'ready'; revoke.disabled = blocked || !['ready', 'refreshing', 'uncertain'].includes(oauthState);
      reconnect.disabled = blocked || !def.enabled || oauthState !== 'revoked'; close.disabled = busy; manage.disabled = busy;
    };
    const renderState = (value) => {
      version = safeVersion(value.version); oauthState = value.state; oauthProvider = value.provider_id; loaded = true; panel.dataset.oauth2State = value.state; panel.dataset.oauth2Version = String(value.version); clearLink();
      const providerText = value.provider_id ? ` Provider: ${value.provider_id}.` : '';
      if (value.state === 'draft') statusText(`Authorization has not started.${providerText}`);
      else if (value.state === 'ready') statusText(`OAuth connection ready.${providerText} Account: ${value.account_id}. Scopes: ${value.scopes.join(', ') || 'none'}.`);
      else if (value.state === 'revoked') statusText('OAuth connection revoked locally. Provider tokens are unaffected. Prepare reconnect to authorize again.');
      else if (value.state === 'reconnecting') statusText('Reconnect is prepared. Start a new authorization.');
      else if (value.state === 'uncertain') statusText('The last exchange outcome is uncertain. Do not retry it. Check status, or revoke locally and reconnect.');
      else statusText('OAuth refresh is in progress. Check status before any further action, or revoke locally.');
      start.hidden = !['draft', 'reconnecting'].includes(value.state); reconnect.hidden = value.state !== 'revoked'; refresh.hidden = value.state !== 'ready'; revoke.hidden = !['ready', 'refreshing', 'uncertain'].includes(value.state); continueButton.hidden = true;
      setPanelBusy(false);
    };
    async function readStatus() {
      if (state.busy || localBusy || !current() || panel.hidden) return;
      loaded = false; failed = false; version = null; oauthState = ''; clearMetadata(); clearLink(); setPanelBusy(true); statusText('Checking OAuth status…');
      try { const value = await request(`/auth/v1/account/connections/${encodeURIComponent(collection)}/${encodeURIComponent(connection.id)}/oauth2`).then(readJSON); if (!current()) return; if (!validStatus(value)) throw new Error('unsupported status'); renderState(value); }
      catch (_) { if (current()) { failed = true; clearMetadata(); statusText('Unable to load OAuth status. Check status to try again.', true); setPanelBusy(false); } }
    }
    async function mutate(kind) {
      if (state.busy || localBusy || failed || !loaded || version === null || !current() || panel.hidden) return;
      if (kind === 'start' && !providerIds.includes(provider.value)) return;
      if (kind === 'start' && (!def.enabled || !['draft', 'reconnecting'].includes(oauthState)) || kind === 'refresh' && (!def.enabled || !providerIds.includes(oauthProvider) || oauthState !== 'ready') || kind === 'reconnect' && (!def.enabled || oauthState !== 'revoked') || kind === 'revoke' && !['ready', 'refreshing', 'uncertain'].includes(oauthState)) return;
      const path = `/auth/v1/account/connections/${encodeURIComponent(collection)}/${encodeURIComponent(connection.id)}/oauth2${kind === 'refresh' ? '/refresh' : kind === 'reconnect' ? '/reconnect' : ''}`;
      const options = { method: kind === 'revoke' ? 'DELETE' : 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf }, body: JSON.stringify(kind === 'start' ? { provider_id: provider.value } : { version }) };
      if (kind === 'revoke' && (!globalThis.confirm || !globalThis.confirm('Revoke this OAuth connection locally? Provider tokens are unaffected.'))) return;
      if (kind === 'reconnect' && (!globalThis.confirm || !globalThis.confirm('Prepare this connection to reconnect? You will need to start authorization separately.'))) return;
      if (kind === 'refresh' && (!globalThis.confirm || !globalThis.confirm('Refresh access with the provider now? This sends one token exchange; an uncertain result must not be retried.'))) return;
      setPanelBusy(true);
      try {
        const value = await request(path, options).then((response) => { if (kind !== 'revoke') return readJSON(response); if (response.status !== 204) throw new Error('unsupported revoke response'); return null; }); if (!current()) return;
        if (kind === 'revoke') { renderState({ state: 'revoked', version, connected: false, provider_id: '', scopes: [] }); return; }
        if (kind === 'start') { if (!validURL(value?.authorization_url)) throw new Error('unsafe authorization URL'); continueButton.href = value.authorization_url; continueButton.hidden = false; loaded = false; start.hidden = true; statusText('Open authorization in a new tab, return here, then check status.'); setPanelBusy(false); return; }
        if (!validStatus(value) || (kind === 'refresh' && (value.state !== 'ready' || value.version !== version + 1)) || (kind === 'reconnect' && (value.state !== 'reconnecting' || value.version !== version))) throw new Error('unsupported response'); renderState(value);
      } catch (_) { if (current()) { failed = true; clearMetadata(); clearLink(); statusText('OAuth action failed. Check status before trying again.', true); setPanelBusy(false); } }
    }
    panel.append(statusMessage, providerLabel, provider, start, continueButton, check, refresh, revoke, reconnect, close); wrapper.append(manage, panel);
    manage.addEventListener('click', async () => { if (state.busy || localBusy || !current()) return; panel.hidden = false; manage.hidden = true; await readStatus(); });
    close.addEventListener('click', () => { if (state.busy || localBusy) return; loaded = false; clearMetadata(); clearLink(); panel.hidden = true; manage.hidden = false; });
    check.addEventListener('click', readStatus); start.addEventListener('click', () => mutate('start')); refresh.addEventListener('click', () => mutate('refresh')); revoke.addEventListener('click', () => mutate('revoke')); reconnect.addEventListener('click', () => mutate('reconnect'));
    setPanelBusy(false);
    return wrapper;
  }
  function unsafeIntegerMetadata(connection) {
    const def = definition(); const metadata = connection && connection.metadata;
    return Boolean(def && metadata && def.fields.some((field) => field.type === 'integer' && typeof metadata[field.name] === 'number' && !Number.isSafeInteger(metadata[field.name])));
  }
  async function loadConnections() {
    const collection = state.selected; const generation = ++state.generation; clearAPIKeyInputs(); state.connections = []; state.editing = null; renderConnections(); renderFields(null); setBusy(true);
    try { const result = await request(`/auth/v1/account/connections/${encodeURIComponent(collection)}`).then(readJSON); if (generation !== state.generation) return; state.connections = Array.isArray(result) ? result : []; renderConnections(); } catch (error) { if (generation === state.generation) status('connections-status', error.message, true); } finally { if (generation === state.generation) setBusy(false); }
  }
  async function loadDefinitions() {
    const generation = ++state.generation, previousSelection = state.selected;
    clearAPIKeyInputs(); state.definitions = []; state.selected = ''; state.connections = []; state.editing = null;
    renderCollections(); renderConnections(); renderFields(null); setBusy(true);
    try {
      const result = await request('/auth/v1/account/auth-collections').then(readJSON);
      if (generation !== state.generation) return;
      state.definitions = Array.isArray(result) ? result : []; section.hidden = false;
      state.selected = state.definitions.some((item) => item.id === previousSelection) ? previousSelection : state.definitions[0]?.id || '';
      renderCollections(); if (state.selected) await loadConnections(); else { renderFields(null); renderConnections(); }
    } catch (error) { if (generation === state.generation) { section.hidden = false; status('connections-status', error.message, true); } }
    finally { if (generation === state.generation) setBusy(false); }
  }
  async function saveConnection(event) {
    event.preventDefault(); if (state.busy || !state.selected) return; let metadata;
    try { metadata = metadataJSON(); } catch (error) { status('connections-status', error.message, true); return; }
    const def = definition(); if (!def || !def.enabled) { status('connections-status', 'This collection is disabled; new connections cannot be saved.', true); return; }
    setBusy(true); const editing = state.editing; try {
      const body = `{"definition_revision":${def.revision},"metadata":${metadata}}`;
      const path = editing ? `/auth/v1/account/connections/${encodeURIComponent(state.selected)}/${encodeURIComponent(editing.id)}` : `/auth/v1/account/connections/${encodeURIComponent(state.selected)}`;
      const options = editing ? { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf, 'If-Match': quoted(editing.revision) }, body } : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf }, body };
      await request(path, options); state.editing = null; await loadConnections(); status('connections-status', editing ? 'Connection saved.' : 'Connection created.');
    } catch (error) { status('connections-status', error.message.includes('(409)') ? 'This connection changed elsewhere. Reload and try again.' : error.message, true); } finally { setBusy(false); }
  }
  async function deleteConnection(connection) {
    if (state.busy || !state.selected || !globalThis.confirm || !globalThis.confirm(`Delete connection “${connection.id}”?`)) return;
    setBusy(true); try { await request(`/auth/v1/account/connections/${encodeURIComponent(state.selected)}/${encodeURIComponent(connection.id)}`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': dashboard.state.csrf, 'If-Match': quoted(connection.revision) }, body: '' }); await loadConnections(); status('connections-status', 'Connection deleted.'); } catch (error) { status('connections-status', error.message.includes('(409)') ? 'This connection changed elsewhere. Reload and try again.' : error.message, true); } finally { setBusy(false); }
  }
  select.addEventListener('change', () => { if (state.busy) return; state.selected = select.value; loadConnections(); });
  form.addEventListener('submit', saveConnection); $('#connections-cancel').addEventListener('click', () => { if (state.busy) return; state.editing = null; renderFields(null); }); $('#connections-refresh').addEventListener('click', () => { if (!state.busy) loadDefinitions(); });
  if (globalThis.addEventListener) globalThis.addEventListener('pagehide', clearAPIKeyInputs);
  dashboard.ready.then(loadDefinitions);
  dashboard.connections = { state, loadDefinitions, loadConnections, saveConnection, deleteConnection };
})();
