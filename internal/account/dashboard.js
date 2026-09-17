(() => {
  'use strict';
  const state = { account: null, csrf: '', attributes: [], attributeValues: {}, attributesLoaded: false, passkeys: [], passkeysLoaded: false, passkeyBusy: false, actionBusy: false, selfDeleteAllowed: false };
  const $ = (selector) => document.querySelector(selector);
  const status = (id, message, error) => { const el = document.getElementById(id); if (el) { el.textContent = message; el.className = `status${error ? ' error' : ''}`; } };
  const basePath = () => { const path = window.location.pathname; const marker = path.lastIndexOf('/account'); return marker < 0 ? '' : path.slice(0, marker); };
  const endpoint = (path) => `${basePath()}${path}`;
  const request = (url, options = {}) => fetch(endpoint(url), Object.assign({ credentials: 'same-origin' }, options)).then(async (response) => {
    if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? 'Your session has expired. Sign in again.' : `Request failed (${response.status}).`);
    return response;
  });
  const jsonRequest = (url, method, body) => request(url, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, body: JSON.stringify(body) });
  const subjectPath = () => `/auth/v1/users/${encodeURIComponent(state.account.subject)}`;
  const webauthnAvailable = (operation) => Boolean(globalThis.navigator && navigator.credentials && navigator.credentials[operation] && globalThis.PublicKeyCredential && typeof globalThis.PublicKeyCredential[`parse${operation === 'create' ? 'Creation' : 'Request'}OptionsFromJSON`] === 'function');

  function displayProfile(account) {
    const profile = $('#profile'); profile.textContent = '';
    const heading = document.createElement('h2'); heading.id = 'profile-heading'; heading.textContent = [account.given_name, account.family_name].filter(Boolean).join(' ') || account.email || 'Your profile'; profile.append(heading);
    const email = document.createElement('p'); email.textContent = account.email || ''; profile.append(email);
    if (account.email_verified === false) { const note = document.createElement('p'); note.className = 'hint'; note.textContent = 'Email address is not verified.'; profile.append(note); }
    $('#preferred-username').value = account.preferred_username || '';
    $('#password-section').hidden = Boolean(account.features && account.features.password === false);
    const conversion = $('#passwordless-section'); conversion.hidden = !(account.features && account.features.password && account.features.passkeys && state.passkeys.length); updateConversionControl();
    $('#passwordless-hint').textContent = account.features && account.features.passkey_conversion ? 'This requires an enrolled passkey and will remove password sign-in.' : 'Use a registered passkey to sign in again before converting.';
    $('#password-restore-section').hidden = !(account.features && account.features.password === false);
  }

  async function convertPasswordless() { if (state.actionBusy || state.passkeyBusy || !state.passkeysLoaded || !state.account || !state.account.features.passkey_conversion) return; if (!globalThis.confirm || !globalThis.confirm('Turn off password sign-in for this account?')) return; state.actionBusy = true; $('#passwordless-convert').disabled = true; try { await request(`${subjectPath()}/self/convert_passkey`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf } }); await refreshAccount(); status('passwordless-status', 'Password sign-in disabled.'); } catch (error) { status('passwordless-status', error.message, true); $('#passwordless-convert').disabled = false; } finally { state.actionBusy = false; displayProfile(state.account); setPasskeyBusy(false); } }

  async function restorePassword(event) { event.preventDefault(); if (state.actionBusy || state.passkeyBusy || !state.account || state.account.features?.password !== false) return; let next = $('#password-restore-new').value; const confirmNext = $('#password-restore-confirm').value; if (!next || next !== confirmNext) { status('password-restore-status', 'Passwords do not match.', true); return; } if (!webauthnAvailable('get')) { status('password-restore-status', 'Passkeys are unavailable in this browser.', true); return; } state.actionBusy = true; $('#password-restore-submit').disabled = true; let proof = ''; try { const start = await jsonRequest(`${subjectPath()}/webauthn/auth/start`, 'POST', { purpose: 'PasswordNew' }).then((r) => r.json()); const assertion = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(start.rcr.publicKey) }); if (!assertion) throw new Error('Passkey authorization cancelled.'); if (typeof assertion.toJSON !== 'function') throw new Error('This browser cannot serialize passkey credentials.'); const finish = await jsonRequest(`${subjectPath()}/webauthn/auth/finish`, 'POST', { code: start.code, data: assertion.toJSON() }).then((r) => r.json()); proof = finish.code; await jsonRequest(`${subjectPath()}/self`, 'PUT', { mfa_code: proof, password_new: next }); await refreshAccount(); status('password-restore-status', 'Password sign-in restored.'); } catch (error) { status('password-restore-status', error.message, true); } finally { proof = ''; next = ''; $('#password-restore-new').value = ''; $('#password-restore-confirm').value = ''; $('#password-restore-submit').disabled = false; state.actionBusy = false; setPasskeyBusy(false); } }

  async function checkSelfDelete() { state.selfDeleteAllowed = false; try { const response = await request(`${subjectPath()}/self/delete`); state.selfDeleteAllowed = response.status === 202; $('#self-delete-section').hidden = !state.selfDeleteAllowed; $('#self-delete-button').disabled = !state.selfDeleteAllowed || !$('#self-delete-confirm').value || $('#self-delete-confirm').value !== state.account.email; } catch (error) { $('#self-delete-section').hidden = error.message === 'Request failed (406).'; $('#self-delete-button').disabled = true; status('self-delete-status', error.message, true); } }
  async function deleteAccount() { if (state.actionBusy || state.passkeyBusy || !state.selfDeleteAllowed || !state.account || !state.account.email || $('#self-delete-confirm').value !== state.account.email) return; if (!globalThis.confirm || !globalThis.confirm('Delete your account permanently?')) return; state.actionBusy = true; $('#self-delete-button').disabled = true; try { const response = await request(`${subjectPath()}/self/delete`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, body: '' }); if (response.status !== 204) throw new Error(`Account deletion was not completed (${response.status}).`); document.querySelector('main').textContent = ''; const done = document.createElement('h1'); done.id = 'account-deleted'; done.textContent = 'Account deleted'; document.querySelector('main').append(done); state.account = null; state.csrf = ''; state.selfDeleteAllowed = false; } catch (error) { status('self-delete-status', error.message, true); $('#self-delete-button').disabled = false; state.actionBusy = false; } }

  function renderAttributes(items) {
    state.attributesLoaded = true;
    $('#attributes-form button').disabled = false;
    const section = $('#attributes-section'); const container = $('#attributes'); container.textContent = '';
    if (!Array.isArray(items) || items.length === 0) return; section.hidden = false;
    items.forEach((item) => {
      const label = document.createElement('label'); label.htmlFor = `attribute-${item.name}`; label.textContent = item.desc || item.name;
      const input = document.createElement('input'); input.id = label.htmlFor; input.name = item.name; input.dataset.attribute = item.name; input.type = item.typ === 'email' ? 'email' : 'text';
      if (item.value !== undefined) { const value = item.value; state.attributeValues[item.name] = value; if (typeof value === 'string' || typeof value === 'number') input.value = value; else if (value !== null) input.value = JSON.stringify(value); }
      container.append(label, input);
    });
  }

  function renderPasskeys(items) {
    state.passkeys = Array.isArray(items) ? items : []; const list = $('#passkeys-list'); list.textContent = ''; $('#passkey-current-password').hidden = state.passkeys.length > 0; $('#passkey-current-password-label').hidden = state.passkeys.length > 0; if (state.account) displayProfile(state.account);
    if (!state.passkeys.length) { const empty = document.createElement('p'); empty.className = 'hint'; empty.textContent = 'No passkeys registered.'; list.append(empty); return; }
    state.passkeys.forEach((item) => { const row = document.createElement('div'); row.className = 'passkey-row'; const name = document.createElement('span'); name.textContent = item.name; const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'secondary'; remove.dataset.passkeyDelete = item.name; remove.textContent = 'Remove'; remove.addEventListener('click', () => deletePasskey(item.name, remove)); row.append(name, remove); list.append(row); });
  }

  function setPasskeyBusy(busy) { state.passkeyBusy = busy; updateConversionControl(); const disabled = busy || !state.passkeysLoaded || state.actionBusy; $('#passkey-add').disabled = disabled; $('#passkey-name').disabled = disabled; $('#passkey-current-password').disabled = disabled; $('#passkeys-list').querySelectorAll('button').forEach((button) => { button.disabled = disabled; }); if (busy) status('passkey-status', 'Waiting for passkey verification…'); }
  function updateConversionControl() { $('#passwordless-convert').disabled = state.actionBusy || state.passkeyBusy || !state.passkeysLoaded || !state.account?.features?.passkey_conversion || !state.passkeys.length; }
  async function modificationToken() {
    let secret = '';
    try {
      if (!state.passkeysLoaded) throw new Error('Passkeys are still loading. Try again.');
      if (!state.passkeys.length) { secret = $('#passkey-current-password').value; if (!secret) throw new Error('Enter your current password.'); return (await jsonRequest(`${subjectPath()}/mfa_token`, 'POST', { password: secret })).json().then((result) => result.id); }
      if (!webauthnAvailable('get')) throw new Error('Passkeys are unavailable in this browser.');
      const start = await jsonRequest(`${subjectPath()}/webauthn/auth/start`, 'POST', { purpose: 'MfaModToken' }).then((r) => r.json());
      const assertion = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(start.rcr.publicKey) });
      if (!assertion) throw new Error('Passkey authorization cancelled.');
      if (typeof assertion.toJSON !== 'function') throw new Error('This browser cannot serialize passkey credentials.');
      const finish = await jsonRequest(`${subjectPath()}/webauthn/auth/finish`, 'POST', { code: start.code, data: assertion.toJSON() }).then((r) => r.json());
      return (await jsonRequest(`${subjectPath()}/mfa_token`, 'POST', { mfa_code: finish.code })).json().then((result) => result.id);
    } finally { secret = ''; }
  }

  async function addPasskey(event) {
    if (state.actionBusy) { event.preventDefault(); return; }
    event.preventDefault(); if (!state.account || state.passkeyBusy) return; if (!webauthnAvailable('create')) { status('passkey-status', 'Passkeys are unavailable in this browser.', true); return; } const name = $('#passkey-name').value.trim(); if (!name) { status('passkey-status', 'Enter a name for this passkey.', true); return; }
    setPasskeyBusy(true); let token = ''; let credential = null; try { token = await modificationToken(); const start = await jsonRequest(`${subjectPath()}/webauthn/register/start`, 'POST', { passkey_name: name, mfa_mod_token_id: token }).then((r) => r.json()); credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(start.publicKey) }); if (!credential || typeof credential.toJSON !== 'function') throw new Error('This browser cannot serialize passkey credentials.'); await jsonRequest(`${subjectPath()}/webauthn/register/finish`, 'POST', { passkey_name: name, data: credential.toJSON() }); await refreshAccount(); await loadPasskeys(); $('#passkey-name').value = ''; $('#passkey-current-password').value = ''; status('passkey-status', 'Passkey added.'); } catch (error) { status('passkey-status', error.message, true); } finally { token = ''; credential = null; $('#passkey-current-password').value = ''; setPasskeyBusy(false); }
  }

  async function deletePasskey(name, button) { if (state.actionBusy || !state.account || state.passkeyBusy || !state.passkeysLoaded) return; if (!globalThis.confirm || !globalThis.confirm(`Remove passkey “${name}”?`)) return; setPasskeyBusy(true); if (button) button.disabled = true; let token = ''; try { token = await modificationToken(); await jsonRequest(`${subjectPath()}/webauthn/delete/${encodeURIComponent(name)}`, 'DELETE', { mfa_mod_token_id: token }); await loadPasskeys(); status('passkey-status', 'Passkey removed.'); } catch (error) { status('passkey-status', error.message, true); } finally { token = ''; $('#passkey-current-password').value = ''; setPasskeyBusy(false); } }
  async function loadPasskeys() { state.passkeysLoaded = false; setPasskeyBusy(state.passkeyBusy); const items = await request(`${subjectPath()}/webauthn`).then((r) => r.json()); renderPasskeys(items); state.passkeysLoaded = true; displayProfile(state.account); setPasskeyBusy(state.passkeyBusy); }

  async function refreshAccount() {
    const account = await request('/account/data').then((r) => r.json());
    state.account = account; state.csrf = account.csrf_token || ''; displayProfile(account);
    return account;
  }

  async function load() {
    state.attributesLoaded = false;
    $('#attributes-form button').disabled = true;
    try {
      const account = await refreshAccount(); const passkeySection = $('#passkeys-section'); passkeySection.hidden = !(account.features && account.features.passkeys); if (account.features && account.features.passkeys) { $('#passkeys-unsupported').hidden = webauthnAvailable('create') && webauthnAvailable('get'); try { await loadPasskeys(); } catch (error) { state.passkeysLoaded = false; status('passkey-status', 'Unable to load passkeys.', true); } }
      if (account.subject) { try { const result = await request(`/auth/v1/users/${encodeURIComponent(account.subject)}/attr/editable`).then((r) => r.json()); state.attributes = result.values || []; renderAttributes(state.attributes); } catch (_) { $('#attributes-section').hidden = false; status('attributes-status', 'Unable to load editable details.', true); } } await checkSelfDelete();
    } catch (error) { $('#profile').textContent = error.message; }
  }

  async function submitUsername(event) {
    event.preventDefault(); if (!state.account) return;
    try { await jsonRequest(`/auth/v1/users/${encodeURIComponent(state.account.subject)}/self/preferred_username`, 'PUT', { preferred_username: $('#preferred-username').value || null }); status('username-status', 'Username saved.'); }
    catch (error) { status('username-status', error.message, true); }
  }

  async function submitPassword(event) {
    event.preventDefault(); if (!state.account) return;
    const current = $('#password-current').value; const next = $('#password-new').value;
    if (next !== $('#password-confirm').value) { status('password-status', 'New passwords do not match.', true); return; }
    try { await jsonRequest(`/auth/v1/users/${encodeURIComponent(state.account.subject)}/self`, 'PUT', { password_current: current, password_new: next }); event.target.reset(); status('password-status', 'Password changed. Use the new password the next time you sign in.'); }
    catch (error) { status('password-status', error.message, true); }
  }

  async function submitAttributes(event) {
    event.preventDefault(); if (!state.account) return;
    if (!state.attributesLoaded) { status('attributes-status', 'Reload the page to load your details before saving.', true); return; }
    let values;
    try { values = [...event.target.querySelectorAll('[data-attribute]')].map((input) => { if (input.value === '') return { key: input.dataset.attribute, value: null }; const prior = state.attributeValues[input.dataset.attribute]; const value = prior !== null && typeof prior === 'object' ? JSON.parse(input.value) : (typeof prior === 'number' || typeof prior === 'boolean' ? JSON.parse(input.value) : input.value); return { key: input.dataset.attribute, value }; }); }
    catch (_) { status('attributes-status', 'Enter valid JSON for structured details.', true); return; }
    try { await jsonRequest(`/auth/v1/users/${encodeURIComponent(state.account.subject)}/attr`, 'PUT', { values }); status('attributes-status', 'Details saved.'); }
    catch (error) { status('attributes-status', error.message, true); }
  }

  $('#username-form').addEventListener('submit', submitUsername); $('#password-form').addEventListener('submit', submitPassword); $('#attributes-form').addEventListener('submit', submitAttributes); $('#passkey-form').addEventListener('submit', addPasskey); $('#passwordless-convert').addEventListener('click', convertPasswordless); $('#password-restore-form').addEventListener('submit', restorePassword); $('#self-delete-button').addEventListener('click', deleteAccount); $('#self-delete-confirm').addEventListener('input', () => { $('#self-delete-button').disabled = !state.selfDeleteAllowed || state.actionBusy || !state.account || $('#self-delete-confirm').value !== state.account.email; });
  globalThis.accountDashboard = { displayProfile, renderAttributes, renderPasskeys, submitUsername, submitPassword, submitAttributes, addPasskey, deletePasskey, loadPasskeys, convertPasswordless, restorePassword, checkSelfDelete, deleteAccount, load, state, connectionDeps: { request, jsonRequest, endpoint, status } };
  globalThis.accountDashboard.ready = load();
})();
