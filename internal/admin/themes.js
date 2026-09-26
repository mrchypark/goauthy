async function clientTheme(id) {
  const t = globalThis.GoAuthyI18n?.t || ((key, values = {}) => String(key).replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match));
  const h = (key, values) => esc(t(key, values));
  const clientID = String(id ?? ''), endpoint = '/auth/v1/theme/' + encodeURIComponent(clientID);
  const colorFields = ['text', 'text_high', 'bg', 'bg_high', 'action', 'accent', 'error'];
  const colorLabels = {text: 'Text', text_high: 'Strong text', bg: 'Background', bg_high: 'Raised background', action: 'Action', accent: 'Accent', error: 'Error'};
  const invalidPreviewMessage = t('The preview omits invalid CSS values; your input is kept for server validation.');
  let theme = null, mode = 'light', inherited = false, pending = false;

  shell(t('Client login theme'), t('Customize the sign-in logo, text, layout, and appearance for this OAuth client.'),
    `<p><a class="button secondary" href="/auth/v1/admin/clients">${h('Back to clients')}</a></p><div class="theme-workspace"><section class="panel theme-editor"><p id="theme-notice" class="hint theme-notice" role="status"></p><div id="theme-status" class="theme-status" role="status"></div><div class="theme-mode" role="group" aria-label="${h('Preview mode')}"><button type="button" data-theme-mode="light" aria-pressed="true">${h('Light')}</button><button type="button" data-theme-mode="dark" aria-pressed="false">${h('Dark')}</button></div><div id="theme-fields"></div><div class="theme-actions actions"><button id="theme-save" type="button">${h('Save theme')}</button><button id="theme-reload" class="button secondary" type="button">${h('Reload saved')}</button><button id="theme-reset" class="button secondary" type="button">${h('Reset to inherited theme')}</button></div><div id="theme-reset-review" hidden><p class="warning">${h('Remove this client theme and inherit the global theme?')}</p><div class="actions"><button id="theme-reset-confirm" type="button">${h('Confirm reset')}</button><button id="theme-reset-cancel" type="button" class="button secondary">${h('Cancel')}</button></div></div><section class="theme-logo"><h3>${h('Client logo')}</h3><p class="hint">${h('Logo changes save immediately and are separate from theme settings.')}</p><img id="theme-logo-image" alt="${h('Current client logo')}" hidden><label>${h('Upload logo (PNG, JPEG, or SVG; up to 10 MiB)')}<input id="theme-logo-upload" type="file" accept="image/png,image/jpeg,image/svg+xml"></label><button id="theme-logo-delete" type="button" class="button secondary">${h('Remove client logo')}</button><div id="theme-logo-remove-review" hidden><p class="warning">${h('Remove this client logo?')}</p><div class="actions"><button id="theme-logo-remove-confirm" type="button">${h('Confirm removal')}</button><button id="theme-logo-remove-cancel" type="button" class="button secondary">${h('Cancel')}</button></div></div><div id="theme-logo-status" class="theme-status" role="status"></div></section></section><section class="theme-preview" aria-label="${h('Sign-in preview sample')}"><h2>${h('Preview')}</h2><p class="hint">${h('Sample only. It does not submit credentials or represent the full sign-in flow.')}</p><iframe id="theme-preview-frame" class="theme-preview-frame" title="${h('Client theme preview')}" sandbox="allow-same-origin"></iframe></section></div>`);

  const by = key => document.getElementById(key), status = by('theme-status'), fields = by('theme-fields'), frame = by('theme-preview-frame');
  let copyLanguage = 'en', logoVersion = Date.now(), logoPending = false;
  const logoURL = () => `/auth/v1/clients/${encodeURIComponent(clientID)}/logo?v=${logoVersion}`;
  const syncPreviewLogo = () => {
    const image = by('theme-logo-image'), previewImage = frame.contentDocument?.getElementById('theme-logo-image');
    if (!image || !previewImage) return;
    const loaded = image.complete && image.naturalWidth > 0;
    image.hidden = !loaded;
    previewImage.hidden = !loaded;
    frame.contentDocument.getElementById('theme-default-brand').hidden = loaded;
    if (loaded && previewImage.src !== image.src) previewImage.src = image.src;
  };
  const refreshLogo = () => {
    const image = by('theme-logo-image');
    if (!image) return;
    image.hidden = true;
    image.onload = syncPreviewLogo;
    image.onerror = syncPreviewLogo;
    const previewImage = frame.contentDocument?.getElementById('theme-logo-image');
    if (previewImage) {
      previewImage.hidden = true;
      frame.contentDocument.getElementById('theme-default-brand').hidden = false;
    }
    image.src = logoURL();
  };
  const requestTheme = async targetID => {
    const result = await api('/auth/v1/theme/' + encodeURIComponent(targetID), {method: 'POST'});
    return result;
  };
  const loadTheme = async () => {
    const requested = await requestTheme(clientID);
    const usesGlobal = requested?.client_id !== clientID;
    const loaded = usesGlobal ? await requestTheme('rauthy') : requested;
    if (!loaded?.light || !loaded?.dark) throw Error(t('Theme data is incomplete.'));
    theme = loaded;
    theme.login ||= {};
    theme.login.copy ||= {};
    for (const lang of ['en', 'ko']) theme.login.copy[lang] ||= {};
    theme.login.logo_alignment ??= '';
    theme.login.card_width ??= 0;
    inherited = usesGlobal;
    renderFields();
    updateNotice();
    updatePreview();
    status.textContent = '';
  };
  const updateNotice = () => {
    by('theme-notice').textContent = inherited
      ? t('This client inherits the global theme. Saving creates a client-specific override.')
      : t('This client has a saved theme override.');
  };
  const hslText = value => (Array.isArray(value) ? value : []).join(' ');
  const hslToHex = value => {
    if (!Array.isArray(value) || value.length !== 3) return '#000000';
    const [rawHue, rawSat, rawLight] = value.map(Number);
    const hue = ((rawHue % 360) + 360) % 360, sat = Math.max(0, Math.min(100, rawSat)), light = Math.max(0, Math.min(100, rawLight));
    const s = sat / 100, l = light / 100, chroma = (1 - Math.abs(2 * l - 1)) * s;
    const x = chroma * (1 - Math.abs((hue / 60) % 2 - 1)), m = l - chroma / 2;
    const rgb = hue < 60 ? [chroma, x, 0] : hue < 120 ? [x, chroma, 0] : hue < 180 ? [0, chroma, x] : hue < 240 ? [0, x, chroma] : hue < 300 ? [x, 0, chroma] : [chroma, 0, x];
    return '#' + rgb.map(component => Math.round((component + m) * 255).toString(16).padStart(2, '0')).join('');
  };
  const hexToHSL = hex => {
    const rgb = [1, 3, 5].map(offset => parseInt(hex.slice(offset, offset + 2), 16) / 255);
    const max = Math.max(...rgb), min = Math.min(...rgb), delta = max - min;
    let hue = 0;
    if (delta) {
      if (max === rgb[0]) hue = 60 * (((rgb[1] - rgb[2]) / delta) % 6);
      else if (max === rgb[1]) hue = 60 * ((rgb[2] - rgb[0]) / delta + 2);
      else hue = 60 * ((rgb[0] - rgb[1]) / delta + 4);
    }
    const light = (max + min) / 2, saturation = delta ? delta / (1 - Math.abs(2 * light - 1)) : 0;
    return [(Math.round(hue) + 360) % 360, Math.round(saturation * 100), Math.round(light * 100)];
  };
  const renderFields = () => {
    const selected = theme[mode];
    const login = theme.login, copy = login.copy[copyLanguage];
    fields.innerHTML = `<section class="theme-login"><h3>${h('Login text')}</h3><label>${h('Copy language')}<select data-theme-copy-language><option value="en"${copyLanguage === 'en' ? ' selected' : ''}>English</option><option value="ko"${copyLanguage === 'ko' ? ' selected' : ''}>한국어</option></select></label><label>${h('Title')}<input maxlength="120" data-theme-copy="title" value="${esc(copy.title || '')}"></label><label>${h('Description')}<textarea maxlength="500" data-theme-copy="description">${esc(copy.description || '')}</textarea></label><label>${h('Button text')}<input maxlength="60" data-theme-copy="button" value="${esc(copy.button || '')}"></label><h3>${h('Login layout')}</h3><label>${h('Logo alignment')}<select data-theme-layout="logo_alignment"><option value=""${login.logo_alignment === '' ? ' selected' : ''}>${h('Default')}</option><option value="start"${login.logo_alignment === 'start' ? ' selected' : ''}>${h('Start')}</option><option value="center"${login.logo_alignment === 'center' ? ' selected' : ''}>${h('Center')}</option></select></label><label>${h('Card width (0 for default)')}<input type="number" min="0" max="640" data-theme-layout="card_width" value="${Number(login.card_width) || 0}"></label></section><details class="theme-colors-details"><summary>${h('Colors and advanced appearance')}</summary><div class="theme-colors">${colorFields.map(field => `<label class="theme-color"><span>${h(colorLabels[field])}</span><input type="color" data-theme-color="${field}" value="${hslToHex(selected[field])}" aria-label="${h(colorLabels[field] + ' color')}"><output data-theme-hsl="${field}">${esc(hslText(selected[field]))}</output></label>`).join('')}</div><label for="theme-btn-text">${h('Button text CSS value')}<input id="theme-btn-text" data-theme-css="btn_text" value="${esc(selected.btn_text)}"></label><label for="theme-border-radius">${h('Border radius CSS value')}<input id="theme-border-radius" data-theme-css="border_radius" value="${esc(theme.border_radius)}"></label></details>`;
    fields.querySelectorAll('[data-theme-copy-language]').forEach(input => { input.disabled = pending; input.onchange = () => { copyLanguage = input.value; renderFields(); updatePreview(); }; });
    fields.querySelectorAll('[data-theme-copy]').forEach(input => { input.disabled = pending; input.oninput = () => { if (!pending) { copy[input.dataset.themeCopy] = input.value; updatePreview(); } }; });
    fields.querySelectorAll('[data-theme-layout]').forEach(input => { input.disabled = pending; input.oninput = () => { if (!pending) { login[input.dataset.themeLayout] = input.dataset.themeLayout === 'card_width' ? Number(input.value) || 0 : input.value; updatePreview(); } }; });
    fields.querySelectorAll('[data-theme-color]').forEach(input => { input.disabled = pending; input.oninput = () => {
      if (pending) return;
      const field = input.dataset.themeColor;
      selected[field] = hexToHSL(input.value);
      fields.querySelector(`[data-theme-hsl="${field}"]`).textContent = hslText(selected[field]);
      updatePreview();
    }; });
    fields.querySelectorAll('[data-theme-css]').forEach(input => { input.disabled = pending; input.oninput = () => {
      if (pending) return;
      if (input.dataset.themeCss === 'border_radius') theme.border_radius = input.value;
      else selected.btn_text = input.value;
      updatePreview();
    }; });
  };
  const sampleDocument = () => `<!doctype html><html lang="${document.documentElement?.lang === 'ko' ? 'ko' : 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/auth/v1/theme/global.css"></head><body class="auth-page"><header class="auth-topbar"><a class="auth-brand"><img id="theme-logo-image" class="client-login-logo" alt="${h(clientID)}" hidden><span id="theme-default-brand" class="auth-brand"><span class="brand-symbol" aria-hidden="true"></span><span>GoAuthy</span></span></a></header><main class="auth-panel"><p class="auth-eyebrow">${h('PREVIEW')}</p><h1 id="theme-sample-title">${h('Sign in to {client}', {client: clientID})}</h1><p id="theme-sample-description" class="auth-intro">${h('Enter your account details to continue.')}</p><div id="theme-sample-fields" inert><label>${h('Email')}<input type="email" value="alex@example.test"></label><label>${h('Password')}<input type="password" value="sample-password"></label><button id="theme-sample-button" type="button">${h('Continue')}</button></div><p class="auth-error">${h('Example error message')}</p></main></body></html>`;
  const updatePreview = () => {
    if (!theme || !frame.contentDocument?.body) return;
    const body = frame.contentDocument.body;
    body.className = mode === 'dark' ? 'auth-page theme-dark' : 'auth-page theme-light';
    const selected = theme[mode];
    let invalidCSS = false;
    const setCSS = (name, value) => {
      if (/^[a-z0-9-,.#()%/\s]+$/.test(String(value ?? ''))) body.style.setProperty(name, String(value));
      else { body.style.removeProperty(name); invalidCSS = true; }
    };
    for (const field of colorFields) setCSS('--' + field.replace('_', '-'), (selected[field] || []).join(' '));
    setCSS('--btn-text', selected.btn_text);
    setCSS('--border-radius', theme.border_radius);
    setCSS('--theme-sun', selected.theme_sun);
    setCSS('--theme-moon', selected.theme_moon);
    syncPreviewLogo();
    const copy = theme.login.copy[copyLanguage], fallback = theme.login.copy.en;
    const title = frame.contentDocument.getElementById('theme-sample-title'), description = frame.contentDocument.getElementById('theme-sample-description'), button = frame.contentDocument.getElementById('theme-sample-button');
    const sampleFields = frame.contentDocument.getElementById('theme-sample-fields');
    if (!title || !description || !button || !sampleFields) return;
    title.dataset.brandEn = theme.login.copy.en.title || ''; title.dataset.brandKo = theme.login.copy.ko.title || '';
    description.dataset.brandEn = theme.login.copy.en.description || ''; description.dataset.brandKo = theme.login.copy.ko.description || '';
    button.dataset.brandEn = theme.login.copy.en.button || ''; button.dataset.brandKo = theme.login.copy.ko.button || '';
    title.textContent = copy.title || fallback.title || t('Sign in to {client}', {client: clientID});
    description.textContent = copy.description || fallback.description || t('Enter your account details to continue.');
    button.textContent = copy.button || fallback.button || t('Continue');
    frame.contentDocument.querySelector('.auth-panel').style.setProperty('width', `min(100%, ${theme.login.card_width || 420}px)`);
    frame.contentDocument.querySelector('.auth-panel').style.setProperty('max-width', theme.login.card_width ? `${theme.login.card_width}px` : '');
    const brand = frame.contentDocument.querySelector('.auth-topbar .auth-brand');
    brand.style.setProperty('margin-inline', theme.login.logo_alignment === 'center' ? 'auto' : '');
    sampleFields.style.setProperty('display', 'grid');
    sampleFields.style.setProperty('gap', '14px');
    if (invalidCSS) { status.className = 'theme-status hint'; status.textContent = invalidPreviewMessage; }
    else if (status.textContent === invalidPreviewMessage) { status.className = 'theme-status'; status.textContent = ''; }
  };
  frame.onload = updatePreview;
  frame.srcdoc = sampleDocument();
  refreshLogo();
  const busy = value => {
    pending = value;
    by('theme-save').disabled = value || !theme;
    by('theme-reload').disabled = value;
    by('theme-reset').disabled = value || !theme;
    by('theme-reset-confirm').disabled = value;
    by('theme-reset-cancel').disabled = value;
    by('theme-fields').querySelectorAll('input, select, textarea').forEach(input => { input.disabled = value; });
    document.querySelectorAll('[data-theme-mode]').forEach(button => { button.disabled = value; });
  };
  document.querySelectorAll('[data-theme-mode]').forEach(button => button.onclick = () => {
    if (pending || !theme || button.dataset.themeMode === mode) return;
    mode = button.dataset.themeMode;
    document.querySelectorAll('[data-theme-mode]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    renderFields();
    updatePreview();
  });
  by('theme-save').onclick = async () => {
    if (pending || !theme) return;
    busy(true);
    status.className = 'theme-status';
    status.textContent = t('Saving…');
    try {
      const payload = {...theme}; if (!Object.keys(payload.login.copy.en).length && !Object.keys(payload.login.copy.ko).length && !payload.login.logo_alignment && !payload.login.card_width) delete payload.login;
      await api(endpoint, {method: 'PUT', responseType: 'empty', body: JSON.stringify({...payload, client_id: clientID})});
      inherited = false;
      updateNotice();
      status.className = 'theme-status success';
      status.textContent = t('Theme saved.');
    } catch (error) {
      status.className = 'theme-status error';
      status.textContent = error.message;
    } finally { busy(false); }
  };
  by('theme-reload').onclick = async () => {
    if (pending) return;
    busy(true);
    status.className = 'theme-status';
    status.textContent = t('Loading saved theme…');
    try { await loadTheme(); status.textContent = t('Saved theme reloaded.'); }
    catch (error) { status.className = 'theme-status error'; status.textContent = error.message; }
    finally { busy(false); }
  };
  by('theme-reset').onclick = () => { if (!pending && theme) by('theme-reset-review').hidden = false; };
  by('theme-reset-cancel').onclick = () => { if (!pending) by('theme-reset-review').hidden = true; };
  by('theme-reset-confirm').onclick = async () => {
    if (pending || !theme) return;
    busy(true);
    status.className = 'theme-status';
    status.textContent = t('Resetting theme…');
    try {
      await api(endpoint, {method: 'DELETE'});
      await loadTheme();
      by('theme-reset-review').hidden = true;
      status.className = 'theme-status success';
      status.textContent = t('Client theme removed. The preview shows the current global theme; saving creates a client override.');
    } catch (error) {
      status.className = 'theme-status error';
      status.textContent = error.message;
    } finally { busy(false); }
  };
  by('theme-logo-upload').onchange = async event => {
    if (logoPending) return;
    const file = event.target.files?.[0]; if (!file) return;
    const logoStatus = by('theme-logo-status');
    if (file.size > 10 * 1024 * 1024 - 64 * 1024) { logoStatus.className = 'theme-status error'; logoStatus.textContent = t('Logo file must be 10 MiB or smaller.'); event.target.value = ''; return; }
    const body = new FormData(); body.append('file', file);
    logoPending = true; by('theme-logo-upload').disabled = true; by('theme-logo-delete').disabled = true; logoStatus.className = 'theme-status'; logoStatus.textContent = t('Saving logo…');
    try { await api(`/auth/v1/clients/${encodeURIComponent(clientID)}/logo`, {method: 'PUT', body, responseType: 'empty'}); logoVersion++; refreshLogo(); logoStatus.className = 'theme-status success'; logoStatus.textContent = t('Logo saved.'); }
    catch (error) { logoStatus.className = 'theme-status error'; logoStatus.textContent = error.message; }
    finally { logoPending = false; by('theme-logo-upload').disabled = false; by('theme-logo-delete').disabled = false; event.target.value = ''; }
  };
  by('theme-logo-delete').onclick = () => { if (!pending && !logoPending) by('theme-logo-remove-review').hidden = false; };
  by('theme-logo-remove-cancel').onclick = () => { if (!logoPending) by('theme-logo-remove-review').hidden = true; };
  by('theme-logo-remove-confirm').onclick = async () => {
    if (pending || logoPending) return;
    const logoStatus = by('theme-logo-status'); logoPending = true; by('theme-logo-delete').disabled = true; by('theme-logo-upload').disabled = true; logoStatus.className = 'theme-status'; logoStatus.textContent = t('Removing logo…');
    try { await api(`/auth/v1/clients/${encodeURIComponent(clientID)}/logo`, {method: 'DELETE', responseType: 'empty'}); logoVersion++; refreshLogo(); by('theme-logo-remove-review').hidden = true; logoStatus.className = 'theme-status success'; logoStatus.textContent = t('Logo removed.'); }
    catch (error) { logoStatus.className = 'theme-status error'; logoStatus.textContent = error.message; }
    finally { logoPending = false; by('theme-logo-delete').disabled = false; by('theme-logo-upload').disabled = false; }
  };
  busy(true);
  try { await loadTheme(); }
  catch (error) { status.className = 'theme-status error'; status.textContent = error.message; }
  finally { busy(false); }
}
