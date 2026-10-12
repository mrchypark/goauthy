const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(__dirname + '/themes.js', 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
const makeTheme = client_id => ({client_id, light: {text: [200, 5, 37], text_high: [200, 15, 25], bg: [34, 25, 97], bg_high: [34, 20, 90], action: [34, 100, 40], accent: [265, 100, 53], error: [15, 100, 37], btn_text: 'white', theme_sun: 'hsla(var(--action) / .7)', theme_moon: 'hsla(var(--accent) / .85)'}, dark: {text: [34, 5, 75], text_high: [34, 7, 90], bg: [200, 40, 6], bg_high: [200, 20, 17], action: [34, 100, 59], accent: [265, 100, 53], error: [15, 100, 37], btn_text: 'hsl(var(--bg))', theme_sun: 'hsla(var(--action) / .7)', theme_moon: 'hsla(var(--accent) / .85)'}, border_radius: '5px'});

function harness(messages = {}, language = 'ko') {
  const nodes = new Map(), calls = [], vars = new Map(), removedVars = [], sampleVars = new Map(), frameBody = {style: {setProperty: (key, value) => vars.set(key, value), removeProperty: key => { removedVars.push(key); vars.delete(key); }}, dataset: {}};
  const sampleFields = {style: {setProperty: (key, value) => sampleVars.set(key, value)}};
  let sampleReady = true;
  const node = id => {
    if (!nodes.has(id)) {
      const el = {id, value: '', textContent: '', className: '', disabled: false, dataset: {}, attrs: {}, naturalWidth: 0, complete: false, style: {setProperty() {}, removeProperty() {}}, setAttribute(key, value) { this.attrs[key] = value; }, querySelectorAll() { return []; }, querySelector(selector) { const field = selector.match(/data-theme-hsl="([^"]+)"/)?.[1]; return field ? outputs.get(field) : null; }, insertAdjacentHTML(position, html) { this.html = html + this.html; }};
      if (id === 'theme-logo-image') Object.defineProperty(el, 'src', {get() { return this._src; }, set(value) { this._src = value; this.srcWrites = (this.srcWrites || 0) + 1; }});
      Object.defineProperty(el, 'innerHTML', {get() { return el.html || ''; }, set(html) {
        el.html = html;
        if (id !== 'theme-fields') return;
        colors.length = 0; cssFields.length = 0; copyFields.length = 0; layoutFields.length = 0; controls.length = 0; outputs.clear();
        for (const match of html.matchAll(/<(input|select|textarea)\b([^>]*)>/g)) {
          const attrs = match[2], copy = attrs.match(/data-theme-copy="([^"]+)"/), layout = attrs.match(/data-theme-layout="([^"]+)"/), language = attrs.match(/data-theme-copy-language/);
          const element = match[1], field = copy?.[1] || layout?.[1] || (language ? 'language' : '');
          if (!field) { if (element === 'input') controls.push(node('control-' + controls.length)); continue; }
          const control = element === 'select' && language ? copyLanguage : node('control-' + field);
          if (copy) control.dataset.themeCopy = copy[1];
          if (layout) control.dataset.themeLayout = layout[1];
          const value = (attrs.match(/value="([^"]*)"/) || [])[1]; if (value !== undefined) control.value = value;
          if (element === 'textarea' && copy) control.value = html.slice(match.index + match[0].length).split('</textarea>')[0];
          if (element !== 'input' && copy) copyFields.push(control);
          if (element !== 'input' && layout) layoutFields.push(control);
          controls.push(control);
        }
        for (const match of html.matchAll(/<input\b([^>]*)>/g)) {
          const attrs = match[1], color = attrs.match(/data-theme-color="([^"]+)"/), css = attrs.match(/data-theme-css="([^"]+)"/);
          if (color) { const input = node('color-' + color[1]); input.dataset.themeColor = color[1]; input.value = (attrs.match(/value="([^"]*)"/) || [])[1]; colors.push(input); }
          if (css) { const input = node('css-' + css[1]); input.dataset.themeCss = css[1]; input.value = (attrs.match(/value="([^"]*)"/) || [])[1]; cssFields.push(input); }
          const copy = attrs.match(/data-theme-copy="([^"]+)"/), layout = attrs.match(/data-theme-layout="([^"]+)"/);
          if (copy) { const input = node('copy-' + copy[1]); input.dataset.themeCopy = copy[1]; input.value = (attrs.match(/value="([^"]*)"/) || [])[1]; copyFields.push(input); }
          if (layout) { const input = node('layout-' + layout[1]); input.dataset.themeLayout = layout[1]; input.value = (attrs.match(/value="([^"]*)"/) || [])[1]; layoutFields.push(input); }
        }
        for (const match of html.matchAll(/<output data-theme-hsl="([^"]+)">([^<]*)<\/output>/g)) { const output = node('output-' + match[1]); output.textContent = match[2]; outputs.set(match[1], output); }
        controls.push(...colors, ...cssFields, ...copyFields, ...layoutFields);
        el.querySelectorAll = selector => selector === '[data-theme-color]' ? colors : selector === '[data-theme-css]' ? cssFields : selector === '[data-theme-copy]' ? copyFields : selector === '[data-theme-layout]' ? layoutFields : selector === '[data-theme-copy-language]' ? [copyLanguage] : selector === 'input, select, textarea' ? controls : selector === 'input' ? [...colors, ...cssFields, ...copyFields, ...layoutFields] : [];
      }});
      nodes.set(id, el);
    }
    return nodes.get(id);
  };
  const colors = [], cssFields = [], copyFields = [], layoutFields = [], controls = [], outputs = new Map();
  const copyLanguage = {value: 'en'};
  const modes = ['light', 'dark'].map(value => ({dataset: {themeMode: value}, attrs: {}, disabled: false, setAttribute(key, val) { this.attrs[key] = val; }}));
  const frame = node('theme-preview-frame');
  const previewLabels = new Map();
  let frameWrites = 0;
  Object.defineProperty(frame, 'srcdoc', {get() { return this.htmlDocument; }, set(html) {
    this.htmlDocument = html;
    frameWrites++;
    previewLabels.clear();
    for (const match of html.matchAll(/data-i18n="([^"]+)"/g)) {
      const key = match[1];
      previewLabels.set(key, {textContent: '', getAttribute: () => key});
    }
  }});
  const previewNodes = new Map(['theme-sample-fields','theme-sample-title','theme-sample-description','theme-sample-button','theme-logo-image','theme-default-brand','theme-brand-label'].map(id => [id, {id, textContent: '', hidden: false, dataset: {}, style: {setProperty() {}}, set src(value) { this._src = value; this.srcWrites = (this.srcWrites || 0) + 1; }, get src() { return this._src; }}]));
  const previewPanel = {style: {setProperty(name, value) { this[name] = value; }}}, brand = {style: {setProperty(name, value) { this[name] = value; }}}, topbar = {classList: {toggle(name, value) { this[name] = value; }}};
  frame.contentDocument = {documentElement: {lang: ''}, body: frameBody, getElementById: id => id === 'theme-sample-fields' ? (sampleReady ? sampleFields : null) : previewNodes.get(id) || null, querySelectorAll: selector => selector === '[data-i18n]' ? [...previewLabels.values()] : [], querySelector: selector => selector === '.auth-panel' ? previewPanel : selector === '.auth-topbar .auth-brand' ? brand : topbar};
  const root = {innerHTML: ''};
  const globalTheme = makeTheme('goauthy');
  let saved = null, failNextPut = false, failNextPost = false, holdNextPut = false, resolvePut, rejectPut, confirmCount = 0;
  const document = {documentElement: {lang: language}, getElementById: node, querySelectorAll: selector => selector === '[data-theme-mode]' ? modes : []};
  const ctx = {
    document, console, root, confirm: () => { confirmCount++; return true; }, encodeURIComponent, Date, FormData: class { append(key, value) { this[key] = value; } },
    esc: value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c])),
    GoAuthyI18n: {language, messages, t(key, values = {}) { return String(language === 'ko' ? (messages[key] || key) : key).replace(/\{(\w+)\}/g, (_, name) => Object.hasOwn(values, name) ? values[name] : `{${name}}`); }},
    shell(title, subtitle, body, toolbar = '') { root.innerHTML = `${toolbar}${title}\n${subtitle}\n${body}`; for (const match of (toolbar + body).matchAll(/id="([^"]+)"/g)) node(match[1]); },
    api: async (path, opts = {}) => {
      calls.push({path, opts});
      if (opts.method === 'POST') {
        if (failNextPost) { failNextPost = false; throw Error('read unavailable'); }
        if (path.endsWith('/goauthy')) return clone(saved?.client_id === 'goauthy' ? saved : globalTheme);
        return clone(saved || globalTheme);
      }
      if (opts.method === 'PUT') {
        if (failNextPut) { failNextPut = false; throw Error('write unavailable'); }
        if (holdNextPut) { holdNextPut = false; return new Promise((resolve, reject) => { resolvePut = resolve; rejectPut = reject; }); }
        if (typeof opts.body === 'string') saved = JSON.parse(opts.body);
        return null;
      }
      if (opts.method === 'DELETE' && path.includes('/logo')) return null;
      if (opts.method === 'DELETE') { saved = null; return null; }
      throw Error('unexpected API method');
    },
  };
  vm.runInNewContext(source, ctx);
  return {ctx, calls, root, node, colors, cssFields, copyFields, layoutFields, controls, copyLanguage, outputs, modes, frame, vars, removedVars, sampleVars, previewNodes, previewLabels, get frameWrites() { return frameWrites; }, previewPanel, brand, globalTheme, get saved() { return saved; }, get confirmCount() { return confirmCount; }, setFailPut: () => { failNextPut = true; }, setFailPost: () => { failNextPost = true; }, setSampleReady: ready => { sampleReady = ready; }, holdPut: () => { holdNextPut = true; }, rejectPut: error => rejectPut(error), resolvePut: value => resolvePut(value)};
}

(async () => {
  const h = harness(), id = 'client<& /id';
  await h.ctx.clientTheme(id);
  const endpoint = '/auth/v1/theme/' + encodeURIComponent(id);
  assert.deepEqual(h.calls.slice(0, 2).map(x => [x.path, x.opts.method]), [[endpoint, 'POST'], ['/auth/v1/theme/goauthy', 'POST']]);
  assert.match(h.root.innerHTML, /Client login theme/);
  assert.match(h.root.innerHTML, /href="\/auth\/v1\/admin\/clients"/);
  assert.match(h.root.innerHTML, /theme-workspace/);
  assert.match(h.root.innerHTML, /theme-editor/);
  assert.match(h.node('theme-fields').innerHTML, /data-theme-copy="title"/);
  assert.match(h.node('theme-fields').innerHTML, /data-theme-layout="card_width"/);
  assert.match(h.node('theme-fields').innerHTML, /theme-colors/);
  assert.ok(h.controls.every(control => !control.disabled), 'all editor controls are enabled after initial load');
  assert.ok(h.controls.some(control => control.dataset?.themeCopy === 'description'), 'description textarea participates in busy state');
  assert.ok(h.controls.some(control => control.dataset?.themeLayout === 'logo_alignment'), 'alignment select participates in busy state');
  assert.match(h.root.innerHTML, /theme-preview/);
  assert.match(h.frame.srcdoc, /href="\/auth\/v1\/theme\/global\.css"/);
  assert.match(h.frame.srcdoc, /class="auth-page"/);
  assert.match(h.frame.srcdoc, /class="auth-panel"/);
  assert.match(h.frame.srcdoc, /class="brand-symbol"/);
  assert.match(h.frame.srcdoc, /id="theme-sample-fields" inert/);
  assert.match(h.frame.srcdoc, /lang="en"/);
  assert.match(h.frame.srcdoc, /client&lt;&amp; \/id/);
  assert.doesNotMatch(h.frame.srcdoc, /<script|<form|\saction=|\sstyle=/i);
  assert.match(h.root.innerHTML, /sandbox="allow-same-origin"/);
  h.frame.onload();
  assert.equal(h.outputs.get('text').textContent, '200 5 37');
  assert.equal(h.sampleVars.get('display'), 'grid');
  assert.equal(h.sampleVars.get('gap'), '14px');
  assert.equal(h.vars.get('--text'), '200 5 37');
  const logo = h.previewNodes.get('theme-logo-image');
  assert.match(h.node('theme-logo-image').src, /\/auth\/v1\/clients\/client%3C%26%20%2Fid\/logo\?v=/);
  assert.equal(logo.hidden, true);
  h.node('theme-logo-image').naturalWidth = 0;
  h.node('theme-logo-image').onerror();
  assert.equal(h.previewNodes.get('theme-default-brand').hidden, false);
  h.node('theme-logo-image').naturalWidth = 120;
  h.node('theme-logo-image').complete = true;
  h.node('theme-logo-image').onload();
  assert.equal(logo.hidden, false);
  assert.equal(logo.src, h.node('theme-logo-image').src);
  assert.equal(h.previewNodes.get('theme-default-brand').hidden, true);
  const loadedLogoURL = h.node('theme-logo-image').src;
  h.copyFields.find(x => x.dataset.themeCopy === 'title').oninput();
  assert.equal(h.node('theme-logo-image').src, loadedLogoURL, 'ordinary preview updates do not reload the logo');
  h.copyFields.find(x => x.dataset.themeCopy === 'title').value = '<img onerror=alert(1)>';
  h.copyFields.find(x => x.dataset.themeCopy === 'title').oninput();
  assert.equal(h.previewNodes.get('theme-sample-title').textContent, '<img onerror=alert(1)>');
  h.copyFields.find(x => x.dataset.themeCopy === 'title').value = 'English fallback';
  h.copyFields.find(x => x.dataset.themeCopy === 'title').oninput();
  h.copyLanguage.value = 'ko'; h.copyLanguage.onchange();
  assert.equal(h.previewNodes.get('theme-sample-title').textContent, 'English fallback');
  h.copyFields.find(x => x.dataset.themeCopy === 'title').value = '한국어 제목';
  h.copyFields.find(x => x.dataset.themeCopy === 'title').oninput();
  assert.equal(h.previewNodes.get('theme-sample-title').textContent, '한국어 제목');
  h.layoutFields.find(x => x.dataset.themeLayout === 'logo_alignment').value = 'center';
  h.layoutFields.find(x => x.dataset.themeLayout === 'logo_alignment').oninput();
  assert.equal(h.brand.style['margin-inline'], 'auto');
  h.copyLanguage.value = 'en'; h.copyLanguage.onchange();
  h.layoutFields.find(x => x.dataset.themeLayout === 'card_width').value = '420';
  h.layoutFields.find(x => x.dataset.themeLayout === 'card_width').oninput();
  assert.equal(h.vars.has('--auth-card-width'), false);
  assert.equal(h.previewPanel.style.width, 'min(100%, 420px)');
  assert.equal(h.previewPanel.style['max-width'], '420px');
  assert.equal(h.brand.style['margin-inline'], 'auto');

  h.colors.find(x => x.dataset.themeColor === 'text').value = '#ff0000';
  h.colors.find(x => x.dataset.themeColor === 'text').oninput();
  assert.equal(h.outputs.get('text').textContent, '0 100 50');
  const btnText = h.cssFields.find(x => x.dataset.themeCss === 'btn_text');
  btnText.value = 'white'; btnText.oninput();
  h.modes[1].onclick();
  assert.equal(h.modes[1].attrs['aria-pressed'], 'true');
  assert.equal(h.outputs.get('text').textContent, '34 5 75');
  h.colors.find(x => x.dataset.themeColor === 'text').value = '#00ff00';
  h.colors.find(x => x.dataset.themeColor === 'text').oninput();
  h.modes[0].onclick();
  assert.equal(h.outputs.get('text').textContent, '0 100 50');

  await h.node('theme-save').onclick();
  const put = h.calls.filter(x => x.opts.method === 'PUT').at(-1);
  const payload = JSON.parse(put.opts.body);
  assert.equal(put.path, endpoint);
  assert.equal(put.opts.responseType, 'empty');
  assert.equal(payload.client_id, id);
  assert.equal(payload.login.copy.en.title, 'English fallback');
  assert.equal(payload.login.copy.ko.title, '한국어 제목');
  assert.equal(payload.login.card_width, 420);
  assert.deepEqual(payload.light.text, [0, 100, 50]);
  assert.deepEqual(payload.dark.text, [120, 100, 50]);
  assert.equal(payload.light.theme_sun, h.globalTheme.light.theme_sun);
  assert.equal(payload.dark.theme_moon, h.globalTheme.dark.theme_moon);
  assert.equal(payload.light.btn_text, 'white');

  const cssText = h.cssFields.find(x => x.dataset.themeCss === 'btn_text');
  cssText.value = 'var(--unsafe);'; cssText.oninput();
  assert.match(h.node('theme-status').textContent, /preview omits invalid CSS values/i);
  assert.ok(h.removedVars.includes('--btn-text'));
  h.setFailPut();
  await h.node('theme-save').onclick();
  assert.equal(cssText.value, 'var(--unsafe);');
  assert.equal(h.node('theme-status').textContent, 'write unavailable');

  cssText.value = 'white'; cssText.oninput();
  h.holdPut();
  const beforePending = h.calls.filter(x => x.opts.method === 'PUT').length;
  const pending = h.node('theme-save').onclick();
  await Promise.resolve();
  assert.equal(h.node('theme-save').disabled, true);
  assert.equal(h.cssFields[0].disabled, true);
  await h.node('theme-save').onclick();
  assert.equal(h.calls.filter(x => x.opts.method === 'PUT').length, beforePending + 1);
  h.rejectPut(Error('write unavailable'));
  await pending;
  assert.equal(h.node('theme-save').disabled, false);
  assert.equal(h.cssFields.find(x => x.dataset.themeCss === 'btn_text').value, 'white');

  const savedRadius = JSON.parse(put.opts.body).border_radius;
  h.cssFields.find(x => x.dataset.themeCss === 'border_radius').value = '17px';
  h.cssFields.find(x => x.dataset.themeCss === 'border_radius').oninput();
  await h.node('theme-reload').onclick();
  assert.equal(h.cssFields.find(x => x.dataset.themeCss === 'border_radius').value, savedRadius);

  const beforeReset = h.calls.length;
  await h.node('theme-reset').onclick();
  assert.equal(h.node('theme-reset-review').hidden, false);
  await h.node('theme-reset-cancel').onclick();
  assert.equal(h.node('theme-reset-review').hidden, true);
  await h.node('theme-reset').onclick();
  await h.node('theme-reset-confirm').onclick();
  const resetCalls = h.calls.slice(beforeReset);
  assert.deepEqual(resetCalls.map(x => [x.path, x.opts.method]), [[endpoint, 'DELETE'], [endpoint, 'POST'], ['/auth/v1/theme/goauthy', 'POST']]);
  assert.match(h.node('theme-notice').textContent, /inherits the global theme/i);
  assert.equal(h.outputs.get('text').textContent, '200 5 37');
  assert.equal(h.confirmCount, 0);

  const upload = h.node('theme-logo-upload'), logoFile = {name: 'logo.svg', size: 100, type: 'image/svg+xml'};
  const logoCallsBeforeLimit = h.calls.filter(x => x.path.endsWith('/logo')).length;
  await upload.onchange({target: {files: [{size: 10 * 1024 * 1024 - 64 * 1024 + 1}], value: ''}});
  assert.equal(h.calls.filter(x => x.path.endsWith('/logo')).length, logoCallsBeforeLimit);
  assert.match(h.node('theme-logo-status').textContent, /10 MiB/);
  await upload.onchange({target: {files: [logoFile], value: ''}});
  const logoPut = h.calls.find(x => x.path.endsWith('/logo') && x.opts.method === 'PUT');
  assert.equal(logoPut.opts.responseType, 'empty');
  assert.equal(logoPut.opts.body.file, logoFile);
  assert.match(h.previewNodes.get('theme-logo-image').src, /[?]v=/);
  await h.node('theme-logo-delete').onclick();
  assert.equal(h.node('theme-logo-remove-review').hidden, false);
  await h.node('theme-logo-remove-cancel').onclick();
  assert.equal(h.node('theme-logo-remove-review').hidden, true);
  await h.node('theme-logo-delete').onclick();
  await h.node('theme-logo-remove-confirm').onclick();
  assert.deepEqual(h.calls.filter(x => x.path.endsWith('/logo')).map(x => x.opts.method), ['PUT', 'DELETE']);
  assert.equal(h.confirmCount, 0);

  const failed = harness();
  failed.setFailPost();
  await failed.ctx.clientTheme('empty-client');
  assert.match(failed.node('theme-status').textContent, /read unavailable/);
  failed.modes[1].onclick();
  await failed.node('theme-save').onclick();
  await failed.node('theme-reset').onclick();
  assert.equal(failed.calls.filter(x => x.opts.method === 'PUT').length, 0);
  assert.equal(failed.calls.filter(x => x.opts.method === 'DELETE').length, 0);

  const delayedFrame = harness();
  delayedFrame.setSampleReady(false);
  await delayedFrame.ctx.clientTheme('delayed-client');
  assert.equal(delayedFrame.node('theme-status').textContent, '');
  delayedFrame.setSampleReady(true);
  delayedFrame.frame.onload();
  assert.equal(delayedFrame.sampleVars.get('display'), 'grid');

  const renamed = harness();
  renamed.globalTheme.brand_name = 'Original ID';
  await renamed.ctx.clientTheme('app-b');
  await renamed.node('theme-save').onclick();
  assert.equal(renamed.saved.brand_name, 'Original ID');
  renamed.globalTheme.brand_name = `Current ID "<operator>"`;
  await renamed.node('theme-reload').onclick();
  assert.equal(renamed.saved.brand_name, 'Original ID', 'client override stays intact');
  assert.equal(renamed.previewNodes.get('theme-brand-label').textContent, renamed.globalTheme.brand_name, 'preview uses the current common name after a rename');
  delete renamed.saved.brand_name;
  await renamed.node('theme-reload').onclick();
  assert.equal(renamed.previewNodes.get('theme-brand-label').textContent, renamed.globalTheme.brand_name, 'override without a name also uses the common name');
  delete renamed.globalTheme.brand_name;
  await renamed.node('theme-reload').onclick();
  assert.equal(renamed.previewNodes.get('theme-brand-label').textContent, 'GoAuthy');

  const common = harness();
  await common.ctx.clientTheme('goauthy');
  assert.match(common.root.innerHTML, /Common brand/);
  assert.match(common.node('theme-fields').innerHTML, /Common brand name/);
  assert.equal(common.node('theme-reset').textContent, 'Reset common theme to defaults');
  const name = `GoAuthy ID "<operator>"`;
  common.node('theme-brand-name').value = name;
  common.node('theme-brand-name').oninput();
  await common.node('theme-save').onclick();
  assert.equal(common.saved.brand_name, name);
  assert.equal(common.saved.client_id, 'goauthy');
  assert.equal(common.saved.login, undefined, 'brand name is independent of login title');
  await common.node('theme-reload').onclick();
  assert.match(common.node('theme-fields').innerHTML, /GoAuthy ID &quot;&lt;operator&gt;&quot;/);
  assert.doesNotMatch(common.node('theme-fields').innerHTML, /"<operator>"/);
  assert.ok(common.calls.some(call => call.path === '/auth/v1/theme/goauthy' && call.opts.method === 'PUT'));
  await common.node('theme-reset-confirm').onclick();
  assert.equal(common.saved, null);
  assert.equal(common.node('theme-status').textContent, 'Common theme reset to defaults.');
  assert.equal(common.previewNodes.get('theme-sample-title').textContent, 'Sign in');
  assert.doesNotMatch(common.frame.srcdoc, /rauthy/);

  const koreanMessages = {'Sign in': '로그인'};
  vm.runInNewContext(fs.readFileSync(__dirname + '/module_locale.js', 'utf8'), {globalThis: {GoAuthyI18n: {messages: koreanMessages}}});
  const koreanCommon = harness(koreanMessages);
  koreanCommon.globalTheme.brand_name = 'GoAuthy ID';
  await koreanCommon.ctx.clientTheme('goauthy');
  assert.equal(koreanCommon.previewNodes.get('theme-sample-title').textContent, 'Sign in');
  assert.equal(koreanCommon.previewNodes.get('theme-brand-label').textContent, 'GoAuthy ID');
  assert.doesNotMatch(koreanCommon.root.innerHTML, /대시보드로 돌아가기/);
  assert.match(koreanCommon.root.innerHTML, /공통 로고/);
  assert.doesNotMatch(koreanCommon.frame.srcdoc, /rauthy/);
  assert.doesNotMatch(koreanCommon.root.innerHTML, /Back to dashboard|Common logo|Current common logo|Remove this common logo/);
  const koreanClient = harness(koreanMessages);
  await koreanClient.ctx.clientTheme('app-b');
  assert.equal(koreanClient.previewNodes.get('theme-sample-title').textContent, 'Sign in to app-b');
  koreanClient.copyLanguage.value = 'ko'; koreanClient.copyLanguage.onchange();
  assert.equal(koreanClient.previewNodes.get('theme-sample-title').textContent, 'app-b 로그인');

  for (const adminLanguage of ['ko', 'en']) {
    const localized = harness(koreanMessages, adminLanguage);
    await localized.ctx.clientTheme('goauthy');
    localized.frame.onload();
    const adminMarkup = localized.root.innerHTML, callsBefore = localized.calls.length;
    const sampleText = () => ['title', 'description', 'button'].map(field => localized.previewNodes.get('theme-sample-' + field).textContent);
    const defaults = {
      en: ['Sign in', 'Enter your account details to continue.', 'Continue'],
      ko: ['로그인', koreanMessages['Enter your account details to continue.'], koreanMessages.Continue],
    };
    const switchCopy = language => { localized.copyLanguage.value = language; localized.copyLanguage.onchange(); };
    for (const language of ['en', 'ko', 'en']) {
      switchCopy(language);
      assert.deepEqual(sampleText(), defaults[language], `${adminLanguage} admin: ${language} preview defaults`);
      assert.equal(localized.frame.contentDocument.documentElement.lang, language);
      assert.match(localized.frame.srcdoc, /lang="en"/);
      for (const key of ['PREVIEW', 'Email', 'Password', 'Example error message']) {
        assert.equal(localized.previewLabels.get(key)?.textContent, language === 'ko' ? koreanMessages[key] : key, `${language} static ${key}`);
      }
      assert.equal(localized.previewNodes.get('theme-logo-image').alt, language === 'ko' ? koreanMessages['Sign-in preview sample'] : 'Sign-in preview sample');
    }
    const loadedImage = localized.node('theme-logo-image');
    loadedImage.complete = true; loadedImage.naturalWidth = 120; loadedImage.onload();
    const cachedLogoURL = loadedImage.src, previewLogo = localized.previewNodes.get('theme-logo-image');
    const editorLogoWrites = loadedImage.srcWrites, previewLogoWrites = previewLogo.srcWrites;
    const custom = {en: ['English title', 'English description', 'English button'], ko: ['한국어 제목', '한국어 설명', '한국어 버튼']};
    const editCopy = values => ['title', 'description', 'button'].forEach((field, index) => {
      const input = localized.copyFields.find(input => input.dataset.themeCopy === field);
      input.value = values[index]; input.oninput();
    });
    editCopy(custom.en);
    switchCopy('ko');
    assert.deepEqual(sampleText(), custom.en, 'empty Korean fields preserve the backend English fallback');
    editCopy(custom.ko);
    for (const language of ['en', 'ko', 'en']) {
      switchCopy(language);
      assert.deepEqual(sampleText(), custom[language], 'unsaved language edits survive switching');
      assert.deepEqual(['title', 'description', 'button'].map(field => localized.copyFields.find(input => input.dataset.themeCopy === field).value), custom[language]);
    }
    assert.equal(localized.calls.length, callsBefore, 'language changes and typing do not request data');
    assert.equal(localized.frameWrites, 1, 'language changes keep the iframe and its loaded assets');
    assert.equal(loadedImage.src, cachedLogoURL);
    assert.equal(previewLogo.src, cachedLogoURL);
    assert.equal(loadedImage.srcWrites, editorLogoWrites, 'editing does not reassign the editor logo URL');
    assert.equal(previewLogo.srcWrites, previewLogoWrites, 'editing does not reassign the loaded preview logo URL');
    assert.equal(previewLogo.hidden, false);
    assert.equal(localized.ctx.document.documentElement.lang, adminLanguage);
    assert.equal(localized.ctx.GoAuthyI18n.language, adminLanguage);
    assert.equal(localized.root.innerHTML, adminMarkup, 'management UI remains in its own language');
    await localized.node('theme-save').onclick();
    assert.deepEqual(clone(localized.saved.login.copy), {en: {title: custom.en[0], description: custom.en[1], button: custom.en[2]}, ko: {title: custom.ko[0], description: custom.ko[1], button: custom.ko[2]}});
    assert.deepEqual(Object.keys(localized.saved.login).sort(), ['card_width', 'copy', 'logo_alignment'], 'editing language does not become a stored default');
    editCopy(['Discard title', 'Discard description', 'Discard button']);
    await localized.node('theme-reload').onclick();
    for (const language of ['en', 'ko']) {
      switchCopy(language);
      assert.deepEqual(sampleText(), custom[language], 'reload restores both saved languages');
      assert.deepEqual(['title', 'description', 'button'].map(field => localized.copyFields.find(input => input.dataset.themeCopy === field).value), custom[language]);
    }
  }
  console.log('client theme UI checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
