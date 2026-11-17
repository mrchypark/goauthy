const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function makeElement(extra = {}) {
  const attrs = {};
  return {
    value: '',
    textContent: '',
    innerHTML: '',
    className: '',
    hidden: false,
    disabled: false,
    focused: false,
    attrs,
    setAttribute(k, v) { attrs[k] = String(v); },
    getAttribute(k) { return attrs[k]; },
    removeAttribute(k) { delete attrs[k]; },
    focus() { this.focused = true; },
    ...extra,
  };
}

function loadAdmin(fetchImpl) {
  const elements = {
    app: makeElement(),
    status: makeElement(),
    table: makeElement(),
    secret: makeElement(),
    'key-form': makeElement(),
    'key-name': makeElement(),
    'key-name-error': makeElement({hidden: true}),
    'key-expiry': makeElement(),
    'key-cancel': makeElement(),
    result: makeElement(),
  };
  const checkbox = {dataset: {group: 'Clients', right: 'read'}};
  const document = {
    documentElement: {dataset: {basePath: ''}},
    getElementById(id) { return elements[id] || null; },
    addEventListener() {},
    querySelectorAll(sel) {
      if (sel === '#key-form input[data-group]:checked') return [checkbox];
      return [];
    },
  };
  const context = {
    console,
    document,
    GoAuthyI18n: {
      messages: {},
      t(key, params) { return String(key).replace(/\{(\w+)\}/g, (_, k) => params?.[k] ?? `{${k}}`); },
    },
    location: {pathname: '/auth/v1/admin/api-keys', search: ''},
    fetch: fetchImpl,
    setTimeout,
  };
  context.globalThis = context;
  vm.runInNewContext(fs.readFileSync(__dirname + '/locale.js', 'utf8'), context);
  vm.runInNewContext(fs.readFileSync(__dirname + '/admin.js', 'utf8'), context);
  return {context, elements};
}

(async () => {
  let fetchCalls = 0;
  const {context, elements} = loadAdmin(async (url, opts) => {
    if (url === '/auth/v1/admin/csrf') {
      return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => ({token: 'csrf-1'})};
    }
    if (opts?.method === 'POST') fetchCalls++;
    return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => ({secret: 'test-only-placeholder'})};
  });

  context.apiKeyForm();
  const markup = elements.app.innerHTML;
  assert.match(markup, /id="key-name-hint"[^>]*>2–24 characters; letters, numbers, _, \/, or -/);
  assert.match(markup, /minlength="2"/);
  assert.match(markup, /maxlength="24"/);
  assert.match(markup, /pattern="\[A-Za-z0-9_\/-\]\{2,24\}"/);
  assert.match(markup, /aria-describedby="key-name-hint key-name-error"/);
  assert.match(markup, /id="key-name-error" class="error" role="alert" hidden/);

  for (const bad of ['a', 'a'.repeat(25), 'bad key!', 'key.name']) {
    elements['key-name'].value = bad;
    elements['key-name'].focused = false;
    await elements['key-form'].onsubmit({preventDefault() {}, submitter: makeElement()});
    assert.equal(fetchCalls, 0, `invalid name ${bad} must not trigger fetch`);
    assert.equal(elements['key-name'].getAttribute('aria-invalid'), 'true');
    assert.equal(elements['key-name'].focused, true);
    assert.equal(elements['key-name-error'].hidden, false);
    assert.equal(elements['key-name-error'].textContent, 'Name must be 2–24 characters using letters, numbers, _, /, or -');
    assert.equal(elements.result.className, 'error');
  }

  for (const good of ['ab', 'A1_b-2/cD3_e4-f5_g6/h789']) {
    const prev = fetchCalls;
    const submitter = makeElement();
    elements['key-name'].value = good;
    await elements['key-form'].onsubmit({preventDefault() {}, submitter});
    assert.equal(fetchCalls, prev + 1, `valid name ${good} should submit`);
    assert.equal(elements['key-name'].getAttribute('aria-invalid'), undefined);
    assert.equal(elements['key-name-error'].hidden, true);
    assert.equal(elements['key-name-error'].textContent, '');
    assert.equal(elements.result.className, 'success');
    assert.equal(elements.result.textContent, 'Secret (copy now): test-only-placeholder');
    assert.equal(submitter.disabled, true);
  }
})();
