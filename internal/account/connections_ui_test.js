const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(id = '') { this.id = id; this.children = []; this.dataset = {}; this.hidden = false; this.disabled = false; this.value = ''; this.checked = false; this._textContent = ''; this.listeners = {}; this.className = ''; this.tagName = ''; }
  get textContent() { return this._textContent; }
  set textContent(value) { this._textContent = String(value ?? ''); this.children = []; }
  append(...items) { this.children.push(...items); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  querySelectorAll(selector) {
    const all = [];
    const walk = (item) => { (item.children || []).forEach((child) => { if (selector === '[data-connection-field]' && child.dataset.connectionField) all.push(child); if (selector === 'input,select,textarea,button' && ['INPUT', 'SELECT', 'TEXTAREA', 'BUTTON'].includes(child.tagName)) all.push(child); if (selector === 'button' && child.tagName === 'BUTTON') all.push(child); walk(child); }); };
    walk(this); return all;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
function run() {
  const ids = ['connections-section', 'connections-refresh', 'connections-collection', 'connections-form', 'connections-fields', 'connections-save', 'connections-cancel', 'connections-list', 'connections-status'];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element(id)]));
  elements['connections-refresh'].tagName = 'BUTTON'; elements['connections-save'].tagName = 'BUTTON'; elements['connections-collection'].tagName = 'SELECT';
  elements['connections-form'].querySelectorAll = Element.prototype.querySelectorAll;
  const calls = []; let conflict = false;
  const definition = { id: 'github', name: 'GitHub', enabled: true, revision: 7, fields: [{ name: 'enabled', type: 'boolean', required: true }, { name: 'count', type: 'integer', required: true }, { name: 'label', type: 'string', required: false, max_length: 32 }] };
  const response = (value) => Promise.resolve({ ok: true, status: 200, text: async () => JSON.stringify(value) });
  const context = {
    console, CSS: { escape: (x) => x },
    document: { querySelector: (selector) => selector.startsWith('#') ? elements[selector.slice(1)] : null, createElement: (tag) => { const e = new Element(); e.tagName = tag.toUpperCase(); return e; } },
    confirm: () => true,
    accountDashboard: {
      state: { csrf: 'csrf-1' }, ready: Promise.resolve(),
      connectionDeps: {
        status: (id, message, error) => { elements[id].textContent = message; elements[id].className = error ? 'status error' : 'status'; },
        request: async (url, options = {}) => {
          calls.push({ url, options });
          if (conflict) throw new Error('Request failed (409).');
          if (url.endsWith('/auth-collections')) return response([definition]);
          if (url.endsWith('/connections/github') && (!options.method || options.method === 'GET')) return response([]);
          if (url.includes('/connections/conn-1')) return response({});
          return response({});
        },
        jsonRequest: async () => { throw new Error('unexpected jsonRequest'); },
      },
    },
  };
  vm.runInNewContext(fs.readFileSync(__dirname + '/connections.js', 'utf8'), context);
  return context.accountDashboard.ready.then(async () => {
    await context.accountDashboard.connections.loadDefinitions();
    assert.equal(calls[0].url, '/auth/v1/account/auth-collections');
    const field = (name) => elements['connections-fields'].children.find((item) => item.dataset && item.dataset.connectionField === name);
    field('enabled').checked = false;
    field('count').value = '9007199254740993';
    field('label').value = 'draft';
    await context.accountDashboard.connections.saveConnection({ preventDefault() {} });
    const create = calls.find((item) => item.options.method === 'POST');
    assert.equal(create.options.headers['X-CSRF-Token'], 'csrf-1');
    assert.equal(create.options.body, '{"definition_revision":7,"metadata":{"enabled":false,"count":9007199254740993,"label":"draft"}}');
    context.accountDashboard.connections.state.connections = [{ id: 'conn-1', revision: 4, state: 'draft', metadata: { enabled: true, count: 0, label: 'old' } }];
    context.accountDashboard.connections.state.editing = context.accountDashboard.connections.state.connections[0];
    field('enabled').checked = true; field('count').value = '0'; field('label').value = 'edited';
    await context.accountDashboard.connections.saveConnection({ preventDefault() {} });
    const update = calls.find((item) => item.options.method === 'PUT');
    assert.equal(update.options.headers['If-Match'], '"4"');
    assert.equal(update.options.body, '{"definition_revision":7,"metadata":{"enabled":true,"count":0,"label":"edited"}}');
    assert.equal(field('label').tagName, 'TEXTAREA');
    context.accountDashboard.connections.state.editing = { id: 'conn-1', revision: 5, metadata: { label: '' } };
    field('count').value = '0'; field('label').value = '';
    await context.accountDashboard.connections.saveConnection({ preventDefault() {} });
    assert.equal(JSON.parse(calls.filter(item => item.options.method === 'PUT').at(-1).options.body).metadata.label, '');
    field('count').value = '0'; field('label').value = ' first\nsecond ';
    await context.accountDashboard.connections.saveConnection({ preventDefault() {} });
    assert.equal(JSON.parse(calls.filter(item => item.options.method === 'POST').at(-1).options.body).metadata.label, ' first\nsecond ');
    context.accountDashboard.connections.state.connections = [{ id: 'conn-1', revision: 4, state: 'draft', metadata: {} }];
    context.confirm = () => true;
    await context.accountDashboard.connections.deleteConnection(context.accountDashboard.connections.state.connections[0]);
    const deletion = calls.find((item) => item.options.method === 'DELETE');
    assert.equal(deletion.options.headers['If-Match'], '"4"');
    assert.equal(deletion.options.body, '');
    conflict = true;
    await context.accountDashboard.connections.deleteConnection({ id: 'conn-1', revision: 4 });
    assert.match(elements['connections-status'].textContent, /changed elsewhere/);
    console.log('connections UI checks passed');
  });
}
run().catch((error) => { console.error(error); process.exitCode = 1; });
