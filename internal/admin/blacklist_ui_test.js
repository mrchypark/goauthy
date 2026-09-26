const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const source = fs.readFileSync(__dirname + '/blacklist.js', 'utf8');
const nodes = new Map(), calls = [];
const node = id => nodes.get(id) || (nodes.set(id, {id, innerHTML: '', textContent: '', className: '', value: '', disabled: false, dataset: {}}), nodes.get(id));
const ctx = {
  console, document: {getElementById: node}, encodeURIComponent, confirm: () => true,
  esc: value => String(value ?? ''),
  shell: (_title, _subtitle, body) => { node('app').innerHTML = body; for (const match of body.matchAll(/id="([^"]+)"/g)) node(match[1]); },
  api: async (path, opts = {}) => { calls.push({path, opts}); return opts.method ? {} : {ips: [{ip: '203.0.113.0/24', exp: 2_000_000_000}]}; },
};
vm.runInNewContext(source, ctx);

(async () => {
  await ctx.blacklist();
  assert.match(node('app').innerHTML, /IP prefix/);
  assert.match(node('app').innerHTML, /id="bl-exp" type="datetime-local" required/);
  assert.doesNotMatch(node('app').innerHTML, /auto-blacklist|bl-comment|blacklist\/auto/i);
  assert.match(node('bl-list').innerHTML, /203\.0\.113\.0\/24/);

  node('bl-ip').value = '198.51.100.0/24';
  node('bl-exp').value = '2099-01-02T03:04';
  await node('bl-add').onsubmit({preventDefault() {}});
  const created = calls.find(call => call.opts.method === 'POST');
  assert.equal(created.path, '/auth/v1/blacklist');
  assert.deepEqual(Object.keys(JSON.parse(created.opts.body)).sort(), ['exp', 'ip']);

  ctx.api = async (path, opts = {}) => { calls.push({path, opts}); throw Error('404 Not Found'); };
  await ctx.blacklist();
  assert.match(node('bl-list').innerHTML, /not enabled in this deployment/);
  assert.equal(node('bl-ip').disabled, true);
  assert.equal(node('bl-exp').disabled, true);
  assert.equal(node('bl-submit').disabled, true);
  console.log('blacklist UI behavioral checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
