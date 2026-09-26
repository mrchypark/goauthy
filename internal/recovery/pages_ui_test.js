// Runnable with node; exercises submission outcomes without a browser dependency.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const source = fs.readFileSync(__dirname + '/pages.js', 'utf8');
async function run(outcome) {
  let submit, writes = 0, payload;
  const button = { disabled: true };
  const status = { textContent: '', classList: { toggle() {} }, focus() {} };
  const form = { hidden: false, querySelector: () => button, addEventListener: (_, f) => { submit = f; } };
  const elements = { '#request-form': form, '#page-status': status };
  const context = { document: { body: {dataset: {base:'/tenant', mode:'request'}}, documentElement: {lang:'en'}, querySelector: (s) => elements[s] || null },
    crypto: webcrypto, TextEncoder, Date, setTimeout,
    FormData: class { *[Symbol.iterator]() { yield ['email','example@example.test']; } },
    fetch: async (url, options) => {
      assert.ok(url.startsWith('/tenant/auth/v1/'));
      assert.equal(options.credentials,'same-origin');
      assert.equal(options.cache,'no-store');
      if (url.endsWith('/pow')) return {ok:true,text:async()=>`1:10:${Math.floor(Date.now()/1000)+120}:test:test:`};
      writes++; payload = JSON.parse(options.body);
      if (outcome === 'lost') throw new Error('lost response');
      return {ok:outcome === 200,status:outcome};
    } };
  vm.runInNewContext(source,context);
  await new Promise(setImmediate);
  assert.equal(button.disabled,false);
  await submit({preventDefault(){}});
  assert.equal(writes,1);
  assert.equal(payload.email,'example@example.test');
  assert.ok(payload.pow.startsWith('1:10:'));
  if (outcome === 200) { assert.equal(form.hidden,true); assert.match(status.textContent,/If this address is eligible/); }
  else if (outcome === 'lost' || outcome === 503) {
    assert.equal(button.disabled,true); assert.match(status.textContent,/Do not resubmit/);
    await submit({preventDefault(){}}); assert.equal(writes,1);
  } else { assert.equal(button.disabled,false); assert.match(status.textContent,/could not be completed/); }
}
(async()=>{for(const outcome of [200,400,503,'lost']) await run(outcome); console.log('recovery UI submission checks passed');})().catch(error=>{console.error(error);process.exitCode=1;});
