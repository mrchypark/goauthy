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

async function registrationFields() {
  const created = [];
  const element = () => ({children:[], append(child){this.children.push(child);}});
  const button = {disabled:true};
  const form = {querySelector:()=>button, addEventListener(){}};
  const fields = element();
  const prototype = {cloneNode(deep){assert.equal(deep,true);const input = {className:'ely-input',dataset:{slot:'input'}};created.push(input);return input;}};
  const elements = {'#request-form':form,'#registration-fields':fields,'#registration-input':{content:{firstElementChild:prototype}}};
  const context = {document:{body:{dataset:{base:'/tenant',mode:'register'}},documentElement:{lang:'en'},querySelector:s=>elements[s]||null,createElement:element},crypto:webcrypto,
    fetch:async()=>({ok:true,json:async()=>({preferred_username:{preferred_username:'required',pattern_html:'[a-z]+'},birthdate:'required',phone:'optional',given_name:'hidden'})})};
  vm.runInNewContext(source,context);
  await new Promise(setImmediate);
  assert.equal(button.disabled,false);
  assert.ok(created.every(input=>input.dataset.slot==='input'&&input.maxLength===128));
  assert.ok(!created.some(input=>input.name==='given_name'));
  const username=created.find(input=>input.name==='preferred_username');assert.equal(username.required,true);assert.equal(username.pattern,'[a-z]+');
  assert.equal(created.find(input=>input.name==='birthdate').type,'date');
  const phone=created.find(input=>input.name==='phone');assert.equal(phone.type,'tel');assert.equal(phone.placeholder,'+821012345678');assert.equal(phone.required,false);
}
registrationFields().catch(error=>{console.error(error);process.exitCode=1;});
