// Run with node: verifies reset-stage bindings without entering credentials in a browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/pages.js', 'utf8');
async function check(outcome) {
  let begin, submit, writes = 0, cleared = 0;
  const button = {disabled:false};
  const status = {textContent:'',classList:{toggle(){}},focus(){}};
  const start = {addEventListener(_,fn){begin=fn;}};
  const reset = {hidden:true,elements:{password:{value:'fixture-password',focus(){}},confirm:{value:'different'}},
    querySelector(){return button;},addEventListener(_,fn){submit=fn;},reset(){cleared++;this.elements.password.value='';this.elements.confirm.value='';}};
  const nodes = {'#reset-start':start,'#reset-form':reset,'#page-status':status,'#password-policy':{}};
  vm.runInNewContext(source, {document:{body:{dataset:{base:'/tenant',mode:'reset'}},documentElement:{lang:'en'},querySelector:s=>nodes[s]},
    location:{pathname:'/tenant/auth/v1/users/subject/reset/test-token'},
    fetch:async (url,options)=>{
      assert.equal(options.credentials,'same-origin');
      if (!options.method) {
        assert.equal(url,'/tenant/auth/v1/users/subject/reset/test-token');
        assert.equal(options.headers.Accept,'application/json');
        return {ok:true,json:async()=>({csrf_token:'csrf-fixture',password_policy:{length_min:12,length_max:128,lower_case:1,upper_case:1,digits:1,special:1}})};
      }
      writes++;
      assert.equal(url,'/tenant/auth/v1/users/subject/reset');
      assert.equal(options.method,'PUT');
      assert.equal(options.headers['X-Pwd-CSRF-Token'],'csrf-fixture');
      assert.deepEqual(JSON.parse(options.body),{magic_link_id:'test-token',password:'fixture-password'});
      if (outcome==='lost') throw Error('lost');
      return {status:outcome};
    }});
  await begin();
  assert.equal(reset.hidden,false); assert.equal(start.hidden,true);
  assert.match(nodes['#password-policy'].textContent,/12–128/);
  await submit({preventDefault(){}});
  assert.equal(writes,0); assert.match(status.textContent,/do not match/);
  reset.elements.confirm.value='fixture-password';
  await submit({preventDefault(){}});
  assert.equal(writes,1);
  if(outcome===202){assert.equal(reset.hidden,true);assert.equal(cleared,1);assert.match(status.textContent,/Password saved/);}
  else if(outcome===400){assert.equal(button.disabled,false);assert.equal(cleared,0);}
  else {assert.equal(cleared,1);assert.equal(button.disabled,true);assert.match(status.textContent,/Do not resubmit/);}
  if(outcome!==400){await submit({preventDefault(){}});assert.equal(writes,1);}
}
(async()=>{for(const outcome of [202,400,503,'lost'])await check(outcome);console.log('reset UI outcomes passed');})().catch(e=>{console.error(e);process.exitCode=1;});
