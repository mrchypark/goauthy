const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function page(language, protocol='https:') {
 const handlers={}, selectHandlers={}, loginHandlers={}, windowHandlers={}, dialogs=[], labels=[{textContent:'',getAttribute:name=> name==='data-i18n'?'Account':null}];
 const select={value:'',disabled:false,setAttribute(){},addEventListener(n,f){selectHandlers[n]=f},dispatchEvent(e){selectHandlers[e.type]?.()}};
 const progress={hidden:true,textContent:'Signing in…',getAttribute(name){return name==='data-i18n'?'Signing in…':null}};
 const loginForm={attributes:{},addEventListener(n,f){loginHandlers[n]=f},setAttribute(name,value){this.attributes[name]=value},removeAttribute(name){delete this.attributes[name]}};
 function element(tag) { const events={},attributes={}; const el={tag,children:[],textContent:'',attributes,setAttribute(name,value){attributes[name]=value},getAttribute(name){return attributes[name]??null},addEventListener(n,f){events[n]=f},append(...items){this.children.push(...items)},showModal(){dialogs.push(this)},focus(){},close(){events.close?.()},remove(){},click(){events.click?.()}}; return el; }
 const document={createElement:element,body:{dataset:{localeMode:"reload"},append(){}},currentScript:{src:'https://auth.test/tenant/auth/v1/branding/locale.js'},documentElement:{lang:language},cookie:'',getElementById(id){return id==='login-form'?loginForm:null},querySelector(s){return s==='[data-login-progress]'?progress:null},querySelectorAll(s){return s==='[data-language-select]'?[select]:s==='[data-i18n]'?[...labels,progress]:[]},addEventListener(n,f){handlers[n]=f}};
 let reloads=0, confirms=0, accepted=true;
 const context={document,URL,Event:class{constructor(type){this.type=type}},location:{protocol,reload(){reloads++}},window:{addEventListener(n,f){windowHandlers[n]=f},confirm(){confirms++;return accepted}}};
 vm.runInNewContext(fs.readFileSync(__dirname+'/assets/locale.js','utf8'),context);
 context.GoAuthyI18n.messages.Account='계정';handlers.DOMContentLoaded();
 return {context,document,select,labels,dialogs,loginForm,progress,submitLogin(event){loginHandlers.submit(event)},pageshow(event){windowHandlers.pageshow(event)},change(v){select.value=v;selectHandlers.change()},dirty(){handlers.input({target:{matches:s=>s==='input,textarea,select'}})},reject(){accepted=false},stats:()=>({reloads,confirms})};
}
const ko=page('ko');assert.equal(ko.labels[0].textContent,'계정');assert.equal(ko.select.value,'ko');
assert.equal(ko.context.GoAuthyI18n.t('Login failed'),'로그인하지 못했습니다');
assert.equal(ko.context.GoAuthyI18n.t('Check your username or password'),'사용자 이름 또는 비밀번호를 확인하세요.');
assert.equal(ko.context.GoAuthyI18n.t('Too many attempts'),'시도 횟수가 많습니다.');
assert.equal(ko.context.GoAuthyI18n.t('Sign-in temporarily unavailable'),'로그인 서비스를 일시적으로 사용할 수 없습니다.');
assert.equal(ko.context.GoAuthyI18n.t('Your account could not be loaded.'),'계정을 불러올 수 없습니다.');
assert.equal(ko.context.GoAuthyI18n.t('Please check this message.'),'메시지를 확인해 주세요.');
assert.equal(ko.context.GoAuthyI18n.t('Passkey sign-in failed'),'패스키 로그인에 실패했습니다.');
assert.equal(ko.context.GoAuthyI18n.t('Please try your passkey again.'),'패스키로 다시 시도하세요.');
assert.equal(ko.context.GoAuthyI18n.t('Check the code and try again.'),'인증 코드를 확인하고 다시 시도하세요.');
assert.equal(ko.context.GoAuthyI18n.t('Hello {name}',{name:'<script>'}),'Hello <script>');
ko.change('en');assert.equal(ko.document.cookie,'goauthy_ui_locale=en; Path=/tenant/; Max-Age=31536000; SameSite=Lax; Secure');assert.equal(ko.stats().reloads,1);
const en=page('en','http:');en.dirty();en.change('ko');assert.equal(en.dialogs.length,1);en.dialogs[0].children[1].click();assert.equal(en.select.value,'en');assert.equal(en.stats().reloads,0);
en.context.GoAuthyI18n.setBusy(true);en.change('ko');assert.equal(en.select.disabled,true);assert.equal(en.stats().confirms,0);en.context.GoAuthyI18n.setBusy(false);assert.equal(en.select.disabled,false);
console.log('locale selection, persistence, dirty form and pending-operation checks passed');

const inline=page('en');inline.document.body.dataset.localeMode='in-place';inline.dirty();inline.change('ko');assert.equal(inline.stats().reloads,0);assert.equal(inline.stats().confirms,0);assert.equal(inline.document.documentElement.lang,'ko');assert.equal(inline.labels[0].textContent,'계정');

const dynamicError=page('en');dynamicError.document.body.dataset.localeMode='in-place';
const dynamicTitle={textContent:'',attributes:{'data-i18n':'Passkey sign-in failed'},getAttribute(name){return this.attributes[name]??null}};
const dynamicDetail={textContent:'',attributes:{'data-i18n':'Please try your passkey again.'},getAttribute(name){return this.attributes[name]??null}};
dynamicError.labels.push(dynamicTitle,dynamicDetail);dynamicError.change('ko');
assert.equal(dynamicTitle.textContent,'패스키 로그인에 실패했습니다.');
assert.equal(dynamicDetail.textContent,'패스키로 다시 시도하세요.');

const discard=page('en');discard.dirty();discard.change('ko');discard.dialogs[0].children[2].click();assert.equal(discard.stats().reloads,1);assert.match(discard.document.cookie,/goauthy_ui_locale=ko/);

const branded=page('en');branded.document.body.dataset.localeMode='in-place';
branded.labels[0].getAttribute=name=>({'data-i18n':'Sign in','data-brand-en':'Welcome <team>','data-brand-ko':'팀에 오신 것을 환영합니다'}[name]||null);
branded.context.GoAuthyI18n.translate();assert.equal(branded.labels[0].textContent,'Welcome <team>');
branded.change('ko');assert.equal(branded.labels[0].textContent,'팀에 오신 것을 환영합니다');

const login=page('en');let firstPrevented=false;
login.submitLogin({defaultPrevented:true,preventDefault(){throw new Error('already-canceled submit was changed')}});
assert.equal(login.progress.hidden,true);assert.equal(login.loginForm.attributes['aria-busy'],undefined);
login.submitLogin({preventDefault(){firstPrevented=true}});
assert.equal(firstPrevented,false);assert.equal(login.progress.hidden,false);assert.equal(login.progress.textContent,'Signing in…');assert.equal(login.loginForm.attributes['aria-busy'],'true');
login.pageshow({persisted:false});assert.equal(login.progress.hidden,true);assert.equal(login.loginForm.attributes['aria-busy'],undefined);
login.submitLogin({preventDefault(){throw new Error('native submission was prevented')}});
assert.equal(login.progress.hidden,false);assert.equal(login.loginForm.attributes['aria-busy'],'true');
login.pageshow({persisted:true});assert.equal(login.progress.hidden,true);assert.equal(login.loginForm.attributes['aria-busy'],undefined);
assert.equal(page('ko').progress.textContent,'로그인 중…');
