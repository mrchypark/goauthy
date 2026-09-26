const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function page(language, protocol='https:') {
 const handlers={}, selectHandlers={}, dialogs=[], labels=[{textContent:'',getAttribute:name=> name==='data-i18n'?'Account':null}];
 const select={value:'',disabled:false,setAttribute(){},addEventListener(n,f){selectHandlers[n]=f},dispatchEvent(e){selectHandlers[e.type]?.()}};
 function element(tag) { const events={}; const el={tag,children:[],textContent:'',setAttribute(){},addEventListener(n,f){events[n]=f},append(...items){this.children.push(...items)},showModal(){dialogs.push(this)},focus(){},close(){events.close?.()},remove(){},click(){events.click?.()}}; return el; }
 const document={createElement:element,body:{dataset:{localeMode:"reload"},append(){}},currentScript:{src:'https://auth.test/tenant/auth/v1/branding/locale.js'},documentElement:{lang:language},cookie:'',querySelectorAll(s){return s==='[data-language-select]'?[select]:s==='[data-i18n]'?labels:[]},addEventListener(n,f){handlers[n]=f}};
 let reloads=0, confirms=0, accepted=true;
 const context={document,URL,Event:class{constructor(type){this.type=type}},location:{protocol,reload(){reloads++}},window:{confirm(){confirms++;return accepted}}};
 vm.runInNewContext(fs.readFileSync(__dirname+'/assets/locale.js','utf8'),context);
 context.GoAuthyI18n.messages.Account='계정';handlers.DOMContentLoaded();
 return {context,document,select,labels,dialogs,change(v){select.value=v;selectHandlers.change()},dirty(){handlers.input({target:{matches:s=>s==='input,textarea,select'}})},reject(){accepted=false},stats:()=>({reloads,confirms})};
}
const ko=page('ko');assert.equal(ko.labels[0].textContent,'계정');assert.equal(ko.select.value,'ko');
assert.equal(ko.context.GoAuthyI18n.t('Hello {name}',{name:'<script>'}),'Hello <script>');
ko.change('en');assert.equal(ko.document.cookie,'goauthy_ui_locale=en; Path=/tenant/; Max-Age=31536000; SameSite=Lax; Secure');assert.equal(ko.stats().reloads,1);
const en=page('en','http:');en.dirty();en.change('ko');assert.equal(en.dialogs.length,1);en.dialogs[0].children[1].click();assert.equal(en.select.value,'en');assert.equal(en.stats().reloads,0);
en.context.GoAuthyI18n.setBusy(true);en.change('ko');assert.equal(en.select.disabled,true);assert.equal(en.stats().confirms,0);en.context.GoAuthyI18n.setBusy(false);assert.equal(en.select.disabled,false);
console.log('locale selection, persistence, dirty form and pending-operation checks passed');

const inline=page('en');inline.document.body.dataset.localeMode='in-place';inline.dirty();inline.change('ko');assert.equal(inline.stats().reloads,0);assert.equal(inline.stats().confirms,0);assert.equal(inline.document.documentElement.lang,'ko');assert.equal(inline.labels[0].textContent,'계정');

const discard=page('en');discard.dirty();discard.change('ko');discard.dialogs[0].children[2].click();assert.equal(discard.stats().reloads,1);assert.match(discard.document.cookie,/goauthy_ui_locale=ko/);

const branded=page('en');branded.document.body.dataset.localeMode='in-place';
branded.labels[0].getAttribute=name=>({'data-i18n':'Sign in','data-brand-en':'Welcome <team>','data-brand-ko':'팀에 오신 것을 환영합니다'}[name]||null);
branded.context.GoAuthyI18n.translate();assert.equal(branded.labels[0].textContent,'Welcome <team>');
branded.change('ko');assert.equal(branded.labels[0].textContent,'팀에 오신 것을 환영합니다');
