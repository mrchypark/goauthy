const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const i18n = {messages: {}};
vm.runInNewContext(fs.readFileSync(__dirname + '/module_locale.js', 'utf8'), {globalThis: {GoAuthyI18n: i18n}});
for (const key of ['State', 'Rows', 'Apply', 'Global logout', 'Client ID', 'Authentication method', 'Event Log', 'Expiry must be in the future']) {
  assert.ok(i18n.messages[key], `missing Korean translation for ${key}`);
}
assert.equal(i18n.messages['Delete client {id} permanently?'], '클라이언트 {id}을(를) 영구 삭제하시겠습니까?');
console.log('admin module locale checks passed');
