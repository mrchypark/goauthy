const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const i18n = {messages: {}};
vm.runInNewContext(fs.readFileSync(__dirname + '/module_locale.js', 'utf8'), {globalThis: {GoAuthyI18n: i18n}});
for (const key of ['State', 'Rows', 'Apply', 'Global logout', 'Client ID', 'Authentication method', 'Event Log', 'Expiry must be in the future']) {
  assert.ok(i18n.messages[key], `missing Korean translation for ${key}`);
}
assert.equal(i18n.messages['Delete client {id} permanently?'], '클라이언트 {id}을(를) 영구 삭제하시겠습니까?');
assert.equal(i18n.messages['Back to dashboard'], '대시보드로 돌아가기');
assert.equal(i18n.messages['Common logo'], '공통 로고');
assert.equal(i18n.messages['Current common logo'], '현재 공통 로고');
assert.equal(i18n.messages['Remove this common logo?'], '공통 로고를 삭제하시겠습니까?');
assert.match(i18n.messages['Account creation requires email delivery.'], /이메일 발송/);
assert.match(i18n.messages['Account creation requires email delivery. Administrator access requires the goauthy_admin role.'], /goauthy_admin/);
for (const [key, value] of Object.entries({Operators: '운영자', 'Service users': '서비스 사용자', 'New operator': '새 운영자', 'Create operator': '운영자 만들기', 'Edit operator': '운영자 수정'})) {
  assert.equal(i18n.messages[key], value);
}
assert.match(i18n.messages['Operator listing does not grant administrator access; roles determine access.'], /관리자 권한/);
console.log('admin module locale checks passed');
