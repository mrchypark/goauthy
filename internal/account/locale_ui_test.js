'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const messages = {};
const context = { GoAuthyI18n: { messages } };
context.globalThis = context;
vm.runInNewContext(fs.readFileSync(__dirname + '/locale.js', 'utf8'), context);

for (const file of ['dashboard.js', 'connections.js', 'connection_grants.js', 'devices.js']) {
  const source = fs.readFileSync(__dirname + '/' + file, 'utf8');
  const keys = [...source.matchAll(/\bt\('((?:\\.|[^'])*)'/g)].map((match) => match[1].replace(/\\n/g, '\n').replace(/\\'/g, "'").replace(/\\\\/g, '\\'));
  for (const key of new Set(keys)) assert.ok(Object.hasOwn(messages, key), `${file}: missing Korean message for ${key}`);
}
const html = fs.readFileSync(__dirname + '/dashboard.html', 'utf8');
for (const match of html.matchAll(/\bdata-i18n(?:-label)?="([^"]+)"/g)) {
  assert.ok(Object.hasOwn(messages, match[1]), `dashboard.html: missing Korean message for ${match[1]}`);
}

assert.equal(messages['I reviewed this provider and its allowed operations. Store my key with these settings. This does not authorize a consumer service to use it.'], '이 제공자와 허용된 작업을 검토했습니다. 이 설정으로 키를 저장합니다. 소비자 서비스의 사용을 허용하는 것은 아닙니다.');
assert.equal(messages['Unable to load provider settings. Close and reopen to review them before saving. An existing key can still be revoked.'], '제공자 설정을 불러올 수 없습니다. 저장하기 전에 닫았다가 다시 열어 설정을 검토하세요. 기존 키는 계속 취소할 수 있습니다.');
console.log('account locale checks passed');
