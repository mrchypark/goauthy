const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const context = {GoAuthyI18n: {messages: {}, t(key, params) { return this.messages[key].replace(/\{(\w+)\}/g, (_, name) => params[name]); }}};
context.globalThis = context;
vm.runInNewContext(fs.readFileSync(__dirname + '/locale.js', 'utf8'), context);
assert.equal(context.GoAuthyI18n.messages.Dashboard, '대시보드');
assert.equal(context.GoAuthyI18n.messages.Menu, '메뉴');
assert.equal(context.GoAuthyI18n.t('Back to {list}', {list: '사용자'}), '사용자 목록으로 돌아가기');
const localizedKeys = [
  'Name', 'Metadata', 'Optional JSON value', 'Create', 'Save changes', 'Cancel', 'Delete', 'Saved',
  'New role', 'New group', 'Manage roles through the live authorization service.',
  'Manage groups through the live authorization service.', '{count} roles', '{count} groups',
  '{count} users', 'Metadata must be valid JSON', 'Request outcome is unknown. Check the current state before retrying.', 'Saving…', 'Creating…',
  'Deleting…', 'Rotating…', 'Expiry must be a safe integer of at least 1719784800',
  'Create a named authorization entity.', 'Update {name} and preserve its immutable ID.',
  'Create user', 'Edit user', 'Send an activation email to a new user.', 'Email', 'Given name',
  'Family name', 'Language', 'Roles', 'Groups', 'roles', 'groups', 'Comma-separated names', 'Preferred username',
  'Time zone', 'Optional IANA name, for example Asia/Seoul', 'Account expiry',
  'Unix seconds; blank means no expiry', 'Unix seconds; blank clears', 'New password',
  'Leave blank to keep current', 'Enabled', 'Email verified', 'Subject {subject}',
  'New API key', 'Expiry', 'Never',
  'Delete subject {subject} permanently?', 'Delete {kind} permanently?', 'Delete user',
  'Delete API key permanently?', 'Expiry must be a safe integer of at least 1719784800',
  'Edit API key', 'Update rights and expiry; the name is immutable.',
  'Create a key with at least one access right.', 'Create key',
  'Select at least one access right', 'Secret (copy now): {secret}', 'Done',
  'Manage access rights and expiry. Plaintext secrets are shown once and are not stored.',
  'API-key permissions do not grant API-key management. Manage keys with an administrator browser session.',
  '{count} keys', 'Expires', 'Rotate', 'Rotated secret (copy now): {secret}',
];
for (const key of localizedKeys) assert.ok(context.GoAuthyI18n.messages[key], `missing Korean translation: ${key}`);
const apiKeyPermissionLabels = ['Blacklist', 'Clients', 'Events', 'Generic', 'Groups', 'Roles', 'Secrets', 'Sessions', 'Scopes', 'UserAttributes', 'Users', 'Pam', 'AuthProviders', 'ApiKeys', 'read', 'create', 'update', 'delete'];
for (const key of apiKeyPermissionLabels) assert.ok(context.GoAuthyI18n.messages[key], `missing Korean permission label: ${key}`);
assert.equal(context.GoAuthyI18n.t('Delete subject {subject} permanently?', {subject: 'alice'}), 'alice 사용자를 영구 삭제할까요?');
assert.equal(context.GoAuthyI18n.t('{count} groups', {count: 0}), '그룹 0개');
assert.equal(context.GoAuthyI18n.t('New group'), '새 그룹');
assert.equal(context.GoAuthyI18n.t('Back to {list}', {list: context.GoAuthyI18n.t('groups')}), '그룹 목록으로 돌아가기');
assert.equal(context.GoAuthyI18n.t('Metadata must be valid JSON'), '메타데이터는 올바른 JSON 형식이어야 합니다.');
assert.equal(context.GoAuthyI18n.t('Request outcome is unknown. Check the current state before retrying.'), '요청 결과를 확인할 수 없습니다. 다시 시도하기 전에 현재 상태를 확인하세요.');
const adminJS = fs.readFileSync(__dirname + '/admin.js', 'utf8');
for (const key of localizedKeys.filter(key => key !== 'roles' && key !== 'groups')) assert.ok([`t('${key}'`, `?'${key}'`, `:'${key}'`].some(use => adminJS.includes(use)), `admin.js does not use translation key: ${key}`);
assert.ok(adminJS.includes('list:t(list)'), 'admin.js should localize the current list name in its back link');
assert.match(adminJS, /subject:esc\(id\)/);
assert.match(adminJS, /data-subject="\$\{esc\(id\)\}"/);
const apiKeyForm = adminJS.slice(adminJS.indexOf('function apiKeyForm'), adminJS.indexOf('async function apiKeys'));
assert.match(apiKeyForm, /href="\/auth\/v1\/admin\/api-keys">\$\{t\('Back to \{list\}',\{list:t\('API keys'\)\}\)\}<\/a><\/p><p class="hint">\$\{t\('API-key permissions do not grant API-key management\. Manage keys with an administrator browser session\.'\)\}<\/p><div class="panel"><form id="key-form"/);
assert.match(adminJS, /<legend>\$\{t\(g\)\}<\/legend>/);
assert.match(adminJS, /data-group="\$\{g\}" data-right="\$\{r\}"/);
assert.match(adminJS, /\$\{t\(r\)\}<\/label>/);
assert.match(adminJS, /t\('Manage access rights and expiry\. Plaintext secrets are shown once and are not stored\.'/);
assert.equal(context.GoAuthyI18n.t('Back to {list}', {list: context.GoAuthyI18n.t('API keys')}), 'API 키 목록으로 돌아가기');
assert.equal(context.GoAuthyI18n.t('Generic'), '일반');
assert.equal(context.GoAuthyI18n.t('UserAttributes'), '사용자 속성');
assert.equal(context.GoAuthyI18n.t('AuthProviders'), '인증 공급자');
assert.equal(context.GoAuthyI18n.t('read'), '읽기');
assert.equal(context.GoAuthyI18n.t('create'), '만들기');
assert.equal(context.GoAuthyI18n.t('update'), '수정');
assert.equal(context.GoAuthyI18n.t('delete'), '삭제');
assert.equal(context.GoAuthyI18n.t('API-key permissions do not grant API-key management. Manage keys with an administrator browser session.'), 'API 키 권한으로는 API 키를 관리할 수 없습니다. 관리자 브라우저 세션으로 관리하세요.');
assert.equal(context.GoAuthyI18n.t('Manage access rights and expiry. Plaintext secrets are shown once and are not stored.'), '접근 권한과 만료 시간을 관리합니다. 평문 비밀 값은 한 번만 표시되며 저장되지 않습니다.');
const html = fs.readFileSync(__dirname + '/admin.html', 'utf8');
assert.match(html, /src="\/auth\/v1\/branding\/locale\.js" defer/);
assert.match(html, /data-language-select/);
assert.match(html, /id="admin-menu-toggle"[^>]*aria-controls="admin-navigation"[^>]*aria-expanded="false"[^>]*data-i18n="Menu"/);
assert.match(html, /<nav id="admin-navigation"/);
assert.match(html, /<body data-locale-mode="reload">/);
assert.match(html, /href="\/oidc\/logout"/);
assert.match(adminJS, /document\.documentElement\?\.dataset\?\.basePath/);
assert.match(adminJS, /GoAuthyI18n\?\.setBusy\?\.\(true\)/);
assert.ok(adminJS.includes("if(e.target.id!=='admin-menu-toggle')return"));
assert.ok(adminJS.includes("document.getElementById?.('admin-menu-toggle')"));
assert.ok(adminJS.includes("document.getElementById?.('admin-navigation')"));
assert.ok(adminJS.includes("if(!button||!nav)return;button.setAttribute('aria-expanded',String(button.getAttribute('aria-expanded')!=='true'))"));
console.log('admin locale checks passed');
