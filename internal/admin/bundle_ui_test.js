const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const handler = fs.readFileSync(__dirname + '/ui.go', 'utf8');
const units = handler.match(/if r\.URL\.Path == "\/auth\/v1\/admin\/app\.js" \{[\s\S]*?\[\]string\{([^}]+)\}/);
assert.ok(units, 'admin app bundle assembly must be found in its HTTP handler');
const names = [...units[1].matchAll(/"([^"]+\.js)"/g)].map(match => match[1]);
assert.ok(names.includes('themes.js') && names.includes('admin.js'));
// Match the HTTP handler's source order and separator without executing browser actions.
const bundle = names.map(name => fs.readFileSync(__dirname + '/' + name, 'utf8') + '\n;\n').join('');
new vm.Script(bundle, {filename: '/auth/v1/admin/app.js'});
console.log('admin app bundle parses successfully');
