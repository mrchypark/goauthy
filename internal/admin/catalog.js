// Custom claims catalog UI; invoked by admin.js with its shared API and rendering helpers.
function catalog(kind, id) {
  const t = globalThis.GoAuthyI18n?.t || ((key, values = {}) => String(key).replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match));
  const attribute = kind === 'attributes', label = attribute ? 'attribute' : 'scope';
  const endpoint = attribute ? '/auth/v1/users/attr' : '/auth/v1/scopes';
  const current = arguments.length > 2 ? arguments[2] : null;
  if (id === 'new') return catalogForm(kind, null, {}, t);
  if (id != null && !current) return api(endpoint).then(data => {
    const rows = attribute ? (data && data.values || []) : (Array.isArray(data) ? data : []);
    const found = rows.find(x => (attribute ? x.name : x.scope) === id);
    if (!found) throw Error(t('Could not find {kind} {name}', {kind: label, name: id}));
    return catalog(kind, id, found);
  }).catch(error => { shell(t('Catalog entry unavailable'), '', '<p class="error">' + esc(error.message) + '</p><p><a class="button secondary" href="/auth/v1/admin/' + kind + '">' + esc(t('Back to {list}', {list: t(kind)})) + '</a></p>'); });
  if (id != null) return catalogForm(kind, id, current || {}, t);
  return catalogList(kind, endpoint, label, attribute, t);
}

async function catalogList(kind, endpoint, label, attribute, t = key => key) {
  const h = (key, values) => esc(t(key, values));
  shell(t(attribute ? 'User attributes' : 'Scopes'), t('Manage the live custom-claims catalog.'), '<div class="toolbar"><span class="hint" id="catalog-status">' + h('Loading…') + '</span><a class="button" id="catalog-new" href="/auth/v1/admin/' + kind + '/new">' + h(attribute ? 'New attribute' : 'New scope') + '</a></div><div id="catalog-list"></div>');
  try {
    const data = await api(endpoint), rows = attribute ? (data && data.values || []) : (Array.isArray(data) ? data : []);
    document.getElementById('catalog-status').textContent = t('{count} {kind}', {count: rows.length, kind: t(rows.length === 1 ? label : label + 's')});
    document.getElementById('catalog-list').innerHTML = rows.length
      ? '<table><thead><tr><th>' + h('Name') + '</th><th>' + h('Details') + '</th></tr></thead><tbody>' + rows.map(x => {
        const name = attribute ? x.name : x.scope;
        const details = attribute ? (x.typ || '—') : t('{accessCount} access, {idCount} ID', {accessCount: (x.attr_include_access || []).length, idCount: (x.attr_include_id || []).length});
        return '<tr><td><a href="/auth/v1/admin/' + kind + '/' + encodeURIComponent(name) + '">' + esc(name) + '</a></td><td>' + esc(details) + '</td></tr>';
      }).join('') + '</tbody></table>'
      : '<p class="state">' + h('No {kind} entries yet. Create the first one above.', {kind: t(label + 's')}) + '</p>';
  } catch (error) {
    document.getElementById('catalog-list').innerHTML = '<p class="error">' + h('Could not load {kind}: {message}', {kind: t(label + 's'), message: error.message}) + '</p>';
  }
}

function catalogForm(kind, id, value, t = key => key) {
  const h = (key, values) => esc(t(key, values));
  const attribute = kind === 'attributes', label = attribute ? 'attribute' : 'scope', editing = id != null;
  const name = attribute ? value.name : value.scope;
  const nameInput = '<label for="catalog-name">' + h('Name') + '<input id="catalog-name" required value="' + esc(name) + '"></label>';
  const fields = attribute
    ? '<label for="catalog-desc">' + h('Description') + ' <span class="hint">' + h('Optional, 128 characters max') + '</span><input id="catalog-desc" maxlength="128" value="' + esc(value.desc) + '"></label><label for="catalog-default">' + h('Default value') + ' <span class="hint">' + h('Optional JSON') + '</span><textarea id="catalog-default" placeholder="null">' + esc(value.default_value === undefined ? '' : JSON.stringify(value.default_value)) + '</textarea></label><label for="catalog-type">' + h('Type') + '<select id="catalog-type"><option value="">' + h('Optional') + '</option><option value="email"' + (value.typ === 'email' ? ' selected' : '') + '>email</option></select></label><label><input id="catalog-editable" type="checkbox"' + (value.user_editable ? ' checked' : '') + '> ' + h('User editable') + '</label>'
    : '<label for="catalog-access">' + h('Include in access claims') + ' <span class="hint">' + h('Comma-separated attribute names') + '</span><input id="catalog-access" value="' + esc((value.attr_include_access || []).join(', ')) + '"></label><label for="catalog-id">' + h('Include in ID claims') + ' <span class="hint">' + h('Comma-separated attribute names') + '</span><input id="catalog-id" value="' + esc((value.attr_include_id || []).join(', ')) + '"></label><label><input id="catalog-root" type="checkbox"' + (value.claims_at_root ? ' checked' : '') + '> ' + h('Put claims at root') + '</label>';
  shell(t(editing ? 'Edit {kind}' : 'New {kind}', {kind: t(label)}), t(editing ? 'Update the catalog entry, then verify the server response.' : 'Create a catalog entry with server-side validation.'), '<div class="panel"><form id="catalog-form">' + nameInput + fields + '<div class="actions"><button id="catalog-submit" type="submit">' + h(editing ? 'Save changes' : 'Create {kind}', {kind: t(label)}) + '</button><a class="button secondary" id="catalog-cancel" href="/auth/v1/admin/' + kind + '">' + h('Cancel') + '</a>' + (editing ? '<button type="button" class="button secondary" id="catalog-delete">' + h('Delete') + '</button>' : '') + '<span id="catalog-result" role="status"></span></div></form></div>');
  const form = document.getElementById('catalog-form');
  let saving = false;
  const controls = [...form.querySelectorAll('input, select, textarea, button')];
  const originallyDisabled = new Map(controls.map(control => [control, control.disabled]));
  const setBusy = busy => controls.forEach(control => { control.disabled = busy || originallyDisabled.get(control); });
  document.getElementById('catalog-cancel').onclick = event => { if (saving) event.preventDefault(); };
  form.onsubmit = async event => {
    event.preventDefault();
    if (saving) return;
    saving = true;
    const out = document.getElementById('catalog-result');
    setBusy(true);
    try {
      const body = attribute ? {name: document.getElementById('catalog-name').value, desc: document.getElementById('catalog-desc').value, user_editable: document.getElementById('catalog-editable').checked} : {scope: document.getElementById('catalog-name').value, claims_at_root: document.getElementById('catalog-root').checked};
      if (!attribute) { const access = split(document.getElementById('catalog-access').value), ids = split(document.getElementById('catalog-id').value); if (access.length) body.attr_include_access = access; if (ids.length) body.attr_include_id = ids; }
      if (attribute) { const raw = document.getElementById('catalog-default').value.trim(); if (raw) { try { body.default_value = JSON.parse(raw); } catch { throw Error(t('Default value must be valid JSON.')); } } const type = document.getElementById('catalog-type').value; if (type) body.typ = type; }
      await api(pathForCatalog(kind, id), {method: editing ? 'PUT' : 'POST', body: JSON.stringify(body)});
      location.href = '/auth/v1/admin/' + kind;
    } catch (error) { out.className = 'error'; out.textContent = error.message; setBusy(false); saving = false; }
  };
  if (editing) document.getElementById('catalog-delete').onclick = async () => {
    if (saving || !confirm(t('Delete this {kind} permanently?', {kind: label}))) return;
    saving = true;
    setBusy(true);
    const out = document.getElementById('catalog-result');
    try { await api(pathForCatalog(kind, id), {method: 'DELETE'}); location.href = '/auth/v1/admin/' + kind; } catch (error) { out.className = 'error'; out.textContent = error.message; setBusy(false); saving = false; }
  };
}

function pathForCatalog(kind, id) { return (kind === 'attributes' ? '/auth/v1/users/attr' : '/auth/v1/scopes') + (id == null ? '' : '/' + encodeURIComponent(id)); }
