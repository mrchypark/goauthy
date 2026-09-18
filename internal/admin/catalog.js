// Custom claims catalog UI; invoked by admin.js with its shared API and rendering helpers.
function catalog(kind, id) {
  const attribute = kind === 'attributes', label = attribute ? 'attribute' : 'scope';
  const endpoint = attribute ? '/auth/v1/users/attr' : '/auth/v1/scopes';
  const current = arguments.length > 2 ? arguments[2] : null;
  if (id === 'new') return catalogForm(kind, null, {});
  if (id != null && !current) return api(endpoint).then(data => {
    const rows = attribute ? (data && data.values || []) : (Array.isArray(data) ? data : []);
    const found = rows.find(x => (attribute ? x.name : x.scope) === id);
    if (!found) throw Error('Could not find ' + label + ' ' + id);
    return catalog(kind, id, found);
  }).catch(error => { root.innerHTML = '<p class="error">' + esc(error.message) + '</p>'; });
  if (id != null) return catalogForm(kind, id, current || {});
  return catalogList(kind, endpoint, label, attribute);
}

async function catalogList(kind, endpoint, label, attribute) {
  shell(attribute ? 'User attributes' : 'Scopes', 'Manage the live custom-claims catalog.', '<div class="toolbar"><span class="hint" id="catalog-status">Loading…</span><a class="button" id="catalog-new" href="/auth/v1/admin/' + kind + '/new">New ' + label + '</a></div><div id="catalog-list"></div>');
  try {
    const data = await api(endpoint), rows = attribute ? (data && data.values || []) : (Array.isArray(data) ? data : []);
    document.getElementById('catalog-status').textContent = rows.length + ' ' + (rows.length === 1 ? label : label + 's');
    document.getElementById('catalog-list').innerHTML = rows.length
      ? '<table><thead><tr><th>Name</th><th>Details</th></tr></thead><tbody>' + rows.map(x => {
        const name = attribute ? x.name : x.scope;
        const details = attribute ? (x.typ || '—') : ((x.attr_include_access || []).length + ' access, ' + (x.attr_include_id || []).length + ' ID');
        return '<tr><td><a href="/auth/v1/admin/' + kind + '/' + encodeURIComponent(name) + '">' + esc(name) + '</a></td><td>' + esc(details) + '</td></tr>';
      }).join('') + '</tbody></table>'
      : '<p class="state">No ' + label + 's yet. Create the first one above.</p>';
  } catch (error) {
    document.getElementById('catalog-list').innerHTML = '<p class="error">Could not load ' + label + 's: ' + esc(error.message) + '</p>';
  }
}

function catalogForm(kind, id, value) {
  const attribute = kind === 'attributes', label = attribute ? 'attribute' : 'scope', editing = id != null;
  const name = attribute ? value.name : value.scope;
  const nameInput = '<label for="catalog-name">Name<input id="catalog-name" required value="' + esc(name) + '"></label>';
  const fields = attribute
    ? '<label for="catalog-desc">Description <span class="hint">Optional, 128 characters max</span><input id="catalog-desc" maxlength="128" value="' + esc(value.desc) + '"></label><label for="catalog-default">Default value <span class="hint">Optional JSON</span><textarea id="catalog-default" placeholder="null">' + esc(value.default_value === undefined ? '' : JSON.stringify(value.default_value)) + '</textarea></label><label for="catalog-type">Type<select id="catalog-type"><option value="">Optional</option><option value="email"' + (value.typ === 'email' ? ' selected' : '') + '>email</option></select></label><label><input id="catalog-editable" type="checkbox"' + (value.user_editable ? ' checked' : '') + '> User editable</label>'
    : '<label for="catalog-access">Include in access claims <span class="hint">Comma-separated attribute names</span><input id="catalog-access" value="' + esc((value.attr_include_access || []).join(', ')) + '"></label><label for="catalog-id">Include in ID claims <span class="hint">Comma-separated attribute names</span><input id="catalog-id" value="' + esc((value.attr_include_id || []).join(', ')) + '"></label><label><input id="catalog-root" type="checkbox"' + (value.claims_at_root ? ' checked' : '') + '> Put claims at root</label>';
  shell((editing ? 'Edit ' : 'New ') + label, editing ? 'Update the catalog entry, then verify the server response.' : 'Create a catalog entry with server-side validation.', '<div class="panel"><form id="catalog-form">' + nameInput + fields + '<div class="actions"><button type="submit">' + (editing ? 'Save changes' : 'Create ' + label) + '</button><a class="button secondary" href="/auth/v1/admin/' + kind + '">Cancel</a>' + (editing ? '<button type="button" class="button secondary" id="catalog-delete">Delete</button>' : '') + '<span id="catalog-result" role="status"></span></div></form></div>');
  document.getElementById('catalog-form').onsubmit = async event => {
    event.preventDefault();
    const out = document.getElementById('catalog-result');
    try {
      const body = attribute ? {name: document.getElementById('catalog-name').value, desc: document.getElementById('catalog-desc').value, user_editable: document.getElementById('catalog-editable').checked} : {scope: document.getElementById('catalog-name').value, claims_at_root: document.getElementById('catalog-root').checked};
      if (!attribute) { const access = split(document.getElementById('catalog-access').value), ids = split(document.getElementById('catalog-id').value); if (access.length) body.attr_include_access = access; if (ids.length) body.attr_include_id = ids; }
      if (attribute) { const raw = document.getElementById('catalog-default').value.trim(); if (raw) body.default_value = JSON.parse(raw); const type = document.getElementById('catalog-type').value; if (type) body.typ = type; }
      await api(pathForCatalog(kind, id), {method: editing ? 'PUT' : 'POST', body: JSON.stringify(body)});
      await catalog(kind);
    } catch (error) { out.className = 'error'; out.textContent = error.message; }
  };
  if (editing) document.getElementById('catalog-delete').onclick = async () => {
    if (!confirm('Delete this ' + label + ' permanently?')) return;
    const out = document.getElementById('catalog-result');
    try { await api(pathForCatalog(kind, id), {method: 'DELETE'}); await catalog(kind); } catch (error) { out.className = 'error'; out.textContent = error.message; }
  };
}

function pathForCatalog(kind, id) { return (kind === 'attributes' ? '/auth/v1/users/attr' : '/auth/v1/scopes') + (id == null ? '' : '/' + encodeURIComponent(id)); }
