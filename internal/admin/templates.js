async function templates() {
  const t = globalThis.GoAuthyI18n?.t || ((key, values = {}) => String(key).replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match));
  shell(t('Email templates'), t('Preview rendered email templates for all supported types and languages.'), `<div class="toolbar"><span class="hint" id="template-status">${t('Loading…')}</span></div><div class="panel"><label>${t('Type')}<select id="template-type"><option value="">${t('Select type')}</option></select></label><label>${t('Language')}<select id="template-lang"><option value="">${t('Select language')}</option></select></label><div id="template-preview"></div></div>`);
  try {
    const data = await api('/auth/v1/admin/email-templates'), typeSelect = document.getElementById('template-type'), langSelect = document.getElementById('template-lang');
    for (const value of data.types) { const option = document.createElement('option'); option.value = value; option.textContent = value; typeSelect.appendChild(option); }
    document.getElementById('template-status').textContent = t('{count} types, all languages available', {count: data.types.length});
    typeSelect.onchange = () => {
      const type = typeSelect.value; langSelect.innerHTML = `<option value="">${t('Select language')}</option>`; document.getElementById('template-preview').innerHTML = '';
      if (!type || !data.languages[type]) return;
      for (const value of data.languages[type]) { const option = document.createElement('option'); option.value = value; option.textContent = value; langSelect.appendChild(option); }
    };
    langSelect.onchange = () => {
      const type = typeSelect.value, language = langSelect.value;
      if (!type || !language) { document.getElementById('template-preview').innerHTML = ''; return; }
      document.getElementById('template-preview').innerHTML = '<iframe src="/auth/v1/admin/email-templates/preview?type=' + encodeURIComponent(type) + '&lang=' + encodeURIComponent(language) + '" title="' + esc(t('Email template preview')) + '"></iframe>';
    };
  } catch (error) { document.getElementById('template-status').innerHTML = '<p class="error">' + esc(error.message) + '</p>'; }
}
