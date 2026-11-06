async function dashboard() {
  const areas = [
    ['Identity', [['users', 'Users'], ['roles', 'Roles'], ['groups', 'Groups']]],
    ['Applications', [['clients', 'OAuth clients'], ['collections', 'Collections'], ['providers', 'SaaS providers']]],
    ['Operations', [['sessions', 'Sessions'], ['events', 'Events'], ['api-keys', 'API keys']]]
  ];
  shell('Overview', '', '<div class="overview-account"><div><p class="eyebrow">' + t('Signed in as') + '</p><p id="overview-identity" role="status">' + t('Loading account…') + '</p></div><a class="button secondary" href="/account">' + t('Account settings ↗') + '</a></div>' +
    '<div class="overview-areas">' + areas.map(([title, links]) => '<section><h2>' + t(title) + '</h2><div class="overview-links">' + links.map(([path, label]) => '<a href="/auth/v1/admin/' + path + '"><strong>' + t(label) + '</strong><span aria-hidden="true">↗</span></a>').join('') + '</div></section>').join('') + '</div>');
  const identity = document.getElementById('overview-identity');
  try {
    const profile = await api('/account/data');
    identity.textContent = profile.email || profile.preferred_username || profile.subject;
  } catch (error) {
    identity.textContent = t('Account details are unavailable. You can still choose a management area.');
  }
}
