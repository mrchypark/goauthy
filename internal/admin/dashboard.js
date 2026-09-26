async function dashboard() {
  const areas = [
    ['Identity', 'Manage the people who can sign in.', [['users', 'Users', 'Accounts and profile settings'], ['roles', 'Roles', 'Application access roles'], ['groups', 'Groups', 'Membership and delegated access']]],
    ['Applications', 'Connect your applications and services.', [['clients', 'OAuth clients', 'Sign-in integrations'], ['collections', 'Collections', 'Connection definitions'], ['providers', 'SaaS providers', 'External service connections']]],
    ['Operations', 'Review access and activity.', [['sessions', 'Sessions', 'Active sessions and revocation'], ['events', 'Events', 'Audit and lifecycle history'], ['api-keys', 'API keys', 'Service access credentials']]]
  ];
  shell('Overview', 'Your identity workspace.', '<div class="overview-account"><div><p class="eyebrow">' + t('Signed in as') + '</p><p id="overview-identity" role="status">' + t('Loading account…') + '</p></div><a class="button secondary" href="/account">' + t('Account settings ↗') + '</a></div>' +
    '<div class="overview-areas">' + areas.map(([title, description, links]) => '<section><h2>' + t(title) + '</h2><p class="hint">' + t(description) + '</p><div class="overview-links">' + links.map(([path, label, detail]) => '<a href="/auth/v1/admin/' + path + '"><span><strong>' + t(label) + '</strong><small>' + t(detail) + '</small></span><span aria-hidden="true">↗</span></a>').join('') + '</div></section>').join('') + '</div>');
  const identity = document.getElementById('overview-identity');
  try {
    const profile = await api('/account/data');
    identity.textContent = profile.email || profile.preferred_username || profile.subject;
  } catch (error) {
    identity.textContent = t('Account details are unavailable. You can still choose a management area.');
  }
}
