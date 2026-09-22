package browser

import "context"

// LoadReauthenticationParent reads a server-persisted session digest, never a
// cookie bearer, without extending its lifetime. Reauthentication is restricted
// to this exact active subject and peer.
func (s *Store) LoadReauthenticationParent(ctx context.Context, digest, subject, peerIP string) (Session, error) {
	if !validSessionID(digest) || subject == "" || peerIP == "" {
		return Session{}, ErrNotFound
	}
	parent, _, err := s.loadSession(ctx, digest, s.timeNow())
	if err != nil {
		return Session{}, err
	}
	if !parent.Authenticated() || parent.Subject != subject {
		return Session{}, ErrNotFound
	}
	if err := CheckPeerIP(parent, peerIP); err != nil {
		return Session{}, err
	}
	return parent, nil
}

// ConsumeReauthenticationInteractionByDigest keeps the normal init-only consume
// contract and additionally checks the parent in the same replicated mutation.
// A logout between preparation and consumption cannot authorize a replacement.
func (s *Store) ConsumeReauthenticationInteractionByDigest(ctx context.Context, sessionToken, interactionDigest, parentDigest, subject, peerIP string) (AuthorizationInteraction, error) {
	sessionDigest, err := tokenDigest(sessionToken)
	if err != nil || !validSessionID(interactionDigest) || sessionDigest == parentDigest {
		return AuthorizationInteraction{}, ErrNotFound
	}
	parent, err := s.LoadReauthenticationParent(ctx, parentDigest, subject, peerIP)
	if err != nil {
		return AuthorizationInteraction{}, err
	}
	guard, args := s.SessionAuthorizationGuard(parent, peerIP)
	return s.consumeAuthorizationInteractionGuarded(ctx, sessionDigest, interactionDigest, true, guard, args)
}
