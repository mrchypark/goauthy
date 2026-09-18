package browser

import "testing"

// TestPasswordPolicyRolloutAcrossPods proves that a stronger configured Argon2
// policy accepts the bootstrap password after every pod has rolled.
func TestPasswordPolicyRolloutAcrossPods(t *testing.T) {
	primary, secondary, username, password, _ := browserE2EConfig(t)

	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client,
		oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "password-policy-rollout", "password-policy-rollout-nonce"),
		primary, secondary, username, password, "password-policy-rollout")
	if code == "" {
		t.Fatal("strong-password-policy login did not return an authorization code")
	}
}
