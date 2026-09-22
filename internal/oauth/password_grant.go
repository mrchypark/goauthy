package oauth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

const passwordSnapshotExtra = "goauthy_password_snapshot"
const passwordAuthTimeExtra = "goauthy_password_auth_time"

// Fosite access-denied errors compare equal by field and code alone, and its
// password handler reports every non-ErrNotFound authentication failure as a
// server error. These sentinels keep the two policy denials distinguishable
// through that wrapping so each keeps its own public error.
var (
	errPasswordAdmission     = errors.New("password admission denied")
	errAccountLocked         = errors.New("account locked")
	errPasswordResetRequired = errors.New("password reset required")
)

type passwordAuthenticationKey struct{}

type passwordGrantHandler struct {
	*oauth2.ResourceOwnerPasswordCredentialsGrantHandler
	*Store
	users             *identity.Store
	locks             *loginpolicy.Store
	onPasswordExpired func(context.Context, string) error
}

func newPasswordGrantHandler(store *Store, users *identity.Store, strategy oauth2.CoreStrategy, config *fosite.Config) *passwordGrantHandler {
	h := &passwordGrantHandler{Store: store, users: users, locks: loginpolicy.NewStore(store.db)}
	h.ResourceOwnerPasswordCredentialsGrantHandler = &oauth2.ResourceOwnerPasswordCredentialsGrantHandler{
		HandleHelper: &oauth2.HandleHelper{AccessTokenStrategy: strategy, AccessTokenStorage: store, Config: config},
		ResourceOwnerPasswordCredentialsGrantStorage: h, RefreshTokenStrategy: strategy, Config: config,
	}
	return h
}

func (h *passwordGrantHandler) Authenticate(ctx context.Context, username, password string) (string, error) {
	snapshot, ok := ctx.Value(passwordAuthenticationKey{}).(*identity.Authentication)
	if !ok || h.users == nil || h.locks == nil {
		return "", fosite.ErrServerError
	}
	peer := browser.PeerIPFromContext(ctx)
	if peer == "" {
		return "", fosite.ErrServerError
	}
	started := time.Now()
	if err := h.checkLockdown(ctx, username); err != nil {
		return "", err
	}
	status, err := h.locks.Check(ctx, peer, started.UTC())
	if err != nil {
		return "", fosite.ErrServerError
	}
	if !status.BlockedUntil.IsZero() {
		return "", fosite.ErrAccessDenied.WithWrap(errPasswordAdmission)
	}
	allowed, err := h.locks.Allow(ctx, peer, started.UTC())
	if err != nil {
		return "", fosite.ErrServerError
	}
	if !allowed {
		return "", fosite.ErrAccessDenied.WithWrap(errPasswordAdmission)
	}
	// The browser path refuses an actively locked account before checking
	// credentials; this grant must not be a way around that lock (GA-OAUTH-006).
	locked, _, err := h.locks.CheckAccountLock(ctx, loginpolicy.AccountStuffingDigest(username), time.Now().UTC())
	if err != nil {
		return "", fosite.ErrServerError
	}
	if locked {
		return "", fosite.ErrAccessDenied.WithHint("Account locked.").WithWrap(errAccountLocked)
	}
	auth, err := h.users.AuthenticatePasswordGrant(ctx, username, []byte(password), h.onPasswordExpired)
	if errors.Is(err, identity.ErrPasswordExpired) {
		if auth.Subject == "" {
			return "", fosite.ErrServerError
		}
		return "", fosite.ErrAccessDenied.WithHint("Password reset required.").WithWrap(errPasswordResetRequired)
	}
	if errors.Is(err, identity.ErrInvalidCredentials) {
		status, failureErr := h.locks.Failure(ctx, peer, time.Now().UTC())
		if failureErr != nil {
			return "", fosite.ErrServerError
		}
		if _, _, failureErr := h.locks.RecordAccountFailure(ctx, loginpolicy.AccountStuffingDigest(username), peer, time.Now().UTC()); failureErr != nil {
			return "", fosite.ErrServerError
		}
		timer := time.NewTimer(loginpolicy.Delay(status, time.Since(started)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
		}
		return "", fosite.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if err := h.locks.Success(ctx, peer, time.Since(started)); err != nil {
		return "", fosite.ErrServerError
	}
	*snapshot = auth
	return auth.Subject, nil
}

func (h *passwordGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return fosite.ErrUnknownRequest
	}
	if !request.GetClient().GetGrantTypes().Has("password") {
		return fosite.ErrUnauthorizedClient
	}
	// Admission refuses force_mfa together with the password grant; this keeps
	// rows written before that rule from issuing password-only tokens.
	if h.forceMFA(request.GetClient()) {
		return fosite.ErrUnauthorizedClient
	}
	form := request.GetRequestForm()
	if _, ok := exactlyOne(form, "username"); !ok {
		return fosite.ErrInvalidRequest
	}
	if _, ok := exactlyOne(form, "password"); !ok {
		return fosite.ErrInvalidRequest
	}
	var scopes []string
	if client, ok := request.GetClient().(*clients.Client); ok {
		scopes = client.DefaultScopes
	} else {
		var err error
		scopes, err = h.dynamicClients.DefaultScopes(ctx, request.GetClient().GetID())
		if err != nil {
			return fosite.ErrServerError
		}
	}
	// The pinned password producer selects defaults and ignores resource.
	request.SetRequestedScopes(append(fosite.Arguments(nil), scopes...))
	form.Set("scope", strings.Join(scopes, " "))
	delete(form, "resource")
	request.SetRequestedAudience(nil)
	snapshot := identity.Authentication{}
	ctx = context.WithValue(ctx, passwordAuthenticationKey{}, &snapshot)
	if err := h.ResourceOwnerPasswordCredentialsGrantHandler.HandleTokenEndpointRequest(ctx, request); err != nil {
		// Restore the policy denials the grant handler collapsed into a server
		// error; a storage failure keeps that server error.
		if errors.Is(err, errPasswordAdmission) {
			return fosite.ErrAccessDenied
		}
		if errors.Is(err, errAccountLocked) {
			return fosite.ErrAccessDenied.WithHint("Account locked.")
		}
		if errors.Is(err, errPasswordResetRequired) {
			return fosite.ErrAccessDenied.WithHint("Password reset required.")
		}
		return err
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || snapshot.Subject == "" || snapshot.PasswordGeneration < 1 || snapshot.AuthenticationGeneration < 1 {
		return fosite.ErrServerError
	}
	if session.Extra == nil {
		session.Extra = map[string]interface{}{}
	}
	session.Extra[passwordSnapshotExtra] = snapshot
	session.Extra[passwordAuthTimeExtra] = strconv.FormatInt(time.Now().UTC().Unix(), 10)
	for _, scope := range scopes {
		request.GrantScope(scope)
	}
	return nil
}

func (h *passwordGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return fosite.ErrUnknownRequest
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return fosite.ErrServerError
	}
	snapshot, ok := session.Extra[passwordSnapshotExtra].(identity.Authentication)
	if !ok || snapshot.Subject != session.Subject {
		return fosite.ErrInvalidGrant
	}
	if err := h.checkLockdown(ctx, request.GetRequestForm().Get("username")); err != nil {
		return err
	}
	delete(session.Extra, passwordSnapshotExtra)
	if err := h.users.RecordPasswordLogin(ctx, snapshot); err != nil {
		return err
	}
	// The lock row is keyed by the submitted login identifier: that is what
	// admission checked and what the browser login path records failures against.
	accountHash := loginpolicy.AccountStuffingDigest(request.GetRequestForm().Get("username"))
	ctx, err := h.beginPasswordTX(ctx, snapshot.Subject, snapshot.PasswordGeneration, snapshot.AuthenticationGeneration, accountHash)
	if err != nil {
		return err
	}
	defer h.Rollback(ctx)
	lifetime := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePassword, fosite.AccessToken, h.Config.GetAccessTokenLifespan(ctx))
	accessSignature, err := h.IssueAccessToken(ctx, lifetime, request, response)
	if err != nil {
		return err
	}
	// Rauthy selects refresh issuance by enabled flow, not offline_access.
	if request.GetClient().GetGrantTypes().Has("refresh_token") {
		refresh, signature, err := h.RefreshTokenStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return err
		}
		if err := h.CreateRefreshTokenSession(ctx, signature, accessSignature, request.Sanitize(nil)); err != nil {
			return err
		}
		response.SetExtra("refresh_token", refresh)
	}
	return h.Commit(ctx)
}

func (h *passwordGrantHandler) checkLockdown(ctx context.Context, username string) error {
	lockdown := loginpolicy.NewLockdownStore(h.Store.db)
	locked, _, _, err := lockdown.IsLockedDown(ctx)
	if err != nil {
		return fosite.ErrServerError
	}
	if locked {
		admin, err := lockdown.IsAdminByUsername(ctx, username)
		if err != nil {
			return fosite.ErrServerError
		}
		if !admin {
			return fosite.ErrAccessDenied.WithWrap(errPasswordAdmission)
		}
	}
	return nil
}
