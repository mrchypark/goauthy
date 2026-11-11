package identity

import (
	"time"

	"github.com/mrchypark/rhiza"
)

// delegatedActorPredicate matches a subject in extra.act(.act)*.sub at any
// depth. json_tree exposes each field below its parent path; adding the key
// reconstructs the full path, and removing every repeated .act segment proves
// the path consists only of that actor chain.
const delegatedActorPredicate = `EXISTS (
	SELECT 1 FROM json_tree(request_json) AS actor
	WHERE actor.type = 'text' AND actor.key = 'sub' AND actor.value = ?
	  AND substr((actor.path || '.sub'), 1, 11) = '$.extra.act'
	  AND substr((actor.path || '.sub'), -4) = '.sub'
	  AND replace(substr((actor.path || '.sub'), 12, length(actor.path || '.sub') - 15), '.act', '') = ''
)`

// passwordRevocationStatements invalidates credentials issued from browser
// sessions and every OAuth artifact for subject. A non-empty keepSessionID is
// the explicit self-service policy: the browser session that proved the
// password change remains active, while its FedCM cookie remains usable only
// through that same live row. The caller places these statements in the same
// transaction as the password write and supplies a guard that is true only
// after that write committed.
func passwordRevocationStatements(subject, eventID, keepSessionID string, now time.Time, guard string, guardArgs []any) []rhiza.SQLStatement {
	sessionFilter, sessionArgs := "subject = ?", []any{subject}
	if keepSessionID != "" {
		sessionFilter += " AND token_digest <> ?"
		sessionArgs = append(sessionArgs, keepSessionID)
	}
	guarded := func(sql string, args ...any) rhiza.SQLStatement {
		all := append(append([]any(nil), args...), guardArgs...)
		return rhiza.SQLStatement{SQL: sql + ` AND EXISTS (SELECT 1 FROM identity_users WHERE ` + guard + `)`, Args: all}
	}
	nowMS := now.UTC().UnixMilli()
	return []rhiza.SQLStatement{
		guarded(`INSERT OR IGNORE INTO oidc_backchannel_deliveries (event_id,client_id,sid,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
			SELECT ? || '/' || sid,client_id,sid,logout_uri,allow_private,allow_http,0,?,? FROM oidc_session_clients
			WHERE logout_uri <> '' AND sid IN (SELECT token_digest FROM browser_sessions WHERE `+sessionFilter+`)`,
			append([]any{eventID, nowMS, nowMS}, sessionArgs...)...),
		guarded(`DELETE FROM browser_authorization_interactions WHERE session_digest IN (SELECT token_digest FROM browser_sessions WHERE `+sessionFilter+`)`, sessionArgs...),
		guarded(`UPDATE browser_sessions SET revoked_at_unix_ms=COALESCE(revoked_at_unix_ms,?) WHERE `+sessionFilter, append([]any{nowMS}, sessionArgs...)...),
		guarded(`UPDATE oauth_authorize_codes SET invalidated=1 WHERE invalidated=0 AND json_extract(request_json,'$.subject')=?`, subject),
		guarded(`DELETE FROM oauth_pkce_requests WHERE signature IN (SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')=?)`, subject),
		guarded(`UPDATE oauth_refresh_tokens SET active=0 WHERE active=1 AND (json_extract(request_json,'$.subject')=? OR request_id IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=? OR `+delegatedActorPredicate+`))`, subject, subject, subject),
		guarded(`DELETE FROM oauth_access_tokens WHERE signature IN (SELECT signature FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=? OR `+delegatedActorPredicate+`)`, subject, subject),
		guarded(`DELETE FROM oauth_token_requests WHERE json_extract(request_json,'$.subject')=? OR `+delegatedActorPredicate, subject, subject),
		guarded(`UPDATE oauth_device_grants SET state='denied',claim_token_digest=NULL,claim_until_unix_ms=NULL WHERE subject=? AND state IN ('pending','approved')`, subject),
		guarded(`DELETE FROM oidc_session_clients WHERE sid IN (SELECT token_digest FROM browser_sessions WHERE `+sessionFilter+`)`, sessionArgs...),
	}
}
