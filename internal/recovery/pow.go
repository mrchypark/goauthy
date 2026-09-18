package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// ErrInvalidProof is deliberately shared by malformed, expired, unsolved, and
// already-consumed proofs so callers cannot use it as a state oracle.
var ErrInvalidProof = errors.New("invalid proof of work")

// ErrProofIssueLimited deliberately covers both direct-peer admission and the
// global live-challenge ceiling.  Neither condition reveals another caller's
// state.
var ErrProofIssueLimited = errors.New("proof of work issuance limited")

const (
	proofIssueWindow = time.Minute
	proofIssueLimit  = 5
	proofIssuePeers  = 256
	proofActiveLimit = 256
	MaxProofTTL      = 5 * time.Minute
)

// ProofOfWork issues and consumes the Rauthy/spow v1 textual PoW format. The
// server stores only a SHA-256 digest of the unsigned challenge, never its
// secret-derived value or the solved counter.
type ProofOfWork struct {
	db     *rhiza.DB
	secret string
	now    func() time.Time
	random io.Reader
}

func NewProofOfWork(db *rhiza.DB, resetKey []byte) (*ProofOfWork, error) {
	if db == nil || len(resetKey) != sha256.Size {
		return nil, ErrInvalidProof
	}
	return &ProofOfWork{
		db:     db,
		secret: base64.RawStdEncoding.EncodeToString(append([]byte(nil), resetKey...)),
		now:    time.Now,
		random: rand.Reader,
	}, nil
}

// Issue returns an unsigned spow v1 challenge. The final empty counter field
// is intentional: clients append any nonempty counter suffix while solving.
func (p *ProofOfWork) Issue(ctx context.Context, difficulty uint8, ttl time.Duration) (string, error) {
	return p.issue(ctx, "", difficulty, ttl)
}

// IssueForPeer atomically reserves a direct-peer issuance slot and one of the
// bounded live challenge rows. Forwarding headers are intentionally not an
// input: callers must pass the direct TCP peer until trusted-proxy policy
// exists.
func (p *ProofOfWork) IssueForPeer(ctx context.Context, peer string, difficulty uint8, ttl time.Duration) (string, error) {
	parsed := net.ParseIP(peer)
	if parsed == nil || parsed.String() != peer {
		return "", ErrInvalidProof
	}
	return p.issue(ctx, peer, difficulty, ttl)
}

func (p *ProofOfWork) issue(ctx context.Context, peer string, difficulty uint8, ttl time.Duration) (string, error) {
	if p == nil || p.db == nil || difficulty < 10 || difficulty > 98 || ttl < time.Second || ttl > MaxProofTTL {
		return "", ErrInvalidProof
	}
	now := p.now().UTC().Truncate(time.Second)
	expires := now.Add(ttl).Unix()
	if expires <= now.Unix() {
		return "", ErrInvalidProof
	}
	saltBytes := make([]byte, 12) // RawStdEncoding of 12 bytes is exactly 16 chars.
	if _, err := io.ReadFull(p.random, saltBytes); err != nil {
		return "", err
	}
	salt := base64.RawStdEncoding.EncodeToString(saltBytes)
	challenge := makeChallenge(difficulty, expires, salt, p.secret)
	stored := challengeDigest(challenge)
	windowStart := now.Unix() / int64(proofIssueWindow/time.Second) * int64(proofIssueWindow/time.Second)
	peerDigest := ""
	if peer != "" {
		peerDigest = challengeDigest("pow-issue/" + peer)
	}
	_, err := storage.Execute(ctx, p.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("pow-issue", stored, peerDigest, strconv.FormatInt(expires, 10)),
		Statements: []rhiza.SQLStatement{
			// Delete the complete expired set before counting. A partial cleanup
			// lets an attacker permanently outpace admission with expired rows.
			{SQL: `DELETE FROM identity_password_reset_pow_challenges WHERE expires_at_unix_seconds < ?`, Args: []any{now.Unix()}},
			// The peer quota is also bounded. Without this cleanup/cap an attacker
			// can solve each challenge and grow one row per direct peer.
			{SQL: `DELETE FROM identity_password_reset_pow_issuance_limits WHERE window_start_unix_seconds < ?`, Args: []any{windowStart}},
			{SQL: `INSERT INTO identity_password_reset_pow_challenges (challenge,expires_at_unix_seconds,consumed_attempt,consumed_at_unix_seconds)
				SELECT ?, ?, NULL, NULL
				WHERE (SELECT COUNT(*) FROM identity_password_reset_pow_challenges WHERE expires_at_unix_seconds >= ?) < ?
				  AND (? = '' OR COALESCE((SELECT CASE WHEN window_start_unix_seconds = ? THEN count ELSE 0 END FROM identity_password_reset_pow_issuance_limits WHERE peer_digest = ?), 0) < ?)
				  AND (? = '' OR (SELECT COUNT(*) FROM identity_password_reset_pow_issuance_limits) < ? OR EXISTS (SELECT 1 FROM identity_password_reset_pow_issuance_limits WHERE peer_digest = ?))`, Args: []any{stored, expires, now.Unix(), int64(proofActiveLimit), peerDigest, windowStart, peerDigest, int64(proofIssueLimit), peerDigest, int64(proofIssuePeers), peerDigest}},
			// changes() is the immediately preceding conditional challenge insert;
			// therefore a rejected capacity/quota check consumes no peer slot.
			{SQL: `INSERT INTO identity_password_reset_pow_issuance_limits (peer_digest,window_start_unix_seconds,count)
				SELECT ?, ?, 1 WHERE changes() = 1 AND ? != ''
				ON CONFLICT(peer_digest) DO UPDATE SET window_start_unix_seconds = excluded.window_start_unix_seconds,
				count = CASE WHEN identity_password_reset_pow_issuance_limits.window_start_unix_seconds = excluded.window_start_unix_seconds THEN identity_password_reset_pow_issuance_limits.count + 1 ELSE 1 END`, Args: []any{peerDigest, windowStart, peerDigest}},
		},
	})
	if err != nil {
		return "", err
	}
	if !p.unconsumed(ctx, stored, expires, now.Unix()) {
		return "", ErrProofIssueLimited
	}
	return challenge, nil
}

// VerifyAndConsume checks a solved full string and marks its challenge used in
// the same Rhiza mutation. An expiry equal to now remains valid, matching
// spow's second-precision contract.
func (p *ProofOfWork) VerifyAndConsume(ctx context.Context, solved string) error {
	if p == nil || p.db == nil {
		return ErrInvalidProof
	}
	difficulty, expires, challenge, ok := p.parseSolved(solved)
	if !ok || !leadingZeroBits(sha256.Sum256([]byte(solved)), difficulty) {
		return ErrInvalidProof
	}
	now := p.now().UTC().Truncate(time.Second)
	if expires < now.Unix() {
		return ErrInvalidProof
	}
	stored := challengeDigest(challenge)
	attemptBytes := make([]byte, 16)
	if _, err := io.ReadFull(p.random, attemptBytes); err != nil {
		return ErrInvalidProof
	}
	attempt := base64.RawURLEncoding.EncodeToString(attemptBytes)
	_, err := storage.Execute(ctx, p.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("pow-consume", stored, attempt),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM identity_password_reset_pow_challenges WHERE challenge IN (SELECT challenge FROM identity_password_reset_pow_challenges WHERE expires_at_unix_seconds < ? ORDER BY expires_at_unix_seconds LIMIT 128)`, Args: []any{now.Unix()}},
			{SQL: `UPDATE identity_password_reset_pow_challenges SET consumed_attempt = ?, consumed_at_unix_seconds = ? WHERE challenge = ? AND expires_at_unix_seconds >= ? AND consumed_attempt IS NULL`, Args: []any{attempt, now.Unix(), stored, now.Unix()}},
		},
	})
	if err != nil || !p.consumedBy(ctx, stored, attempt, expires, now.Unix()) {
		return ErrInvalidProof
	}
	return nil
}

func makeChallenge(difficulty uint8, expires int64, salt, secret string) string {
	digestInput := "1" + strconv.Itoa(int(difficulty)) + strconv.FormatInt(expires, 10) + salt + secret
	digest := sha256.Sum256([]byte(digestInput))
	return "1:" + strconv.Itoa(int(difficulty)) + ":" + strconv.FormatInt(expires, 10) + ":" + salt + ":" + base64.RawStdEncoding.EncodeToString(digest[:]) + ":"
}

func challengeDigest(challenge string) string {
	digest := sha256.Sum256([]byte(challenge))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (p *ProofOfWork) parseSolved(solved string) (uint8, int64, string, bool) {
	parts := strings.Split(solved, ":")
	if len(parts) != 6 || parts[0] != "1" || parts[5] == "" {
		return 0, 0, "", false
	}
	difficulty64, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil || difficulty64 < 10 || difficulty64 > 98 {
		return 0, 0, "", false
	}
	expires, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || expires < 0 {
		return 0, 0, "", false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) != 12 || base64.RawStdEncoding.EncodeToString(salt) != parts[3] {
		return 0, 0, "", false
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(digest) != sha256.Size || base64.RawStdEncoding.EncodeToString(digest) != parts[4] {
		return 0, 0, "", false
	}
	challenge := makeChallenge(uint8(difficulty64), expires, parts[3], p.secret)
	if challenge != strings.Join(parts[:5], ":")+":" {
		return 0, 0, "", false
	}
	return uint8(difficulty64), expires, challenge, true
}

func leadingZeroBits(sum [sha256.Size]byte, bits uint8) bool {
	for bit := uint8(0); bit < bits; bit++ {
		if sum[bit/8]&(byte(0x80)>>uint(bit%8)) != 0 {
			return false
		}
	}
	return true
}

func (p *ProofOfWork) unconsumed(ctx context.Context, challenge string, expires, now int64) bool {
	result, err := p.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT expires_at_unix_seconds,consumed_attempt FROM identity_password_reset_pow_challenges WHERE challenge = ?`, Args: []any{challenge}, Consistency: rhiza.ConsistencyLinearizable})
	return err == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 2 && result.Rows[0][0] == expires && result.Rows[0][1] == nil && expires >= now
}

func (p *ProofOfWork) consumedBy(ctx context.Context, challenge, attempt string, expires, now int64) bool {
	result, err := p.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT expires_at_unix_seconds,consumed_attempt FROM identity_password_reset_pow_challenges WHERE challenge = ?`, Args: []any{challenge}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != expires || expires < now {
		return false
	}
	storedAttempt, ok := result.Rows[0][1].(string)
	return ok && storedAttempt == attempt
}
