package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strings"

	"github.com/mrchypark/rhiza"
)

var ErrDCRSoftwareStatementTrustMismatch = errors.New("DCR software-statement trust configuration mismatch")

// EnsureDCRSoftwareStatementTrust fences the local static policy against the
// one replicated policy accepted by this standalone or exact-three database.
func EnsureDCRSoftwareStatementTrust(ctx context.Context, db *rhiza.DB, configDigest string, memberIDs []string) error {
	if db == nil {
		return errors.New("DCR software-statement database is required")
	}
	topologyDigest, err := DCRTopologyDigest(memberIDs)
	if err != nil {
		return err
	}
	if !validDCRDigest(configDigest) {
		return errors.New("invalid DCR software-statement trust digest")
	}
	requestID := "dcr-software-statement-trust/" + configDigest[:16] + "/" + topologyDigest[:16]
	_, err = Execute(ctx, db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO dcr_software_statement_trust (id,config_digest,topology_digest) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET config_digest=excluded.config_digest, topology_digest=excluded.topology_digest WHERE dcr_software_statement_trust.config_digest=? AND dcr_software_statement_trust.topology_digest=?`, Args: []any{configDigest, topologyDigest, configDigest, topologyDigest}})
	if err != nil {
		return err
	}
	return CheckDCRSoftwareStatementTrust(ctx, db, configDigest, memberIDs)
}

func CheckDCRSoftwareStatementTrust(ctx context.Context, db *rhiza.DB, configDigest string, memberIDs []string) error {
	if db == nil {
		return errors.New("DCR software-statement database is required")
	}
	topologyDigest, err := DCRTopologyDigest(memberIDs)
	if err != nil {
		return err
	}
	if !validDCRDigest(configDigest) {
		return errors.New("invalid DCR software-statement trust digest")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT config_digest, topology_digest FROM dcr_software_statement_trust WHERE id=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return ErrDCRSoftwareStatementTrustMismatch
	}
	gotConfig, configOK := result.Rows[0][0].(string)
	gotTopology, topologyOK := result.Rows[0][1].(string)
	if !configOK || !topologyOK || gotConfig != configDigest || gotTopology != topologyDigest {
		return ErrDCRSoftwareStatementTrustMismatch
	}
	return nil
}

func DCRTopologyDigest(memberIDs []string) (string, error) {
	if len(memberIDs) != 1 && len(memberIDs) != 3 {
		return "", errors.New("DCR topology must contain exactly one or three members")
	}
	members := append([]string(nil), memberIDs...)
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		if !validRetirementID(member) {
			return "", errors.New("invalid DCR topology member")
		}
		if _, exists := seen[member]; exists {
			return "", errors.New("duplicate DCR topology member")
		}
		seen[member] = struct{}{}
	}
	sort.Strings(members)
	digest := sha256.Sum256([]byte(strings.Join(members, "\x00")))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validDCRDigest(value string) bool {
	return len(value) == 43 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}
