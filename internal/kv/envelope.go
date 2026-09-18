package kv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mrchypark/goauthy/internal/oidc"
)

const kvRewrapBatchSize = 32

type EnvelopeReferences struct {
	Access, Values    oidc.MasterKeyReferenceFamily
	ActiveMasterKeyID string
	Safe              bool
}

type RewrapResult struct {
	Cursor    string
	Rewrapped int
	Done      bool
}
type kvCursor struct{ Type, ID, Namespace, Key string }

func encodeKVCursor(c kvCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeKVCursor(s string) (kvCursor, error) {
	if s == "" {
		return kvCursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	var c kvCursor
	if err != nil || json.Unmarshal(b, &c) != nil || (c.Type != "access" && c.Type != "value") {
		return c, errors.New("invalid KV rewrap cursor")
	}
	return c, nil
}

func emptyKVFamily() oidc.MasterKeyReferenceFamily {
	return oidc.MasterKeyReferenceFamily{ByKeyID: map[string]int64{}}
}
func addKVRef(f *oidc.MasterKeyReferenceFamily, id string) { f.Total++; f.ByKeyID[id]++ }

func (s *Store) InspectEnvelopeReferences(ctx context.Context) (EnvelopeReferences, error) {
	status := EnvelopeReferences{Access: emptyKVFamily(), Values: emptyKVFamily()}
	if s == nil || s.db == nil || s.keyring == nil {
		return status, ErrCorrupt
	}
	active, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return status, err
	}
	status.ActiveMasterKeyID = active
	accessCursor := ""
	for {
		rows, err := s.query(ctx, "SELECT id,secret FROM kv_access WHERE id>? ORDER BY id LIMIT 32", accessCursor)
		if err != nil {
			return status, err
		}
		for _, r := range rows {
			if len(r) != 2 {
				return status, ErrCorrupt
			}
			id, ok := r[0].(string)
			enc, bok := r[1].([]byte)
			if !ok || !alphaNum(id, 16) || !bok {
				return status, ErrCorrupt
			}
			kid, err := s.keyring.PurposeEnvelopeKeyID(accessPurpose(id), enc)
			if err != nil {
				return status, err
			}
			addKVRef(&status.Access, kid)
			accessCursor = id
		}
		if len(rows) < 32 {
			break
		}
	}
	valueNS, valueKey := "", ""
	for {
		rows, err := s.query(ctx, "SELECT v.namespace,v.key,v.value,n.identity FROM kv_values v JOIN kv_namespaces n ON n.name=v.namespace WHERE v.encrypted=1 AND (v.namespace>? OR (v.namespace=? AND v.key>?)) ORDER BY v.namespace,v.key LIMIT 32", valueNS, valueNS, valueKey)
		if err != nil {
			return status, err
		}
		for _, r := range rows {
			if len(r) != 4 {
				return status, ErrCorrupt
			}
			ns, nOK := r[0].(string)
			key, kOK := r[1].(string)
			enc, bOK := r[2].([]byte)
			identity, iOK := r[3].(string)
			if !nOK || !valid(ns) || !kOK || !valid(key) || !bOK || !iOK || identity == "" {
				return status, ErrCorrupt
			}
			kid, err := s.keyring.PurposeEnvelopeKeyID(valuePurpose(identity, key), enc)
			if err != nil {
				return status, err
			}
			addKVRef(&status.Values, kid)
			valueNS, valueKey = ns, key
		}
		if len(rows) < 32 {
			break
		}
	}
	status.Safe = familyKVOnly(status.Access, active) && familyKVOnly(status.Values, active)
	return status, nil
}
func familyKVOnly(f oidc.MasterKeyReferenceFamily, active string) bool {
	return len(f.ByKeyID) == 0 || (len(f.ByKeyID) == 1 && f.ByKeyID[active] == f.Total)
}

func (s *Store) RewrapBatch(ctx context.Context, cursor string) (RewrapResult, error) {
	if s == nil || s.db == nil || s.keyring == nil {
		return RewrapResult{}, ErrCorrupt
	}
	c, err := decodeKVCursor(cursor)
	if err != nil {
		return RewrapResult{}, err
	}
	active, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return RewrapResult{}, err
	}
	rewrapped := 0
	if c.Type == "" || c.Type == "access" {
		last := c.ID
		args := []any{last}
		rows, err := s.query(ctx, "SELECT id,secret FROM kv_access WHERE id>? ORDER BY id LIMIT 32", args...)
		if err != nil {
			return RewrapResult{}, err
		}
		for _, r := range rows {
			if len(r) != 2 {
				return RewrapResult{}, ErrCorrupt
			}
			id, ok := r[0].(string)
			old, bok := r[1].([]byte)
			if !ok || !alphaNum(id, 16) || !bok {
				return RewrapResult{}, ErrCorrupt
			}
			last = id
			kid, e := s.keyring.PurposeEnvelopeKeyID(accessPurpose(id), old)
			if e != nil {
				return RewrapResult{}, e
			}
			if kid != active {
				neu, e := s.keyring.RewrapEnvelope(accessPurpose(id), old)
				if e != nil {
					return RewrapResult{}, e
				}
				resp, e := s.mutate(ctx, "UPDATE kv_access SET secret=? WHERE id=? AND secret=?", neu, id, old)
				if e != nil {
					return RewrapResult{}, e
				}
				if resp.RowsAffected > 1 {
					return RewrapResult{}, fmt.Errorf("KV rewrap CAS changed %d rows", resp.RowsAffected)
				}
				if resp.RowsAffected == 1 {
					rewrapped++
				}
			}
		}
		if len(rows) == kvRewrapBatchSize {
			return RewrapResult{Cursor: encodeKVCursor(kvCursor{Type: "access", ID: last}), Rewrapped: rewrapped}, nil
		}
		c = kvCursor{Type: "value"}
	}
	rows, err := s.query(ctx, "SELECT v.namespace,v.key,v.value,n.identity FROM kv_values v JOIN kv_namespaces n ON n.name=v.namespace WHERE v.encrypted=1 AND (v.namespace>? OR (v.namespace=? AND v.key>?)) ORDER BY v.namespace,v.key LIMIT 32", c.Namespace, c.Namespace, c.Key)
	if err != nil {
		return RewrapResult{}, err
	}
	lastNS, lastKey := c.Namespace, c.Key
	for _, r := range rows {
		if len(r) != 4 {
			return RewrapResult{}, ErrCorrupt
		}
		ns, nok := r[0].(string)
		key, kok := r[1].(string)
		old, bok := r[2].([]byte)
		identity, iok := r[3].(string)
		if !nok || !kok || !bok || !iok || !valid(ns) || !valid(key) || identity == "" {
			return RewrapResult{}, ErrCorrupt
		}
		lastNS, lastKey = ns, key
		purpose := valuePurpose(identity, key)
		kid, e := s.keyring.PurposeEnvelopeKeyID(purpose, old)
		if e != nil {
			return RewrapResult{}, e
		}
		if kid != active {
			neu, e := s.keyring.RewrapEnvelope(purpose, old)
			if e != nil {
				return RewrapResult{}, e
			}
			resp, e := s.mutate(ctx, "UPDATE kv_values SET value=? WHERE namespace=? AND key=? AND encrypted=1 AND value=? AND EXISTS(SELECT 1 FROM kv_namespaces WHERE name=? AND identity=?)", neu, ns, key, old, ns, identity)
			if e != nil {
				return RewrapResult{}, e
			}
			if resp.RowsAffected > 1 {
				return RewrapResult{}, fmt.Errorf("KV rewrap CAS changed %d rows", resp.RowsAffected)
			}
			if resp.RowsAffected == 1 {
				rewrapped++
			}
		}
	}
	if len(rows) == kvRewrapBatchSize {
		return RewrapResult{Cursor: encodeKVCursor(kvCursor{Type: "value", Namespace: lastNS, Key: lastKey}), Rewrapped: rewrapped}, nil
	}
	return RewrapResult{Cursor: encodeKVCursor(kvCursor{Type: "value", Namespace: lastNS, Key: lastKey}), Rewrapped: rewrapped, Done: true}, nil
}
