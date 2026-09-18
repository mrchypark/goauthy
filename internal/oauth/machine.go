package oauth

import (
	"errors"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
)

const (
	machineSubjectExtra = "goauthy_machine_sub"
	actorMachineExtra   = "goauthy_actor_machine"
)

// machineTokenSubject classifies only durable machine-token representations.
// A non-empty subject is always an end-user identity: a missing identity row
// must therefore be rejected by account validation rather than downgraded to a
// machine token.
func machineTokenSubject(request fosite.Requester) (string, bool, error) {
	if request == nil || request.GetSession() == nil || request.GetClient() == nil || request.GetClient().GetID() == "" {
		return "", false, errors.New("invalid machine token request")
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return "", false, errors.New("invalid machine token session")
	}
	marker, marked := session.Extra[machineSubjectExtra]
	if session.Subject != "" {
		if marked {
			return "", false, errors.New("machine marker on user token")
		}
		return session.Subject, false, nil
	}
	grant := request.GetRequestForm().Get("grant_type")
	if marked {
		value, ok := marker.(string)
		if !ok || (value != "" && value != request.GetClient().GetID()) || (grant != "client_credentials" && grant != TokenExchangeGrantType) {
			return "", false, errors.New("invalid machine token marker")
		}
		return value, true, nil
	}
	if grant == "client_credentials" {
		return "", true, nil
	}
	return "", false, errors.New("empty user token subject")
}

// markMachineToken records the only durable distinction between a no-sub
// machine token and an invalid empty-sub user token. Callers must have already
// established that request is a client-credentials or machine-exchange flow.
func markMachineToken(request fosite.Requester, mapSub bool) error {
	if request == nil || request.GetSession() == nil || request.GetClient() == nil || request.GetClient().GetID() == "" {
		return errors.New("invalid machine token request")
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || session.Subject != "" {
		return errors.New("machine token has user subject")
	}
	if session.Extra == nil {
		session.Extra = make(map[string]interface{})
	}
	value := ""
	if mapSub {
		value = request.GetClient().GetID()
	}
	session.Extra[machineSubjectExtra] = value
	return nil
}

// actorMachineFlags decodes the mask persisted beside an act chain. The mask
// is positional and must describe every actor; accepting a partial mask would
// permit an attacker to silently skip a real account check.
func actorMachineFlags(session *fosite.DefaultSession, actor *oidc.ActorClaims) ([]bool, error) {
	count := 0
	for node := actor; node != nil; node = node.Actor {
		count++
	}
	flags := make([]bool, count)
	if session == nil || session.Extra == nil {
		return flags, nil
	}
	raw, present := session.Extra[actorMachineExtra]
	if !present {
		return flags, nil
	}
	var values []bool
	switch value := raw.(type) {
	case []bool:
		values = append([]bool(nil), value...)
	case []any:
		values = make([]bool, len(value))
		for i, item := range value {
			flag, ok := item.(bool)
			if !ok {
				return nil, errors.New("invalid machine actor marker")
			}
			values[i] = flag
		}
	default:
		return nil, errors.New("invalid machine actor marker")
	}
	if len(values) != count {
		return nil, errors.New("machine actor marker length mismatch")
	}
	return values, nil
}

// tokenAccountSubjects returns the unique real-user identities represented by
// a persisted token. A valid machine token has no account subjects; malformed
// empty-sub sessions never reach that result.
func tokenAccountSubjects(request fosite.Requester) ([]string, error) {
	owner, machine, err := machineTokenSubject(request)
	if err != nil {
		return nil, err
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return nil, errors.New("invalid token account session")
	}
	actor, err := accessSessionActor(session.Extra)
	if err != nil {
		return nil, err
	}
	flags, err := actorMachineFlags(session, actor)
	if err != nil {
		return nil, err
	}
	subjects := make([]string, 0, 1+len(flags))
	seen := make(map[string]struct{}, 1+len(flags))
	add := func(subject string) error {
		if subject == "" {
			return errors.New("empty user account subject")
		}
		if _, found := seen[subject]; !found {
			seen[subject] = struct{}{}
			subjects = append(subjects, subject)
		}
		return nil
	}
	if !machine {
		if err := add(owner); err != nil {
			return nil, err
		}
	}
	for index, node := 0, actor; node != nil; index, node = index+1, node.Actor {
		if !flags[index] {
			if err := add(node.Subject); err != nil {
				return nil, err
			}
		}
	}
	return subjects, nil
}
