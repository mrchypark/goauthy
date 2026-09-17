package oidc

import "fmt"

// ActorClaims preserves the immediate actor and its prior delegation chain.
type ActorClaims struct {
	Subject string       `json:"sub"`
	Actor   *ActorClaims `json:"act,omitempty"`
}

// ParseActorClaims validates a decoded session or JWT actor without accepting
// unrelated identity claims as delegation authority.
func ParseActorClaims(value any) (*ActorClaims, error) {
	var head *ActorClaims
	tail := &head
	for depth := 0; ; depth++ {
		node, ok := value.(map[string]any)
		if !ok || depth >= maxCustomJSONDepth {
			return nil, fmt.Errorf("%w: invalid actor chain", errInvalidAccessToken)
		}
		subject, ok := node["sub"].(string)
		next, nested := node["act"]
		if !ok || subject == "" || (nested && len(node) != 2) || (!nested && len(node) != 1) {
			return nil, fmt.Errorf("%w: invalid actor claims", errInvalidAccessToken)
		}
		*tail = &ActorClaims{Subject: subject}
		tail = &(*tail).Actor
		if !nested {
			return head, nil
		}
		value = next
	}
}

func validActorClaims(actor *ActorClaims) bool {
	for depth := 0; actor != nil; depth++ {
		if depth >= maxCustomJSONDepth || actor.Subject == "" {
			return false
		}
		actor = actor.Actor
	}
	return true
}
