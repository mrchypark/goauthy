package device

import (
	"context"
	"net/http"
)

type bindingKey struct{}

type ClientBinding struct {
	ID, Generation string
	Revision       int64
	Resource       string
}

func SetResource(r *http.Request, resource string) {
	if value, ok := r.Context().Value(bindingKey{}).(*ClientBinding); ok && validResource(resource) {
		value.Resource = resource
	}
}

// WithClientBinding adds mutable authorization metadata for the handler's
// authorizer callback to fill before the grant is persisted.
func WithClientBinding(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), bindingKey{}, new(ClientBinding)))
}

func SetManagedClient(r *http.Request, id, generation string, revision int64) {
	if value, ok := r.Context().Value(bindingKey{}).(*ClientBinding); ok {
		value.ID, value.Generation, value.Revision = id, generation, revision
	}
}

func ClientBindingFromRequest(r *http.Request) ClientBinding {
	if value, ok := r.Context().Value(bindingKey{}).(*ClientBinding); ok && value != nil {
		return *value
	}
	return ClientBinding{}
}
