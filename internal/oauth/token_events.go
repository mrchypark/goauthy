package oauth

import (
	"context"
	"log/slog"
)

// SetTokenIssued configures the post-issuance lifecycle event sink at startup.
func (s *Server) SetTokenIssued(sink func(context.Context, string, string, string) error) {
	s.tokenIssued = sink
}

func (s *Server) emitTokenIssued(ctx context.Context, flow, clientID, subject string) error {
	if s.tokenIssued == nil {
		return nil
	}
	switch flow {
	case "authorization_code", "client_credentials", "password", TokenExchangeGrantType:
	case "urn:ietf:params:oauth:grant-type:device_code":
		// The pinned device grant logs event delivery failure without failing issuance.
		if err := s.tokenIssued(ctx, "device_code", clientID, subject); err != nil {
			slog.Error("Device token-issued event failed")
		}
		return nil
	default:
		return nil
	}
	return s.tokenIssued(ctx, flow, clientID, subject)
}
