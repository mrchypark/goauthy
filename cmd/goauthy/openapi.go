package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/mrchypark/goauthy/internal/apidocs"
)

type swaggerConfig struct {
	Enabled bool
	Public  bool
}

func swaggerConfigFromEnv(getenv func(string) string) (swaggerConfig, error) {
	var config swaggerConfig
	for name, value := range map[string]*bool{
		"GOAUTHY_SWAGGER_UI_ENABLE": &config.Enabled,
		"GOAUTHY_SWAGGER_UI_PUBLIC": &config.Public,
	} {
		parsed, err := strconv.ParseBool(envValue(getenv, name, "false"))
		if err != nil {
			return swaggerConfig{}, fmt.Errorf("%s must be a boolean", name)
		}
		*value = parsed
	}
	return config, nil
}

func mountSwaggerRoutes(mux *http.ServeMux, config swaggerConfig, issuer string, features apidocs.Features, admin func(http.ResponseWriter, *http.Request, bool) bool) error {
	if !config.Enabled {
		return nil
	}
	document, err := apidocs.Document(issuer, features)
	if err != nil {
		return err
	}
	handler, err := apidocs.NewHandler(issuer, document, config.Public, admin)
	if err != nil {
		return err
	}
	mux.Handle("/auth/v1/docs", handler)
	mux.Handle("/auth/v1/docs/", handler)
	return nil
}
