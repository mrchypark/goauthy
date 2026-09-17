package main

import (
	"fmt"
	"strconv"

	"github.com/mrchypark/goauthy/internal/rbac"
)

func userListThresholdFromEnv(getenv func(string) string) (uint16, error) {
	raw := getenv("GOAUTHY_SSP_THRESHOLD")
	if raw == "" {
		return rbac.DefaultUserListThreshold, nil
	}
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != raw {
		return 0, fmt.Errorf("GOAUTHY_SSP_THRESHOLD must be a decimal integer between 1 and 65535")
	}
	return uint16(n), nil
}
