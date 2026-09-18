package security

// ValidHeaderText matches the nonempty HeaderValue.to_str check used for
// upstream login metadata: visible ASCII and horizontal tabs only.
func ValidHeaderText(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '\t' && (value[i] < 32 || value[i] >= 127) {
			return false
		}
	}
	return true
}
