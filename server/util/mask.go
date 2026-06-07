package util

import "strings"

// MaskEmail masks the local part of an email for logs and API responses.
func MaskEmail(email string) string {
	email = strings.TrimSpace(email)
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" {
		return maskString(email)
	}
	return maskString(local) + "@" + domain
}

func maskString(value string) string {
	switch len(value) {
	case 0:
		return ""
	case 1:
		return "*"
	case 2:
		return value[:1] + "*"
	default:
		return value[:1] + "***" + value[len(value)-1:]
	}
}
