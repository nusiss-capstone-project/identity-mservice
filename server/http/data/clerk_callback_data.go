package data

import "strings"

type ClerkCallbackRequest struct {
	Type string             `json:"type"`
	Data *ClerkCallbackData `json:"data"`
}

// ClerkCallbackData maps Clerk user.created event data (fields used for user mapping).
type ClerkCallbackData struct {
	ID                    string              `json:"id"`
	PrimaryEmailAddressID string              `json:"primary_email_address_id"` // email address resource id, not the email string
	EmailAddresses        []ClerkEmailAddress `json:"email_addresses"`
}

type ClerkEmailAddress struct {
	ID           string `json:"id"`
	EmailAddress string `json:"email_address"`
}

func (d *ClerkCallbackData) ClerkUserID() string {
	if d == nil {
		return ""
	}
	return d.ID
}

// EmailAddress returns the primary email string from email_addresses[].email_address.
// primary_email_address_id is only used to pick the matching entry; it is not an email.
func (d *ClerkCallbackData) EmailAddress() string {
	if d == nil || len(d.EmailAddresses) == 0 {
		return ""
	}
	if d.PrimaryEmailAddressID != "" {
		for _, addr := range d.EmailAddresses {
			if addr.ID == d.PrimaryEmailAddressID {
				return normalizeEmail(addr.EmailAddress)
			}
		}
	}
	for _, addr := range d.EmailAddresses {
		if email := normalizeEmail(addr.EmailAddress); email != "" {
			return email
		}
	}
	return ""
}

func normalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return ""
	}
	return email
}
