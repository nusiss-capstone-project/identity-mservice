package data

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClerkCallbackRequest_unmarshalUserCreated(t *testing.T) {
	payload := `{
		"type": "user.created",
		"data": {
			"id": "user_29w83sxmDNGwOuEthce5gg56FcC",
			"primary_email_address_id": "idn_29w83yL7CwVlJXylYLxcslromF1",
			"email_addresses": [
				{
					"id": "idn_29w83yL7CwVlJXylYLxcslromF1",
					"email_address": "example@example.org"
				}
			]
		}
	}`

	var req ClerkCallbackRequest
	require.NoError(t, json.Unmarshal([]byte(payload), &req))
	require.Equal(t, "user.created", req.Type)
	require.Equal(t, "user_29w83sxmDNGwOuEthce5gg56FcC", req.Data.ClerkUserID())
	require.Equal(t, "example@example.org", req.Data.EmailAddress())
}

func TestClerkCallbackData_EmailAddress_usesPrimaryID(t *testing.T) {
	data := &ClerkCallbackData{
		PrimaryEmailAddressID: "idn_primary",
		EmailAddresses: []ClerkEmailAddress{
			{ID: "idn_other", EmailAddress: "other@example.com"},
			{ID: "idn_primary", EmailAddress: "primary@example.com"},
		},
	}
	require.Equal(t, "primary@example.com", data.EmailAddress())
}

func TestClerkCallbackData_EmailAddress_fallsBackToFirst(t *testing.T) {
	require.Empty(t, (*ClerkCallbackData)(nil).EmailAddress())
	require.Empty(t, (&ClerkCallbackData{}).EmailAddress())
	require.Equal(t, "a@b.com", (&ClerkCallbackData{
		EmailAddresses: []ClerkEmailAddress{{EmailAddress: "a@b.com"}},
	}).EmailAddress())
}

func TestClerkCallbackData_EmailAddress_doesNotReturnID(t *testing.T) {
	data := &ClerkCallbackData{
		PrimaryEmailAddressID: "idn_primary",
		EmailAddresses: []ClerkEmailAddress{
			{ID: "idn_primary"},
		},
	}
	require.Empty(t, data.EmailAddress())
}

func TestClerkCallbackData_ClerkUserID(t *testing.T) {
	require.Empty(t, (*ClerkCallbackData)(nil).ClerkUserID())
	require.Equal(t, "user_abc", (&ClerkCallbackData{ID: "user_abc"}).ClerkUserID())
}
