package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskEmail(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "standard", input: "alice@example.com", want: "a***e@example.com"},
		{name: "short local", input: "ab@c.com", want: "a*@c.com"},
		{name: "single char local", input: "a@x.com", want: "*@x.com"},
		{name: "no at sign", input: "secret", want: "s***t"},
		{name: "empty", input: "  ", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, MaskEmail(tc.input))
		})
	}
}
