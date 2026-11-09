package token

import (
	"strings"
	"testing"
)

func TestGenerateValidate(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(tok) != 43 {
		t.Errorf("token length = %d, want 43", len(tok))
	}
	if _, err := Validate(tok); err != nil {
		t.Errorf("Validate(generated) = %v", err)
	}
	other, _ := Generate()
	if tok == other {
		t.Error("two generated tokens are identical")
	}
}

func TestValidateRejects(t *testing.T) {
	bad := []string{"", "short", "has space in the middle-1234", "tab\tin-token-1234567890", strings.Repeat("x", 513)}
	for _, in := range bad {
		if _, err := Validate(in); err == nil {
			t.Errorf("Validate(%q) = nil, want an error", in)
		}
	}
}

func TestEqual(t *testing.T) {
	a := "0123456789abcdef"
	b := "0123456789abcdef"
	c := "0123456789abcdee"
	if !Equal(a, b) {
		t.Error("Equal(a, b) = false")
	}
	if Equal(a, c) {
		t.Error("Equal(a, c) = true")
	}
	if Equal("", "") {
		t.Error("Equal(\"\", \"\") = true")
	}
}
