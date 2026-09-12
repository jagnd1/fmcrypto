package validate

import (
	"fmt"
	"net/mail"
	"strings"
)

func Required(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("required")
	}
	return nil
}

func Email(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return fmt.Errorf("invalid email")
	}
	return nil
}

func MaxLen(s string, n int) error {
	if len(s) > n {
		return fmt.Errorf("max %d chars", n)
	}
	return nil
}