package main

import (
	"fmt"
	"strings"
)

// canonicalDomain returns the canonical form of a DNS domain or an error.
//
// It must agree with the MasterDNS server's normalizeDomain (lowercase, trim
// surrounding whitespace, strip exactly one trailing root dot) so the panel and
// the server never disagree on identity. Previously the panel kept the trailing
// dot while the server stripped it, letting "x.example.com" and "x.example.com."
// pass validation as two domains that collapse to one runtime domain — which
// could smuggle non-AEAD keys into a multi-key ring (F06).
func canonicalDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".") // remove one legal trailing root dot
	if d == "" {
		return "", fmt.Errorf("домен обязателен")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("домен слишком длинный")
	}
	if !strings.Contains(d, ".") {
		return "", fmt.Errorf("укажите делегированный домен (например v.example.com)")
	}
	labels := strings.Split(d, ".")
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("домен содержит пустую метку")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("метка домена слишком длинная")
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return "", fmt.Errorf("домен содержит недопустимый символ %q", string(r))
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("метка домена не может начинаться или заканчиваться дефисом")
		}
	}
	return d, nil
}
