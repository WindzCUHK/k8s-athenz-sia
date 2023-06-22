package token

import "strings"

type Type int

const (
	ACCESS_TOKEN Type = 1 << iota // 01
	ROLE_TOKEN                    // 10
)

func (mode Type) Has(t Type) bool {
	return mode&t == t
}

func (mode Type) Disable(t Type) Type {
	return mode &^ t
}

func (mode Type) Enable(t Type) Type {
	return mode | t
}

func newType(raw string) (t Type) {
	if raw == "" {
		return t
	}
	if strings.Contains(raw, "accesstoken") {
		t |= ACCESS_TOKEN
	}
	if strings.Contains(raw, "roletoken") {
		t |= ROLE_TOKEN
	}
	return t
}
