package token

type Token interface {
	Domain() string
	Role() string
	Raw() string
	Expiry() int64
}

// RoleToken stores role token
type RoleToken struct {
	domain string
	role   string
	raw    string
	expiry int64
}

func (t *RoleToken) Domain() string {
	return t.domain
}

func (t *RoleToken) Role() string {
	return t.role
}

func (t *RoleToken) Raw() string {
	return t.raw
}

func (t *RoleToken) Expiry() int64 {
	return t.expiry
}

// AccessToken stores access token
type AccessToken struct {
	domain string
	role   string
	raw    string
	expiry int64
}

func (t *AccessToken) Domain() string {
	return t.domain
}

func (t *AccessToken) Role() string {
	return t.role
}

func (t *AccessToken) Raw() string {
	return t.raw
}

func (t *AccessToken) Expiry() int64 {
	return t.expiry
}
