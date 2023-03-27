package util

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/util"
)

const NS_DELIMITER = "-"
const DOMAIN_DELIMITER = "."

// NamespaceToDomain converts a kube namespace to an Athenz domain
func NamespaceToDomain(ns string) (domain string) {
	d := util.EnvOrDefault("ATHENZ_DOMAIN", "")
	pre := util.EnvOrDefault("ATHENZ_PREFIX", "")
	suf := util.EnvOrDefault("ATHENZ_SUFFIX", "")

	if d == "" {
		return pre + ns + suf
	}
	return pre + d + suf
}

// ServiceAccountToService converts a kube serviceaccount name to an Athenz service
func ServiceAccountToService(svc string) string {
	return svc
}

// ServiceSpiffeURI returns the SPIFFE URI for the specified Athens domain and service.
func ServiceSpiffeURI(domain, service string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/sa/%s", domain, service))
}

// RoleSpiffeURI returns the SPIFFE URI for the specified Athens domain and service.
func RoleSpiffeURI(domain, role string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/ra/%s", domain, role))
}

// DomainToDNSPart converts the Athenz domain into a DNS label
func DomainToDNSPart(domain string) (part string) {
	return strings.Replace(domain, ".", "-", -1)
}
