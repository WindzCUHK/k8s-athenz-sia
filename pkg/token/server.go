package token

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/AthenZ/k8s-athenz-sia/third_party/log"
)

const (
	DOMAIN_HEADER = "X-Athenz-Domain"
	ROLE_HEADER   = "X-Athenz-Role"
)

func postRoleToken(d *daemon, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errMsg := fmt.Sprintf("Method: %s\t%s", r.Method, http.StatusText(http.StatusMethodNotAllowed))
		http.Error(w, errMsg, http.StatusMethodNotAllowed)
		log.Warnf(errMsg)
		return
	}

	var err error
	defer func() {
		if err != nil {
			errMsg := fmt.Sprintf("Error: %s\t%s", err.Error(), http.StatusText(http.StatusInternalServerError))
			http.Error(w, errMsg, http.StatusInternalServerError)
			log.Warnf(errMsg)
		}
	}()

	// parse body
	rtRequest := RoleTokenRequestBody{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&rtRequest); err != nil {
		return
	}

	// validate body
	domain := rtRequest.Domain
	role := rtRequest.Role
	if domain == "" || role == "" {
		err = fmt.Errorf("Invalid value: domain[%s], role[%s]", domain, role)
		return
	}

	// create cache key
	k := CacheKey{Domain: domain, Role: role}
	if rtRequest.ProxyForPrincipal != nil {
		k.ProxyForPrincipal = *rtRequest.ProxyForPrincipal
	}
	if rtRequest.MinExpiry != nil {
		k.MinExpiry = *rtRequest.MinExpiry
	}
	if rtRequest.MaxExpiry != nil {
		k.MaxExpiry = *rtRequest.MaxExpiry
	}
	if k.MinExpiry != 0 {
		k.MinExpiry = d.tokenExpiryInSecond
	}

	// cache lookup
	rToken := d.roleTokenCache.Load(k)
	if rToken == nil {
		log.Debugf("Role token cache miss, attempting to fetch token from Athenz ZTS server: target[%s]", k.String())
		// on cache miss, fetch token from Athenz ZTS server
		rToken, err = fetchRoleToken(d.ztsClient, k)
		if err == nil {
			return
		}
		// update cache
		d.roleTokenCache.Store(k, rToken)
		log.Infof("Role token cache miss, successfully updated role token cache:: target[%s]", k.String())
	}

	// response
	rtResponse := RoleTokenResponse{
		Token:      rToken.Raw(),
		ExpiryTime: rToken.Expiry(),
	}
	w.Header().Set("Content-type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(rtResponse)
	return
}

func newHandlerFunc(d *daemon) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// sidecar API
		if r.RequestURI == "/roletoken" {
			postRoleToken(d, w, r)
			return
		}

		// API for envoy (all methods and paths)
		domain := r.Header.Get(DOMAIN_HEADER)
		role := r.Header.Get(ROLE_HEADER)

		var errMsg = ""
		var aToken, rToken Token
		if domain == "" || role == "" {
			errMsg = fmt.Sprintf("http headers not set: %s[%s] %s[%s].", DOMAIN_HEADER, domain, ROLE_HEADER, role)
		} else {
			k := CacheKey{Domain: domain, Role: role, MinExpiry: d.tokenExpiryInSecond}
			if d.tokenType.Has(ACCESS_TOKEN) {
				aToken = d.accessTokenCache.Load(k)
				if aToken == nil {
					errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
				}
			}
			if d.tokenType.Has(ROLE_TOKEN) {
				rToken = d.roleTokenCache.Load(k)
				if rToken == nil {
					errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
				}
			}
		}

		if len(errMsg) > 0 {
			response, err := json.Marshal(map[string]string{"error": errMsg})
			if err != nil {
				log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			errMsg = fmt.Sprintf("error writing json response with: %s[%s] %s[%s] error[%s].", DOMAIN_HEADER, domain, ROLE_HEADER, role, errMsg)
			log.Warnf(errMsg)
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, string(response))
			return
		}

		resJSON := make(map[string]string, 2)
		if aToken != nil {
			at := aToken.Raw()
			w.Header().Set("Authorization", "bearer "+at)
			resJSON["accesstoken"] = at
		}
		if rToken != nil {
			rt := rToken.Raw()
			w.Header().Set(d.roleAuthHeader, rt)
			resJSON["roletoken"] = rt
		}
		response, err := json.Marshal(resJSON)
		if err != nil {
			log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Debugf("Returning %d for domain[%s], role[%s]", d.tokenType, domain, role)
		io.WriteString(w, string(response))
	}
}
