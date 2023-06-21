package token

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"

	"github.com/AthenZ/k8s-athenz-sia/pkg/config"
	extutil "github.com/AthenZ/k8s-athenz-sia/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/third_party/util"
)

// TODO
// targets with expiry + proxyforprincipal

// Tokend starts the token server and refreshes tokens periodically.
func Tokend(idConfig *config.IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {

	if stopChan == nil {
		panic(fmt.Errorf("Tokend: stopChan cannot be empty"))
	}

	if idConfig.TokenServerAddr == "" || idConfig.TargetDomainRoles == "" || idConfig.TokenType == "" {
		log.Infof("Token provider is disabled with empty options: address[%s], roles[%s], token-type[%s]", idConfig.TokenServerAddr, idConfig.TargetDomainRoles, idConfig.TokenType)
		return nil, nil
	}

	var roleTokenCache, accessTokenCache TokenCache
	roleTokenCache = &LockedTokenCache{cache: make(map[string]map[string]Token)}
	accessTokenCache = &LockedTokenCache{cache: make(map[string]map[string]Token)}

	var keyPem, certPem []byte
	var err error

	writeFiles := func() error {

		w := util.NewWriter()

		accessTokenCache.Range(func(t Token) error {
			domain := t.Domain()
			role := t.Role()
			at := t.Raw()
			log.Infof("[New Access Token] Domain: %s, Role: %s", domain, role)
			outPath := filepath.Join(idConfig.TokenDir, domain+":role."+role+".accesstoken")
			log.Debugf("Saving Access Token[%d bytes] at %s", len(at), outPath)
			if err := w.AddBytes(outPath, 0644, []byte(at)); err != nil {
				return errors.Wrap(err, "unable to save access token")
			}
			return nil
		})
		roleTokenCache.Range(func(t Token) error {
			domain := t.Domain()
			role := t.Role()
			rt := t.Raw()
			log.Infof("[New Role Token] Domain: %s, Role: %s", domain, role)
			outPath := filepath.Join(idConfig.TokenDir, domain+":role."+role+".roletoken")
			log.Debugf("Saving Role Token[%d bytes] at %s", len(rt), outPath)
			if err := w.AddBytes(outPath, 0644, []byte(rt)); err != nil {
				return errors.Wrap(err, "unable to save role token")
			}
			return nil
		})

		return w.Save()
	}

	// getExponentialBackoff will return a backoff config with first retry delay of 5s, and backoff retry
	// until TOKEN_REFRESH_INTERVAL / 4
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = idConfig.TokenRefresh / 4
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh tokens: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	run := func() error {

		log.Debugf("Attempting to load x509 certificate from local file to get tokens: key[%s], cert[%s]...", idConfig.KeyFile, idConfig.CertFile)

		certPem, err = os.ReadFile(idConfig.CertFile)
		if err != nil {
			log.Warnf("Error while reading x509 certificate from local file[%s]: %s", idConfig.CertFile, err.Error())
		}
		keyPem, err = os.ReadFile(idConfig.KeyFile)
		if err != nil {
			log.Warnf("Error while reading x509 certificate key from local file[%s]: %s", idConfig.KeyFile, err.Error())
		}

		if len(certPem) == 0 || len(keyPem) == 0 {
			log.Errorf("Failed to load x509 certificate from local file to get tokens: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))
			return nil
		} else {

			log.Debugf("Successfully loaded x509 certificate from local file to get tokens: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))

		}

		log.Infof("Attempting to get tokens from identity provider: targets[%s]...", idConfig.TargetDomainRoles)

		roleTokens, accessTokens, err := GetToken(idConfig, certPem, keyPem)
		if err != nil {
			log.Warnf("Error while requesting tokens: %s", err.Error())
			return err
		}

		log.Debugf("Successfully received tokens from identity provider: roleTokens(%d), accessTokens(%d)", len(roleTokens), len(accessTokens))

		for _, r := range roleTokens {
			roleTokenCache.Update(r)
		}
		for _, a := range accessTokens {
			accessTokenCache.Update(a)
		}

		log.Infof("Successfully updated token cache: roleTokens(%d), accessTokens(%d)", len(roleTokens), len(accessTokens))

		if idConfig.TokenDir != "" {
			return writeFiles()
		} else {
			log.Debugf("Skipping to write token files to directory[%s]", idConfig.TokenDir)
			return nil
		}
	}

	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		domainHeader := "X-Athenz-Domain"
		roleHeader := "X-Athenz-Role"
		domain := r.Header.Get(domainHeader)
		role := r.Header.Get(roleHeader)
		at, rt, errMsg, response := "", "", "", []byte("")
		var err error
		var aToken, rToken Token

		if domain == "" || role == "" {
			errMsg = fmt.Sprintf("http headers not set: %s[%s] %s[%s].", domainHeader, domain, roleHeader, role)
		}

		switch idConfig.TokenType {
		case "roletoken":
			rToken = roleTokenCache.Load(domain, role)
			if rToken == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		case "accesstoken":
			aToken = accessTokenCache.Load(domain, role)
			if aToken == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		case "roletoken+accesstoken":
			rToken = roleTokenCache.Load(domain, role)
			aToken = accessTokenCache.Load(domain, role)
			if rToken == nil || aToken == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		}

		if err != nil || len(errMsg) > 0 {
			response, err = json.Marshal(map[string]string{"error": errMsg})
			if err != nil {
				log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
				return
			}
			errMsg = fmt.Sprintf("error writing json response with: %s[%s] %s[%s] error[%s].", domainHeader, domain, roleHeader, role, errMsg)
			log.Warnf(errMsg)
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, string(response))
			return
		}

		switch idConfig.TokenType {
		case "roletoken":
			rt = rToken.Raw()
			w.Header().Set(idConfig.RoleAuthHeader, rt)
			response, err = json.Marshal(map[string]string{"roletoken": rt})
		case "accesstoken":
			at = aToken.Raw()
			w.Header().Set("Authorization", "bearer "+at)
			response, err = json.Marshal(map[string]string{"accesstoken": at})
		case "roletoken+accesstoken":
			rt = rToken.Raw()
			at = aToken.Raw()
			w.Header().Set("Authorization", "bearer "+at)
			w.Header().Set(idConfig.RoleAuthHeader, rt)
			response, err = json.Marshal(map[string]string{"accesstoken": at, "roletoken": rt})
		}

		if err != nil {
			log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
			return
		}

		log.Debugf("Returning %s for domain[%s], role[%s]", idConfig.TokenType, domain, role)
		io.WriteString(w, string(response))
	}

	err = backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
	if err != nil {
		log.Errorf("Failed to get initial tokens after multiple retries: %s", err.Error())
	}

	if idConfig.Init {
		log.Infof("Token provider is disabled for init mode: address[%s]", idConfig.TokenServerAddr)
		return nil, nil
	}

	httpServer := &http.Server{
		Addr:    idConfig.TokenServerAddr,
		Handler: http.HandlerFunc(tokenHandler),
	}

	go func() {
		log.Infof("Starting token provider[%s]", idConfig.TokenServerAddr)

		if err := httpServer.ListenAndServe(); err != nil {
			log.Errorf("Failed to start token provider: %s", err.Error())
		}
	}()

	shutdownChan := make(chan struct{}, 1)
	t := time.NewTicker(idConfig.TokenRefresh)
	go func() {
		defer t.Stop()
		defer close(shutdownChan)

		for {
			log.Infof("Refreshing tokens for roles[%v] in %s", idConfig.TargetDomainRoles, idConfig.TokenRefresh)

			select {
			case <-t.C:
				err := backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				httpServer.SetKeepAlivesEnabled(false)
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Errorf("Failed to shutdown token provider: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil, shutdownChan
}

// GetToken makes ZTS API calls to generate an X.509 role certificate
func GetToken(cfg *config.IdentityConfig, certPEM, keyPEM []byte) (roletokens [](*RoleToken), accesstokens [](*AccessToken), err error) {

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("Failed to load tls client key pair for PostAccessTokenRequest, err: %v", err)
		}
		return &cert, nil
	}
	t := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if cfg.ServerCACert != "" {
		certPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(cfg.ServerCACert)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to load tls client ca certificate for PostAccessTokenRequest, err: %v", err)
		}
		certPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = certPool
		t.TLSClientConfig = tlsConfig
	}

	// In init mode, the existing ZTS Client does not have client certificate set.
	// When config.Reloader.GetLatestCertificate() is called to load client certificate, the first certificate has not written to the file yet.
	// Therefore, ZTS Client must be renewed to make sure the ZTS Client loads the latest client certificate.
	//
	// The intermediate certificates may be different between each ZTS.
	// Therefore, ZTS Client for PostRoleCertificateRequest must share the same endpoint as PostInstanceRegisterInformation/PostInstanceRefreshInformation
	roleClient := zts.NewClient(cfg.Endpoint, t)
	expireTimeMs := int32(120 * 60) // TODO: remove hardcoded value

	for _, domainrole := range strings.Split(cfg.TargetDomainRoles, ",") {
		dr := strings.Split(domainrole, ":role.")

		if strings.Contains(cfg.TokenType, "accesstoken") {
			// TODO: move to init
			request := athenzutils.GenerateAccessTokenRequestString(dr[0], extutil.ServiceAccountToService(cfg.ServiceAccount), dr[1], "", "", int(expireTimeMs))
			accessTokenResponse, err := roleClient.PostAccessTokenRequest(zts.AccessTokenRequest(request))
			if err != nil || accessTokenResponse.Access_token == "" {
				return nil, nil, fmt.Errorf("PostAccessTokenRequest failed for domain[%s], role[%s], err: %v", dr[0], dr[1], err)
			}
			accesstokens = append(accesstokens, &AccessToken{
				domain: dr[0],
				role:   dr[1],
				raw:    accessTokenResponse.Access_token,
				expiry: int64(*accessTokenResponse.Expires_in),
			})
		}

		if strings.Contains(cfg.TokenType, "roletoken") {
			roletokenResponse, err := roleClient.GetRoleToken(zts.DomainName(dr[0]), zts.EntityList(dr[1]), &expireTimeMs, &expireTimeMs, "")
			if err != nil || roletokenResponse.Token == "" {
				return nil, nil, fmt.Errorf("GetRoleToken failed for domain[%s], role[%s], err: %v", dr[0], dr[1], err)
			}
			roletokens = append(roletokens, &RoleToken{
				domain: dr[0],
				role:   dr[1],
				raw:    roletokenResponse.Token,
				expiry: roletokenResponse.ExpiryTime,
			})
		}
	}

	return roletokens, accesstokens, err
}
