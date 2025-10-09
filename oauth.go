package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aohorodnyk/mimeheader"
	"golang.org/x/oauth2"
)

var oauthConfig *oauth2.Config
var oauthUserInfoUrl string
var radiusPasswordExpiry time.Duration

var oauthAuthMutex sync.RWMutex
var oauthAuthorizations map[string]*OAuthUserInfo

var oauthVerifierLock sync.Mutex
var oauthVerifierMap map[string]*oauthVerifier

var oauthTLSCertFilename string
var oauthTLSLoadTime time.Time

type oauthVerifier struct {
	Verifier string
	expiry   time.Time
}

type OAuthUserInfo struct {
	Username              string        `json:"preferred_username" yaml:"username"`
	MikrotikGroup         []string      `json:"mikrotik_group" yaml:"mikrotik_group"`
	APCServiceType        []string      `json:"apc_service_type" yaml:"apc_service_type"`
	APCOutlets            []string      `json:"apc_outlets" yaml:"apc_outlets"`
	CyberPowerServiceType []string      `json:"cyberpower_service_type" yaml:"cyberpower_service_type"`
	SupermicroPermissions []string      `json:"supermicro_permissions" yaml:"supermicro_permissions"`
	Password              StringWithEnv `yaml:"password"`
	AllowedIPs            []net.IP      `yaml:"allowed_ips"`
	Expiry                time.Time
}

type serializedUserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Expiry   string `json:"expiry"`
}

func HasClaim(claims []string, claim string) bool {
	for _, c := range claims {
		if c == claim {
			return true
		}
	}
	return false
}

func randomPassword() string {
	buff := make([]byte, 12) // 16 after b64
	_, err := rand.Read(buff)
	if err != nil {
		log.Fatalf("Failed to generate random password: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buff)
}

func startOAuthServer() {
	var err error

	cfg := GetConfig()

	radiusPasswordExpiry, err = time.ParseDuration(string(cfg.Radius.PasswordExpiry))
	if err != nil {
		log.Fatalf("Failed to parse RADIUS password_expiry: %v", err)
	}

	oauthAuthorizations = make(map[string]*OAuthUserInfo)
	oauthVerifierMap = make(map[string]*oauthVerifier)

	oauthUserInfoUrl = string(cfg.OAuth.UserInfoURL)

	oauthConfig = &oauth2.Config{
		ClientID:     string(cfg.OAuth.ClientID),
		ClientSecret: string(cfg.OAuth.ClientSecret),
		Scopes:       cfg.OAuth.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  string(cfg.OAuth.AuthURL),
			TokenURL: string(cfg.OAuth.TokenURL),
		},
		RedirectURL: string(cfg.OAuth.RedirectURL),
	}

	go loopOauthMaintenance()

	http.HandleFunc("/{$}", handleLogin)
	http.HandleFunc("/index.htm", handleLogin)
	http.HandleFunc("/index.html", handleLogin)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/redirect", handleRedirect)
	http.HandleFunc("/rendertest", handleRenderTest)
	http.Handle("/", http.FileServerFS(webHttpFs))
	log.Printf("Starting OAuth server on %s", cfg.OAuth.ServerAddr)

	oauthTLSCertFilename = cfg.OAuth.TLS.CertFile
	tlsKey := cfg.OAuth.TLS.KeyFile
	if oauthTLSCertFilename != "" && tlsKey != "" {
		oauthTLSLoadTime = time.Now()
		err = http.ListenAndServeTLS(string(cfg.OAuth.ServerAddr), oauthTLSCertFilename, tlsKey, nil)
	} else {
		oauthTLSCertFilename = ""
		err = http.ListenAndServe(string(cfg.OAuth.ServerAddr), nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func handleRedirect(wr http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	oauthVerifierLock.Lock()
	verifierEntry := oauthVerifierMap[state]
	delete(oauthVerifierMap, state)
	oauthVerifierLock.Unlock()

	if verifierEntry == nil || verifierEntry.expiry.Before(time.Now()) {
		handleLogin(wr, r)
		return
	}

	tok, err := oauthConfig.Exchange(r.Context(), code, oauth2.VerifierOption(verifierEntry.Verifier))
	if err != nil {
		http.Error(wr, "Failed to exchange token: "+err.Error(), http.StatusBadRequest)
		return
	}

	client := oauthConfig.Client(r.Context(), tok)
	userInfoResp, err := client.Get(oauthUserInfoUrl)
	if err == nil && (userInfoResp.StatusCode < 200 || userInfoResp.StatusCode >= 300) {
		err = fmt.Errorf("http error %d (%s)", userInfoResp.StatusCode, userInfoResp.Status)
	}
	if err != nil {
		http.Error(wr, "Failed to get userinfo", http.StatusInternalServerError)
		log.Printf("Failed to get userinfo: %v", err)
		return
	}

	userInfo := &OAuthUserInfo{}
	jsonDecoder := json.NewDecoder(userInfoResp.Body)
	err = jsonDecoder.Decode(userInfo)
	if err == nil && userInfo.Username == "" {
		err = errors.New("missing username in userinfo")
	}
	if err != nil {
		http.Error(wr, "Failed to unmarshal userinfo", http.StatusInternalServerError)
		log.Printf("Failed to unmarshal userinfo: %v", err)
		return
	}

	oauthAuthMutex.Lock()
	defer oauthAuthMutex.Unlock()

	userInfoOld := getUserInfoForUserNoLock(userInfo.Username)
	if userInfoOld == nil {
		userInfo.Password = StringWithEnv(randomPassword())
	} else {
		userInfo.Password = userInfoOld.Password
	}
	userInfo.Expiry = time.Now().Add(radiusPasswordExpiry)

	oauthAuthorizations[userInfo.Username] = userInfo
	renderUserInfo(wr, r, userInfo)
}

func handleRenderTest(wr http.ResponseWriter, r *http.Request) {
	dummyUserInfo := &OAuthUserInfo{
		Username: "testuser",
		Password: "testtoken",
		Expiry:   time.Now().Add(radiusPasswordExpiry),
	}
	renderUserInfo(wr, r, dummyUserInfo)
}

func renderUserInfo(wr http.ResponseWriter, r *http.Request, userInfo *OAuthUserInfo) {
	if userInfo == nil {
		http.Error(wr, "Not found", http.StatusNotFound)
		return
	}

	accept := mimeheader.ParseAcceptHeader(r.Header.Get("Accept"))
	_, mimeType, _ := accept.Negotiate([]string{"text/html", "application/json"}, "text/html")

	switch mimeType {
	case "application/json":
		wr.Header().Set("Content-Type", "application/json")
		marshaler := json.NewEncoder(wr)
		err := marshaler.Encode(&serializedUserInfo{
			Username: userInfo.Username,
			Password: string(userInfo.Password),
			Expiry:   userInfo.Expiry.Format(TimeMachineReadable),
		})
		if err != nil {
			http.Error(wr, "Failed to marshal userinfo", http.StatusInternalServerError)
			log.Printf("Failed to marshal userinfo: %v", err)
		}
	case "text/html":
		fallthrough
	default:
		wr.Header().Set("Content-Type", "text/html")
		RenderTemplate(wr, r, "credentials.html", userInfo)
	}
}

func handleLogin(wr http.ResponseWriter, r *http.Request) {
	state := randomPassword()

	verifier := oauth2.GenerateVerifier()
	oauthVerifierLock.Lock()
	oauthVerifierMap[state] = &oauthVerifier{
		Verifier: verifier,
		expiry:   time.Now().Add(5 * time.Minute),
	}
	oauthVerifierLock.Unlock()

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(wr, r, url, http.StatusFound)
}

func getUserInfoForUserNoLock(username string) *OAuthUserInfo {
	authInfo, ok := oauthAuthorizations[username]
	if !ok || authInfo.Expiry.Before(time.Now()) {
		return nil
	}

	return authInfo
}

func GetUserInfoForUser(username string, remoteAddr net.Addr) *OAuthUserInfo {
	userInfo := GetStaticUserInfo(username, remoteAddr)
	if userInfo != nil {
		return userInfo
	}

	oauthAuthMutex.RLock()
	defer oauthAuthMutex.RUnlock()

	return getUserInfoForUserNoLock(username)
}

func cleanupUserInfo() {
	oauthAuthMutex.Lock()
	defer oauthAuthMutex.Unlock()

	for username, authInfo := range oauthAuthorizations {
		if authInfo.Expiry.Before(time.Now()) {
			delete(oauthAuthorizations, username)
		}
	}
}

func cleanupVerifiers() {
	oauthVerifierLock.Lock()
	defer oauthVerifierLock.Unlock()

	for verifier, v := range oauthVerifierMap {
		if v.expiry.Before(time.Now()) {
			delete(oauthVerifierMap, verifier)
		}
	}
}

func shutdownIfNewTLSCert() {
	if oauthTLSCertFilename == "" {
		return
	}

	stat, err := os.Stat(oauthTLSCertFilename)
	if err != nil {
		log.Fatalf("Failed to stat TLS cert: %v", err)
	}

	if stat.ModTime().After(oauthTLSLoadTime) {
		log.Printf("New TLS cert detected, restarting")
		os.Exit(0)
	}
}

func loopOauthMaintenance() {
	for {
		time.Sleep(1 * time.Minute)
		shutdownIfNewTLSCert()
		cleanupUserInfo()
		cleanupVerifiers()
	}
}
