package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

var oauthConfig *oauth2.Config
var oauthUserinfoUrl string
var radiusTokenExpiry time.Duration

var oauthAuthMutex sync.RWMutex
var oauthAuthorizations map[string]OAuthUserInfo

type OAuthUserInfo struct {
	Sub                   string `json:"sub"`
	Name                  string `json:"name"`
	Username              string `json:"preferred_username"`
	MikrotikGroup         string `json:"mikrotik_group"`
	SupermicroPermissions string `json:"supermicro_permissions"`
	token                 string
	expiry                time.Time
}

func randomToken() string {
	buff := make([]byte, 12) // 16 after b64
	rand.Read(buff)
	return base64.RawURLEncoding.EncodeToString(buff)
}

func startOAuthServer() {
	var err error

	radiusTokenExpiry, err = time.ParseDuration(os.Getenv("RADIUS_TOKEN_EXPIRY"))
	if err != nil {
		log.Fatalf("Failed to parse RADIUS_TOKEN_EXPIRY: %v", err)
	}

	oauthAuthorizations = make(map[string]OAuthUserInfo)

	oauthUserinfoUrl = os.Getenv("OAUTH_USERINFO_URL")

	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(os.Getenv("OAUTH_SCOPES"), " "),
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("OAUTH_AUTH_URL"),
			TokenURL: os.Getenv("OAUTH_TOKEN_URL"),
		},
		RedirectURL: os.Getenv("OAUTH_REDIRECT_URL"),
	}

	go loopCleanupUserInfo()

	http.HandleFunc("/", handleLogin)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/redirect", handleRedirect)
	log.Printf("Starting OAuth server on %s", os.Getenv("OAUTH_SERVER_ADDR"))
	log.Printf("Visit: %s", os.Getenv("OAUTH_LOGIN_URL"))

	if err := http.ListenAndServe(os.Getenv("OAUTH_SERVER_ADDR"), nil); err != nil {
		log.Fatal(err)
	}
}

func handleRedirect(wr http.ResponseWriter, r *http.Request) {
	wr.Header().Add("Content-Type", "text/plain")

	code := r.URL.Query().Get("code")

	tok, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(wr, "Failed to exchange token: "+err.Error(), http.StatusBadRequest)
		return
	}

	client := oauthConfig.Client(r.Context(), tok)
	userinfoResp, err := client.Get(oauthUserinfoUrl)
	if err != nil {
		http.Error(wr, "Failed to get userinfo", http.StatusInternalServerError)
		log.Printf("Failed to get userinfo: %v", err)
		return
	}

	userInfo := &OAuthUserInfo{
		token:  randomToken(),
		expiry: time.Now().Add(radiusTokenExpiry),
	}
	jsonDecoder := json.NewDecoder(userinfoResp.Body)
	err = jsonDecoder.Decode(userInfo)
	if err != nil {
		http.Error(wr, "Failed to unmarshal userinfo", http.StatusInternalServerError)
		log.Printf("Failed to unmarshal userinfo: %v", err)
		return
	}

	oauthAuthMutex.Lock()
	defer oauthAuthMutex.Unlock()

	oauthAuthorizations[userInfo.Username] = *userInfo
	wr.Write([]byte(fmt.Sprintf("RADIUS username: %s\nRADIUS password: %s\nIt will expire: %v\n", userInfo.Username, userInfo.token, userInfo.expiry)))
}

func handleLogin(wr http.ResponseWriter, r *http.Request) {
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOnline)
	http.Redirect(wr, r, url, http.StatusFound)
}

func GetUserInfoForUser(username string) (OAuthUserInfo, error) {
	oauthAuthMutex.RLock()
	defer oauthAuthMutex.RUnlock()

	authInfo, ok := oauthAuthorizations[username]
	if !ok || authInfo.expiry.Before(time.Now()) {
		return OAuthUserInfo{}, nil
	}

	return authInfo, nil
}

func cleanupUserInfo() {
	oauthAuthMutex.Lock()
	defer oauthAuthMutex.Unlock()

	for username, authInfo := range oauthAuthorizations {
		if authInfo.expiry.Before(time.Now()) {
			delete(oauthAuthorizations, username)
		}
	}
}

func loopCleanupUserInfo() {
	for {
		time.Sleep(1 * time.Minute)
		cleanupUserInfo()
	}
}
