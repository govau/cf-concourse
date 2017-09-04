package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/concourse/atc/auth"
	"github.com/gorilla/sessions"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	cfcommon "github.com/govau/cf-common"
)

type ttlBytes struct {
	Bytes []byte
	KeyID string
	TTL   time.Time
}

type cfFlyServer struct {
	CFAPIURL string // e.g. https://api.system.example.com
	OurURL   string // e.g. http://localhost

	UAAAPIClientID     string // as configured in UAA
	UAAWebClientID     string // as configured in UAA
	UAAWebClientSecret string // per UAA

	ConcourseClientID     string
	ConcourseClientSecret string
	ConcourseCallbackURL  string

	CookieStore *sessions.CookieStore

	// Internal
	uaaClient *cfcommon.UAAClient

	keyLock sync.RWMutex

	// current key
	curPrivateKey *rsa.PrivateKey
	currentKeyID  string
	currentTTL    time.Time

	// source material
	allKeys []*ttlBytes

	// to serve
	publicKeys []byte

	// Codes
	codeLock sync.Mutex
	codes    map[string]*tbsToken
}

// Init must be called at server start
func (s *cfFlyServer) Init() error {
	s.codes = make(map[string]*tbsToken)

	var err error
	s.uaaClient, err = cfcommon.NewUAAClientFromAPIURL(s.CFAPIURL)
	if err != nil {
		return err
	}
	err = s.rotateSigningKey(time.Now().Add(time.Hour * 24))
	if err != nil {
		return err
	}

	return nil
}

func (s *cfFlyServer) getCurrentKey(desiredTTL time.Time) (*rsa.PrivateKey, string, error) {
	for i := 0; i < 2; i++ {
		s.keyLock.RLock()
		k := s.curPrivateKey
		t := s.currentTTL
		i := s.currentKeyID
		s.keyLock.RUnlock()

		// Make sure we're good for at least an hour
		if t.After(desiredTTL) {
			return k, i, nil
		}

		err := s.rotateSigningKey(desiredTTL)
		if err != nil {
			return nil, "", err
		}
	}
	return nil, "", errors.New("took too long")
}

// generate a new key for signing, discard old ones. New one will be valid at least the length of the desired
func (s *cfFlyServer) rotateSigningKey(desiredTTL time.Time) error {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// give a bit of slop
	now := time.Now().Add(-5 * time.Minute)

	nvb := now
	nva := desiredTTL.Add(1 * time.Hour)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &newKey.PublicKey,
		NotAfter:     nva,
		NotBefore:    nvb,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &newKey.PublicKey, newKey)
	if err != nil {
		return err
	}

	// re-parse the cert so that we can get the raw fields that we want for hashing
	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	newKeyID := hex.EncodeToString(spkiHash[:])

	s.keyLock.Lock()
	defer s.keyLock.Unlock()

	var newAll []*ttlBytes
	toSerial := make(map[string][]byte)
	for _, thing := range append(s.allKeys, &ttlBytes{Bytes: certBytes, TTL: nva, KeyID: newKeyID}) {
		if thing.TTL.After(now) {
			newAll = append(newAll, thing)
			toSerial[thing.KeyID] = thing.Bytes
		}
	}

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(toSerial)
	if err != nil {
		return err
	}

	s.curPrivateKey = newKey
	s.currentKeyID = newKeyID
	s.currentTTL = nva
	s.allKeys = newAll
	s.publicKeys = b.Bytes()

	return nil
}

func (s *cfFlyServer) keyHandler(w http.ResponseWriter, r *http.Request) {
	s.keyLock.RLock()
	v := s.publicKeys
	s.keyLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write(v)
}

type tbsToken struct {
	Claims     jwt.MapClaims
	PrivateKey *rsa.PrivateKey
}

func (tbs *tbsToken) Sign() (string, error) {
	log.Printf("Signed token for %s in team: %s\n", tbs.Claims["emailAddress"], tbs.Claims["displayTeamName"])

	return jwt.NewWithClaims(jwt.SigningMethodRS256, tbs.Claims).SignedString(tbs.PrivateKey)
}

func (s *cfFlyServer) mintToken(accessToken, intendedClientID, spaceID string) (*tbsToken, error) {
	// First make sure it was intended for us
	og, err := s.uaaClient.ValidateAccessToken(accessToken, intendedClientID)
	if err != nil {
		return nil, err
	}

	userID, _ := og["user_id"].(string)
	if userID == "" {
		return nil, errors.New("no user_id")
	}

	email, _ := og["email"].(string)
	if email == "" {
		return nil, errors.New("no email")
	}

	cli, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress: s.CFAPIURL,
		Token:      accessToken,
	})
	if err != nil {
		return nil, err
	}

	space, err := cli.GetSpaceByGuid(spaceID)
	if err != nil {
		return nil, err
	}

	roles, err := space.Roles()
	if err != nil {
		return nil, err
	}

	allowed := false
	for _, sr := range roles {
		if sr.Guid == userID {
			for _, r := range sr.SpaceRoles {
				if r == "space_developer" {
					allowed = true
					break
				}
			}
		}
	}
	if !allowed {
		return nil, errors.New("not allowed")
	}

	org, err := space.Org()
	if err != nil {
		return nil, err
	}

	ttl := time.Now().Add(4 * time.Hour)
	pkey, keyID, err := s.getCurrentKey(ttl)
	if err != nil {
		return nil, err
	}

	displayName := fmt.Sprintf("Org: %s / Space: %s", org.Name, space.Name)
	storeName := fmt.Sprintf("cf:%s", space.Guid)

	return &tbsToken{
		Claims: jwt.MapClaims{
			// Concourse normal claims
			"exp":      ttl.Unix(),
			"teamName": storeName,
			"isAdmin":  false,
			"csrf":     "",

			// Our own
			"kid":              keyID,               // to find which key to verify against
			"aud":              s.ConcourseClientID, // in case the same server matches multiple Concourses
			"createIfNotExist": true,                // create the team if it doesn't exist
			"emailAddress":     email,               // for audit logging
			"displayTeamName":  displayName,
		},
		PrivateKey: pkey,
	}, nil
}

func (s *cfFlyServer) signHandler(w http.ResponseWriter, r *http.Request) {
	t := r.Header.Get("Authorization")
	parts := strings.Split(t, " ")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	at := parts[1]
	spaceID := r.FormValue("space")
	if spaceID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := s.mintToken(at, s.UAAAPIClientID, spaceID)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	signed, err := token.Sign()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(signed))
}

type oauthSessionData struct {
	ConcourseCallback string
	ConcourseState    string
	ConcourseClientID string
	State             string
}

func (s *cfFlyServer) tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("client_id") != s.ConcourseClientID {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.FormValue("client_secret") != s.ConcourseClientSecret { // TODO, consider timing attacks, though this is a low value secret
		w.WriteHeader(http.StatusForbidden)
		return
	}

	code := r.FormValue("code")

	s.codeLock.Lock()
	tbs := s.codes[code]
	delete(s.codes, code) // one-shot deal
	s.codeLock.Unlock()

	// We didn't have this value earlier
	tbs.Claims["csrf"] = r.FormValue("csrf")

	signed, err := tbs.Sign()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(&oauth2.Token{
		AccessToken: signed,
		TokenType:   "EXTERNAL",
	})
}

func (s *cfFlyServer) callbackHandler(w http.ResponseWriter, r *http.Request) {
	osdRaw, _ := s.CookieStore.Get(r, "osd")
	osd, _ := osdRaw.Values["d"].(*oauthSessionData)

	if osd == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if osd.State == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if osd.State != r.FormValue("state") {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	grant, err := s.uaaClient.FetchAccessToken(s.UAAWebClientID, s.UAAWebClientSecret, url.Values{
		"response_type": {"token"},
		"code":          {r.FormValue("code")},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {s.OurURL + "/v1/callback"},
	})
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Parse team name (which is the CF space ID)
	csb, err := base64.RawURLEncoding.DecodeString(osd.ConcourseState)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var coas auth.OAuthState
	err = json.Unmarshal(csb, &coas)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !strings.HasPrefix(coas.TeamName, "cf:") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	tbs, err := s.mintToken(grant.AccessToken, s.UAAWebClientID, coas.TeamName[3:])
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	codeToReturn := base64.RawURLEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
	s.codeLock.Lock()
	s.codes[codeToReturn] = tbs
	s.codeLock.Unlock() // TODO, garbage collect this map

	// We can't sign yet, as we don't have the CSRF bit, so we'll abuse the authorization code dance and get it then.
	http.Redirect(w, r, osd.ConcourseCallback+"?"+(&url.Values{
		"code":  {codeToReturn},
		"state": {osd.ConcourseState},
	}).Encode(), http.StatusFound)
}

func (s *cfFlyServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	osd := &oauthSessionData{
		ConcourseCallback: r.FormValue("callback"),
		ConcourseState:    r.FormValue("state"),
		ConcourseClientID: r.FormValue("client_id"),
	}

	// First, verify the callback is allowed
	if osd.ConcourseCallback != s.ConcourseCallbackURL {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if osd.ConcourseClientID != s.ConcourseClientID {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	osd.State = base64.RawURLEncoding.EncodeToString(securecookie.GenerateRandomKey(32))

	// Ignore error on this call, as it just means we have an empty session, and that's OK
	// (since we are not persisting cookie keys, that'll happen a lot)
	osdRaw, _ := s.CookieStore.Get(r, "osd")
	osdRaw.Values["d"] = osd
	err := osdRaw.Save(r, w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.uaaClient.GetAuthorizeEndpoint()+"?"+(&url.Values{
		"client_id":     {s.UAAWebClientID},
		"response_type": {"code"},
		"state":         {osd.State},
		"redirect_uri":  {s.OurURL + "/v1/callback"},
	}).Encode(), http.StatusFound)
}

func (s *cfFlyServer) CreateHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/keys", s.keyHandler)
	r.HandleFunc("/v1/sign", s.signHandler)
	r.HandleFunc("/v1/login", s.loginHandler)
	r.HandleFunc("/v1/callback", s.callbackHandler)
	r.HandleFunc("/v1/token", s.tokenHandler)
	return r
}

// Create cookie handler, panic upon failure
func mustCreateBasicCookieHandler(insecure bool) *sessions.CookieStore {
	authKey := securecookie.GenerateRandomKey(64)
	if authKey == nil {
		panic("can't create key")
	}

	encryptionKey := securecookie.GenerateRandomKey(32)
	if encryptionKey == nil {
		panic("can't create key")
	}

	rv := sessions.NewCookieStore(authKey, encryptionKey)
	rv.Options.HttpOnly = true
	rv.Options.Secure = !insecure
	return rv
}

// Register classes that GOB needs to know about
func init() {
	gob.Register(&oauthSessionData{})
}

func main() {
	server := &cfFlyServer{
		OurURL:                os.Getenv("OUR_URL"),
		CFAPIURL:              os.Getenv("CF_API"),
		UAAAPIClientID:        "cf-concourse-integration",
		UAAWebClientID:        "cf-concourse-web-integration",
		UAAWebClientSecret:    os.Getenv("UAA_WEB_CLIENT_SECRET"),
		ConcourseCallbackURL:  os.Getenv("CONCOURSE_CALLBACK_URL"),
		ConcourseClientID:     os.Getenv("CONCOURSE_CLIENT_ID"),
		ConcourseClientSecret: os.Getenv("CONCOURSE_CLIENT_SECRET"),
		CookieStore:           mustCreateBasicCookieHandler(strings.HasPrefix(os.Getenv("OUR_URL"), "http://")),
	}
	err := server.Init()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Serving...")
	http.ListenAndServe(":"+os.Getenv("PORT"), server.CreateHandler())
}
