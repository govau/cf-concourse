package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cfclient "github.com/cloudfoundry-community/go-cfclient"
	"github.com/concourse/atc"
	"github.com/concourse/atc/auth/uaa"
	"github.com/concourse/go-concourse/concourse"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	cfcommon "github.com/govau/cf-common"
)

type cfFlyServer struct {
	// CFAPIURL is the URL for the underlying CloudFoundry instance, e.g. https://api.system.example.com
	CFAPIURL string

	// OurURL is the URL by which we are accessed by users, e.g. https://cf-concourse.example.com
	OurURL string

	// UAAAPIClientID is the client ID configured in UAA for the API flow when interacting with us. It should have a client secret of "notasecret".
	UAAAPIClientID string // as configured in UAA

	// UAAConcourseClientID set for team auth in Concourse
	UAAConcourseClientID string

	// UAAConcourseClientSecret set for team auth in Concourse
	UAAConcourseClientSecret string

	// ConcourseURL is the URL for our Concourse instance
	ConcourseURL string

	// ConcourseSigningKey is the PEM key material for the key that is used to sign Concourse tokens. This same key should be passed to "atc" and "tsa" at startup using the --session-signing-key /path/to/key option
	ConcourseSigningKey string

	// AutoCreateTeams, if set, always check the team exists and if not create before minting token
	AutoCreateTeams bool

	// Internal
	uaaClient *cfcommon.UAAClient

	// current key
	curPrivateKey *rsa.PrivateKey
}

// Init must be called at server start
func (s *cfFlyServer) Init() error {
	var err error
	s.uaaClient, err = cfcommon.NewUAAClientFromAPIURL(s.CFAPIURL)
	if err != nil {
		return err
	}

	s.curPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(s.ConcourseSigningKey))
	if err != nil {
		return err
	}

	return nil
}

func (s *cfFlyServer) mintToken(accessToken, spaceID string) ([]byte, error) {
	// First make sure it was intended for us
	og, err := s.uaaClient.ValidateAccessToken(accessToken, s.UAAAPIClientID)
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

	storeName := fmt.Sprintf("cf:%s", space.Guid)

	// Make sure team exists
	if s.AutoCreateTeams {
		teams, err := concourse.NewClient(s.ConcourseURL, http.DefaultClient, true).ListTeams()
		if err != nil {
			log.Println("Error in listing")
			return nil, err
		}
		found := false
		for _, t := range teams {
			if t.Name == storeName {
				found = true
				break
			}
		}
		if !found {
			// Create it
			confBytes, err := json.Marshal(&uaa.UAAAuthConfig{
				AuthURL:      s.uaaClient.GetAuthorizeEndpoint(),
				TokenURL:     s.uaaClient.GetTokenEndpoint(),
				CFSpaces:     []string{space.Guid},
				CFURL:        s.CFAPIURL,
				ClientID:     s.UAAConcourseClientID,
				ClientSecret: s.UAAConcourseClientSecret,
			})
			if err != nil {
				return nil, err
			}

			jrm := json.RawMessage(confBytes)
			_, _, _, err = concourse.NewClient(s.ConcourseURL, &http.Client{
				Transport: &selfAssertingTransport{
					SigningKey:   s.curPrivateKey,
					EmailAddress: email,
				},
			}, true).Team(storeName).CreateOrUpdate(atc.Team{
				Name: storeName,
				Auth: map[string]*json.RawMessage{
					uaa.ProviderName: &jrm,
				},
			})
			if err != nil {
				return nil, err
			}
		}
	}

	ts, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		// Concourse normal claims
		"exp":      ttl.Unix(),
		"teamName": storeName,
		"isAdmin":  false,
		"csrf":     "",

		// Add email address, in the hope Concourse might use this in the future for audit logging
		"emailAddress": email,
	}).SignedString(s.curPrivateKey)

	if err != nil {
		return nil, err
	}

	log.Printf("Issued token for: %s in Org: %s / Space: %s\n", email, org.Name, space.Name)

	return []byte(ts), nil
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

	token, err := s.mintToken(at, spaceID)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(token)
}

func (s *cfFlyServer) CreateHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/sign", s.signHandler)
	return r
}

type selfAssertingTransport struct {
	SigningKey   *rsa.PrivateKey
	EmailAddress string
}

func (t *selfAssertingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		// Concourse normal claims
		"exp":      time.Now().Add(time.Hour).Unix(),
		"teamName": "main",
		"isAdmin":  true,
		"csrf":     "",

		// Add email address, in the hope Concourse might use this in the future for audit logging
		"emailAddress": t.EmailAddress,
	}).SignedString(t.SigningKey)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tok))
	return http.DefaultTransport.RoundTrip(r)
}

func main() {
	server := &cfFlyServer{
		OurURL:                   os.Getenv("OUR_URL"),
		CFAPIURL:                 os.Getenv("CF_API"),
		UAAAPIClientID:           os.Getenv("CF_UAA_API_CLIENT_ID"),
		UAAConcourseClientID:     os.Getenv("CF_UAA_CONCOURSE_CLIENT_ID"),
		UAAConcourseClientSecret: os.Getenv("CF_UAA_CONCOURSE_CLIENT_SECRET"),
		ConcourseURL:             os.Getenv("CONCOURSE_URL"),
		ConcourseSigningKey:      os.Getenv("CONCOURSE_SIGNING_KEY"),
		AutoCreateTeams:          true,
	}
	err := server.Init()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Serving...")
	http.ListenAndServe(fmt.Sprintf(":%s", os.Getenv("PORT")), server.CreateHandler())
}
