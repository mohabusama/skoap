package hackauth

import (
	"encoding/json"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/proxy/proxytest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testToken    = "test-token"
	testUid      = "jdoe"
	testRealm    = "/immortals"
	testTeam     = "test-team"
	testAuthPath = "/test-auth"
	testTeamPath = "/test-team"
)

type (
	testAuthDoc struct {
		authDoc
		SomeOtherStuff string
	}

	testTeamDoc struct {
		teamDoc
		SomeOtherStuff string
	}
)

func lastQueryValue(url string) string {
	s := strings.Split(url, "=")
	if len(s) == 0 {
		return ""
	}

	return s[len(s)-1]
}

func Test(t *testing.T) {
	for _, ti := range []struct {
		msg         string
		authBaseUrl string
		teamBaseUrl string
		args        []interface{}
		hasAuth     bool
		auth        string
		statusCode  int
	}{{
		msg:        "uninitialized filter, no authorization header",
		statusCode: http.StatusUnauthorized,
	}, {
		msg:         "no authorization header",
		authBaseUrl: testAuthPath,
		teamBaseUrl: testTeamPath,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "invalid token",
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		hasAuth:     true,
		auth:        "invalid-token",
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, auth only",
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}, {
		msg:         "invalid realm",
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{"/not-matching-realm"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, valid realm, no team check",
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{testRealm},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}, {
		msg:         "valid token, valid realm, no matching team",
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{testRealm, "invalid-team-0", "invalid-team-1"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, valid realm, matching team",
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{testRealm, "invalid-team-0", testTeam},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}} {
		backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != testAuthPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			if lastQueryValue(r.URL.String()) != testToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			d := testAuthDoc{authDoc{testUid, testRealm}, "noise"}
			e := json.NewEncoder(w)
			err := e.Encode(&d)
			if err != nil {
				t.Error(ti.msg, err)
			}
		}))

		teamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != testTeamPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			if token, err := getToken(r); err != nil || token != testToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if lastQueryValue(r.URL.String()) != testUid {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			d := []testTeamDoc{{teamDoc{testTeam}, "noise"}, {teamDoc{"other-team"}, "more noise"}}
			e := json.NewEncoder(w)
			err := e.Encode(&d)
			if err != nil {
				t.Error(ti.msg, err)
			}
		}))

		s := New(authServer.URL+ti.authBaseUrl, teamServer.URL+ti.teamBaseUrl)
		fr := make(filters.Registry)
		fr.Register(s)
		r := &eskip.Route{Filters: []*eskip.Filter{{Name: s.Name(), Args: ti.args}}, Backend: backend.URL}
		proxy := proxytest.New(fr, r)

		req, err := http.NewRequest("GET", proxy.URL, nil)
		if err != nil {
			t.Error(ti.msg, err)
			continue
		}

		if ti.hasAuth {
			req.Header.Set(authHeaderName, "Bearer "+url.QueryEscape(ti.auth))
		}

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(ti.msg, err)
		}

		defer rsp.Body.Close()

		if rsp.StatusCode != ti.statusCode {
			t.Error(ti.msg, "auth filter failed", rsp.StatusCode, ti.statusCode)
		}
	}
}
