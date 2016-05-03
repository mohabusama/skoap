package skoap

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
	testScope    = "test-scope"
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
		typ         roleCheckType
		authBaseUrl string
		teamBaseUrl string
		args        []interface{}
		hasAuth     bool
		auth        string
		statusCode  int
	}{{
		msg:        "uninitialized filter, no authorization header, scope check",
		typ:        checkScope,
		statusCode: http.StatusUnauthorized,
	}, {
		msg:        "uninitialized filter, no authorization header, team check",
		typ:        checkTeam,
		statusCode: http.StatusUnauthorized,
	}, {
		msg:         "no authorization header, scope check",
		typ:         checkScope,
		authBaseUrl: testAuthPath,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "invalid token, scope check",
		typ:         checkScope,
		authBaseUrl: testAuthPath + "?access_token=",
		hasAuth:     true,
		auth:        "invalid-token",
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, auth only, scope check",
		typ:         checkScope,
		authBaseUrl: testAuthPath + "?access_token=",
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}, {
		msg:         "invalid realm, scope check",
		typ:         checkScope,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{"/not-matching-realm"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "invalid scope",
		typ:         checkScope,
		authBaseUrl: testAuthPath + "?access_token=",
		args:        []interface{}{testRealm, "not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, valid scope",
		typ:         checkScope,
		authBaseUrl: testAuthPath + "?access_token=",
		args:        []interface{}{testRealm, testScope, "other-scope"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}, {
		msg:         "no authorization header, team check",
		typ:         checkTeam,
		authBaseUrl: testAuthPath,
		teamBaseUrl: testTeamPath,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "invalid token, team check",
		typ:         checkTeam,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		hasAuth:     true,
		auth:        "invalid-token",
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, auth only, team check",
		typ:         checkTeam,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}, {
		msg:         "invalid realm, team check",
		typ:         checkTeam,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{"/not-matching-realm"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, valid realm, no team check",
		typ:         checkTeam,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{testRealm},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}, {
		msg:         "valid token, valid realm, no matching team",
		typ:         checkTeam,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{testRealm, "invalid-team-0", "invalid-team-1"},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusUnauthorized,
	}, {
		msg:         "valid token, valid realm, matching team, team",
		typ:         checkTeam,
		authBaseUrl: testAuthPath + "?access_token=",
		teamBaseUrl: testTeamPath + "?member=",
		args:        []interface{}{testRealm, "invalid-team-0", testTeam},
		hasAuth:     true,
		auth:        testToken,
		statusCode:  http.StatusOK,
	}} {
		backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if r.Header[authHeaderName] != nil {
				t.Error(ti.msg, "authorization header was not removed")
			}
		}))

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != testAuthPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			token, err := getToken(r)
			if err != nil || token != testToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			d := testAuthDoc{authDoc{testUid, testRealm, []string{testScope}}, "noise"}
			e := json.NewEncoder(w)
			err = e.Encode(&d)
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

		var s filters.Spec
		if ti.typ == checkScope {
			s = New(authServer.URL + ti.authBaseUrl)
		} else {
			s = NewTeamCheck(authServer.URL+ti.authBaseUrl, teamServer.URL+ti.teamBaseUrl)
		}
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
