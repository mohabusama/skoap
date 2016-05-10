/*
Package skoap implements an authentication filters for Skipper.

This package provides a Skipper extension, for details of using
it, please see the Skipper documentation:

https://godoc.org/github.com/zalando/skipper

The package contains two filters: auth and authTeam.

The auth filter takes the Authorization header from the request,
assuming that it is an OAuth2 Bearer token, and validates it
against the configured token validation service.

If the OAuth2 realm is set for the filter, then it checks if the
user of the token belongs to that realm.

If OAuth2 scopes are set for the filter, then it checks if the
user of the token has at least one of the configured scopes assigned.

The authTeam filter works exactly the same as the auth filter, but
instead of scopes, it checks if the user is a member of a team. To
get the teams of the user, the filter makes an additional request,
with the available authorization token, to a configured team API
endpoint.

To check only the scopes or the teams, the first argument of the
filter needs to be set to empty, "".

Examples:

Check only if the request has a valid authentication token:

	* -> auth() -> "https://www.example.org"

Check if the request has a valid authentication token and the user
of the token belongs to a realm:

	* -> auth("/employees") -> "https://www.example.org"

Check if the request has a valid authentication token, the user of
the token belongs to a realm and has one of the specified scopes
assigned:

	* -> auth("/employees", "read-zmon", "read-stups") -> "https://www.example.org"

Check if the request has a valid authentication token, the user of
the token belongs to a realm and belongs to one of the specified teams:

	* -> authTeam("/employees", "b-team") -> "https://www.example.org"

Check if the request has a valid authentication token, and the user
has one of the specified scopes assigned regardless of the realm they
belong to:

	* -> auth("", "read-zmon") -> "https://www.example.org"
*/
package skoap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/zalando/skipper/filters"
	"log"
	"net/http"
	"strings"
)

const authHeaderName = "Authorization"

type roleCheckType int

const (
	checkScope roleCheckType = iota
	checkTeam
)

const (
	AuthName      = "auth"
	AuthTeamName  = "authTeam"
	BasicAuthName = "basicAuth"
)

type (
	authClient struct{ urlBase string }
	teamClient struct{ urlBase string }

	authDoc struct {
		Uid    string   `json:"uid"`
		Realm  string   `json:"realm"`
		Scopes []string `json:"scope"` // TODO: verify this with service2service authentication
	}

	teamDoc struct {
		Id string `json:"id"`
	}

	spec struct {
		typ        roleCheckType
		authClient *authClient
		teamClient *teamClient
	}

	filter struct {
		typ        roleCheckType
		authClient *authClient
		teamClient *teamClient
		realm      string
		args       []string
	}

	basic string
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid authorization header")
	errRequestFailed              = errors.New("request failed")
)

var BasicAuth filters.Spec = basic("")

func getToken(r *http.Request) (string, error) {
	const b = "Bearer "
	h := r.Header.Get(authHeaderName)
	if !strings.HasPrefix(h, b) {
		return "", errInvalidAuthorizationHeader
	}

	return h[len(b):], nil
}

func unauthorized(ctx filters.FilterContext) {
	log.Println("rejected by skipper")
	ctx.Serve(&http.Response{StatusCode: http.StatusUnauthorized})
}

func getStrings(args []interface{}) ([]string, error) {
	s := make([]string, len(args))
	var ok bool
	for i, a := range args {
		s[i], ok = a.(string)
		if !ok {
			return nil, filters.ErrInvalidFilterParameters
		}
	}

	return s, nil
}

func intersect(left, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}

	return false
}

func jsonGet(url, auth string, doc interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	if auth != "" {
		req.Header.Set(authHeaderName, "Bearer "+auth)
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return errRequestFailed
	}

	d := json.NewDecoder(rsp.Body)
	return d.Decode(doc)
}

func (ac *authClient) validate(token string) (*authDoc, error) {
	var a authDoc
	err := jsonGet(ac.urlBase, token, &a)
	return &a, err
}

func (tc *teamClient) getTeams(uid, token string) ([]string, error) {
	var t []teamDoc
	err := jsonGet(tc.urlBase+uid, token, &t)
	if err != nil {
		return nil, err
	}

	ts := make([]string, len(t))
	for i, ti := range t {
		ts[i] = ti.Id
	}

	return ts, nil
}

func newSpec(typ roleCheckType, authUrlBase, teamUrlBase string) filters.Spec {
	s := &spec{typ: typ, authClient: &authClient{authUrlBase}}
	if typ == checkTeam {
		s.teamClient = &teamClient{teamUrlBase}
	}

	return s
}

// Creates a new auth filter specification to validate authorization
// tokens, optionally check realms and optionally check scopes.
//
// - authUrlBase: the url of the token validation service.
// The filter expects the service to validate the token found in the
// Authorization header and in case of a valid token, it expects it
// to return the user id and the realm of the user associated with
// the token ('uid' and 'realm' fields in the returned json document).
// The token is set as the Authorization Bearer header.
//
func New(authUrlBase string) filters.Spec {
	return newSpec(checkScope, authUrlBase, "")
}

// Creates a new auth filter specification to validate authorization
// tokens, optionally check realms and optionally check teams.
//
// - authUrlBase: the url of the token validation service. The filter
// expects the service to validate the token found in the Authorization
// header and in case of a valid token, it expects it to return the
// user id and the realm of the user associated with the token ('uid'
// and 'realm' fields in the returned json document). The token is set
// as the Authorization Bearer header.
//
// - teamUrlBase: this service is queried for the team ids, that the
// user is a member of ('id' field of the returned json document's
// items). The user id of the user is appended at the end of the url.
//
func NewTeamCheck(authUrlBase, teamUrlBase string) filters.Spec {
	return newSpec(checkTeam, authUrlBase, teamUrlBase)
}

// filters.Spec implementation
func (s *spec) Name() string {
	if s.typ == checkScope {
		return AuthName
	} else {
		return AuthTeamName
	}
}

// filters.Spec implementation
func (s *spec) CreateFilter(args []interface{}) (filters.Filter, error) {
	sargs, err := getStrings(args)
	if err != nil {
		return nil, err
	}

	f := &filter{typ: s.typ, authClient: s.authClient, teamClient: s.teamClient}
	if len(sargs) > 0 {
		f.realm, f.args = sargs[0], sargs[1:]
	}

	return f, nil

}

func (f *filter) validateRealm(a *authDoc) bool {
	if f.realm == "" {
		return true
	}

	return a.Realm == f.realm
}

func (f *filter) validateScope(a *authDoc) bool {
	if len(f.args) == 0 {
		return true
	}

	return intersect(f.args, a.Scopes)
}

func (f *filter) validateTeam(token string, a *authDoc) (bool, error) {
	if len(f.args) == 0 {
		return true, nil
	}

	teams, err := f.teamClient.getTeams(a.Uid, token)
	return intersect(f.args, teams), err
}

// filters.Filter implementation
func (f *filter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	token, err := getToken(r)
	if err != nil {
		unauthorized(ctx)
		return
	}

	a, err := f.authClient.validate(token)
	if err != nil {
		unauthorized(ctx)
		log.Println(err)
		return
	}

	if !f.validateRealm(a) {
		unauthorized(ctx)
		return
	}

	if f.typ == checkScope {
		if !f.validateScope(a) {
			unauthorized(ctx)
		}

		return
	}

	valid, err := f.validateTeam(token, a)
	if err != nil {
		unauthorized(ctx)
		log.Println(err)
		return
	}

	if !valid {
		unauthorized(ctx)
	}
}

// filters.Filter implementation
func (f *filter) Response(_ filters.FilterContext) {}

func (b basic) Name() string { return BasicAuthName }

func (b basic) CreateFilter(args []interface{}) (filters.Filter, error) {
	var (
		uname, pwd string
		ok         bool
	)

	if len(args) > 0 {
		if uname, ok = args[0].(string); !ok {
			return nil, filters.ErrInvalidFilterParameters
		}
	}

	if len(args) > 1 {
		if pwd, ok = args[1].(string); !ok {
			return nil, filters.ErrInvalidFilterParameters
		}
	}

	v := base64.StdEncoding.EncodeToString([]byte(uname + ":" + pwd))
	return basic("Basic " + v), nil
}

func (b basic) Request(ctx filters.FilterContext) {
	ctx.Request().Header.Set(authHeaderName, string(b))
}

func (b basic) Response(_ filters.FilterContext) {}
