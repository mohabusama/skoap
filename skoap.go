/*
Package hackauth implements an authentication filter for Zalando
installations of Skipper.

The filter takes the Authorization header from the request, and
validates it against the configured token validation endpoint.

Since the available authentication solution doesn't support checking
for security roles of the users, this filter can only check whether
the user is:

- authenticated at all

- member of a realm

- member of a team

For checking whether the user is a member of a team, the filter uses a
separate service endpoint: the 'team service'.

The hackauth filter accepts an arbitrary number of string arguments,
where the first argument is the expected 'realm', and the rest of the
arguments is a list of team ids. If no arguments are provided, the
filter only checks if the auth token is valid. If the realm is provided,
the filter also checks if the user is a member of that realm. If teams
are provided, the filter checks in addition, if the user is a member of
at least one of the listed teams.
*/
package skoap

import (
	"encoding/json"
	"errors"
	"github.com/zalando/skipper/filters"
	"net/http"
	"net/url"
	"strings"
)

const authHeaderName = "Authorization"

type roleCheckType int

const (
	checkScope roleCheckType = iota
	checkTeam
)

const (
	AuthName     = "auth"
	AuthTeamName = "authTeam"
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
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid authorization header")
	errRequestFailed              = errors.New("request failed")
)

func getToken(r *http.Request) (string, error) {
	h := r.Header.Get(authHeaderName)
	if !strings.HasPrefix(h, "Bearer ") {
		return "", errInvalidAuthorizationHeader
	}

	return h[7:], nil
}

func unauthorized(ctx filters.FilterContext) {
	ctx.Serve(&http.Response{StatusCode: http.StatusUnauthorized})
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
	err := jsonGet(ac.urlBase+url.QueryEscape(token), "", &a)
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

// Creates a new hackauth specification. It accepts two
// arguments:
//
// - authUrlBase: the url of the token validation service.
//                The filter expects the service to validate
//                the token found in the Authorization header
//                and in case of a valid token, it expects it
//                to return the user id and the realm of the
//                user associated with the token ('uid' and
//                'realm' fields in the returned json
//                document). The token is appended at the end
//                of the url.
//
// - teamUrlBase: when team restriction is specified for a
//                filter instance, this service is queried
//                for the team ids, that the user is a member
//                of ('id' field of the returned json
//                document's items). The user id of the user
//                is appended at the end of the url.
//
func New(authUrlBase string) filters.Spec {
	return newSpec(checkScope, authUrlBase, "")
}

func NewTeamCheck(authUrlBase, teamUrlBase string) filters.Spec {
	return newSpec(checkTeam, authUrlBase, teamUrlBase)
}

func (s *spec) Name() string {
	if s.typ == checkScope {
		return AuthName
	} else {
		return AuthTeamName
	}
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

func (f *filter) validateScope(ctx filters.FilterContext, a *authDoc) {
	if len(f.args) == 0 {
		return
	}

	if !intersect(f.args, a.Scopes) {
		unauthorized(ctx)
	}
}

func (f *filter) validateTeam(ctx filters.FilterContext, token string, a *authDoc) {
	if len(f.args) == 0 {
		return
	}

	teams, err := f.teamClient.getTeams(a.Uid, token)
	if err != nil {
		unauthorized(ctx)
		return
	}

	if !intersect(f.args, teams) {
		unauthorized(ctx)
	}
}

func (f *filter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	token, err := getToken(r)
	if err != nil {
		unauthorized(ctx)
		return
	}

	r.Header.Del(authHeaderName)

	a, err := f.authClient.validate(token)
	if err != nil {
		unauthorized(ctx)
		return
	}

	if f.realm == "" {
		return
	}

	if a.Realm != f.realm {
		unauthorized(ctx)
		return
	}

	if f.typ == checkScope {
		f.validateScope(ctx, a)
	} else {
		f.validateTeam(ctx, token, a)
	}
}

func (f *filter) Response(_ filters.FilterContext) {}
