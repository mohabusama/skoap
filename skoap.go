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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/zalando/skipper/filters"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	authHeaderName      = "Authorization"
	authUserKey         = "auth-user"
	authRejectReasonKey = "auth-reject-reason"
)

type roleCheckType int

const (
	checkScope roleCheckType = iota
	checkTeam
)

type rejectReason string

const (
	missingBearerToken rejectReason = "missing-bearer-token"
	authServiceAccess  rejectReason = "auth-service-access"
	invalidToken       rejectReason = "invalid-token"
	invalidRealm       rejectReason = "invalid-realm"
	invalidScope       rejectReason = "invalid-scope"
	teamServiceAccess  rejectReason = "team-service-access"
	invalidTeam        rejectReason = "invalid-team"
)

const (
	AuthName      = "auth"
	AuthTeamName  = "authTeam"
	BasicAuthName = "basicAuth"
	AuditLogName  = "auditLog"
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

	auditLog struct {
		writer     io.Writer
		maxBodyLog int
	}

	teeBody struct {
		body      io.ReadCloser
		buffer    *bytes.Buffer
		teeReader io.Reader
		maxTee    int
	}

	authStatusDoc struct {
		User     string `json:"user,omitempty"`
		Rejected bool   `json:"rejected"`
		Reason   string `json:"reason,omitempty"`
	}

	auditDoc struct {
		Method      string         `json:"method"`
		Path        string         `json:"path"`
		Status      int            `json:"status"`
		AuthStatus  *authStatusDoc `json:"authStatus,omitempty"`
		RequestBody string         `json:"requestBody,omitempty"`
	}
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid authorization header")
	errInvalidToken               = errors.New("invalid token")
)

func getToken(r *http.Request) (string, error) {
	const b = "Bearer "
	h := r.Header.Get(authHeaderName)
	if !strings.HasPrefix(h, b) {
		return "", errInvalidAuthorizationHeader
	}

	return h[len(b):], nil
}

func unauthorized(ctx filters.FilterContext, uname string, reason rejectReason) {
	ctx.StateBag()[authUserKey] = uname
	ctx.StateBag()[authRejectReasonKey] = string(reason)
	ctx.Serve(&http.Response{StatusCode: http.StatusUnauthorized})
}

func authorized(ctx filters.FilterContext, uname string) {
	ctx.StateBag()["auth-user"] = uname
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
		return errInvalidToken
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
		unauthorized(ctx, "", missingBearerToken)
		return
	}

	a, err := f.authClient.validate(token)
	if err != nil {
		reason := authServiceAccess
		if err == errInvalidToken {
			reason = invalidToken
		} else {
			log.Println(err)
		}

		unauthorized(ctx, "", reason)
		return
	}

	if !f.validateRealm(a) {
		unauthorized(ctx, a.Uid, invalidRealm)
		return
	}

	if f.typ == checkScope {
		if !f.validateScope(a) {
			unauthorized(ctx, a.Uid, invalidScope)
			return
		}

		authorized(ctx, a.Uid)
		return
	}

	if valid, err := f.validateTeam(token, a); err != nil {
		unauthorized(ctx, a.Uid, teamServiceAccess)
		log.Println(err)
	} else if !valid {
		unauthorized(ctx, a.Uid, invalidTeam)
	} else {
		authorized(ctx, a.Uid)
	}
}

// filters.Filter implementation
func (f *filter) Response(_ filters.FilterContext) {}

func NewBasicAuth() filters.Spec { return basic(BasicAuthName) }

// filters.Spec implementation
func (b basic) Name() string { return BasicAuthName }

// filters.Spec implementation
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

// filters.Filter implementation
func (b basic) Request(ctx filters.FilterContext) {
	ctx.Request().Header.Set(authHeaderName, string(b))
}

// filters.Filter implementation
func (b basic) Response(_ filters.FilterContext) {}

func newTeeBody(rc io.ReadCloser, maxTee int) io.ReadCloser {
	b := bytes.NewBuffer(nil)
	tb := &teeBody{
		body:   rc,
		buffer: b,
		maxTee: maxTee}
	tb.teeReader = io.TeeReader(rc, tb)
	return tb
}

func (tb *teeBody) Read(b []byte) (int, error) { return tb.teeReader.Read(b) }
func (tb *teeBody) Close() error               { return tb.body.Close() }

func (tb *teeBody) Write(b []byte) (int, error) {
	if tb.maxTee < 0 {
		return tb.buffer.Write(b)
	}

	wl := len(b)
	if wl >= tb.maxTee {
		wl = tb.maxTee
	}

	n, err := tb.buffer.Write(b[:wl])
	if err != nil {
		return n, err
	}

	tb.maxTee -= n

	// lie to avoid short write
	return len(b), nil
}

func NewAuditLog(w io.Writer) filters.Spec {
	return &auditLog{writer: w}
}

func (al *auditLog) Name() string { return AuditLogName }

func (al *auditLog) CreateFilter(args []interface{}) (filters.Filter, error) {
	if len(args) == 0 {
		return al, nil
	}

	if mbl, ok := args[0].(float64); ok {
		return &auditLog{writer: al.writer, maxBodyLog: int(mbl)}, nil
	} else {
		return nil, filters.ErrInvalidFilterParameters
	}
}

func (al *auditLog) Request(ctx filters.FilterContext) {
	if al.maxBodyLog != 0 {
		ctx.Request().Body = newTeeBody(ctx.Request().Body, al.maxBodyLog)
	}
}

func (al *auditLog) Response(ctx filters.FilterContext) {
	req := ctx.Request()

	oreq := ctx.OriginalRequest()
	rsp := ctx.Response()
	doc := auditDoc{
		Method: oreq.Method,
		Path:   oreq.URL.Path,
		Status: rsp.StatusCode}

	sb := ctx.StateBag()
	au, _ := sb[authUserKey].(string)
	rr, _ := sb[authRejectReasonKey].(string)
	if au != "" || rr != "" {
		doc.AuthStatus = &authStatusDoc{User: au}
		if rr != "" {
			doc.AuthStatus.Rejected = true
			doc.AuthStatus.Reason = rr
		}
	}

	if tb, ok := req.Body.(*teeBody); ok {
		if tb.maxTee < 0 {
			io.Copy(tb.buffer, tb.body)
		} else {
			io.CopyN(tb.buffer, tb.body, int64(tb.maxTee))
		}

		if tb.buffer.Len() > 0 {
			doc.RequestBody = tb.buffer.String()
		}
	}

	enc := json.NewEncoder(al.writer)
	err := enc.Encode(&doc)
	if err != nil {
		log.Println(err)
	}
}
