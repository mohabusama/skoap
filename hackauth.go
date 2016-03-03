/*
Package hackauth implements an authentication filter for Zalando
installations of Skipper.

The filter takes the Authorization header from the request, and
validates it against the configured token validation endpoint.

Since the available authentication solution doesn't support checking
for available roles of the users, this filter can only check whether a
the user is:

- authenticated at all

- member of a realm

- member of a team

For checking whether the user is a member of a team, the filter uses a
separate service endpoint: the 'team service'.

The hackauth filter accepts arbitrary number of string arguments, where
the first argument is the expected 'realm', and the rest of the
arguments is a list of team ids. If no arguments are provided, the
filter only checks if the auth token is valid. If the realm is provided,
the filter also checks if the user is a member of that realm. If teams
are provided, the filter checks in addition, if the user is a member of
at least one of the listed teams.
*/
package hackauth

import (
    "github.com/zalando/skipper/filters"
    "net/http"
    "strings"
    "errors"
    "encoding/json"
)

const authHeaderName = "Authorization"

type (
    authClient struct {urlBase string}
    teamClient struct {urlBase string}

    authDoc struct {
        Uid string `json:"uid"`
        Realm string `json:"realm"`
    }

    teamDoc struct {Id string `json:"id"`}

    spec struct {
        authClient *authClient
        teamClient *teamClient
    }

    filter struct {
        authClient *authClient
        teamClient *teamClient
        realm string
        teams []string}
)

var errMissingAuthHeader = errors.New("missing authorization header")

func getToken(r *http.Request) (string, error) {
    h := r.Header.Get(authHeaderName)
    h = strings.Trim(h, " ")
    if h == "" {
        return "", errMissingAuthHeader
    }

    hs := strings.Split(h, " ")
    return hs[len(hs) - 1], nil
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
        req.Header.Set(authHeaderName, "Bearer " + auth)
    }

    rsp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }

    defer rsp.Body.Close()
    d := json.NewDecoder(rsp.Body)
    return d.Decode(doc)
}

func (ac *authClient) validate(token string) (string, string, error) {
    var a authDoc
    err := jsonGet(ac.urlBase + token, "", &a)
    return a.Uid, a.Realm, err
}

func (tc *teamClient) getTeams(uid, token string) ([]string, error) {
    var t []teamDoc
    err := jsonGet(tc.urlBase + uid, token, &t)
    if err != nil {
        return nil, err
    }

    ts := make([]string, len(t))
    for i, ti := range t {
        ts[i] = ti.Id
    }

    return ts, nil
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
//                document. The token is appended at the end
//                of the url.
//
// - teamUrlBase: when team restriction is specified for a
//                filter instance, this service is queried
//                for the team ids, that the user is member
//                of ('id' field of the returned json
//                document). The user id of the user is
//                appended at the end of the url.
//
func New(authUrlBase, teamUrlBase string) filters.Spec {
    ac := &authClient{authUrlBase}
    tc := &teamClient{teamUrlBase}
    return &spec{ac, tc}
}

func (s *spec) Name() string { return "hackauth" }

func (s *spec) CreateFilter(args []interface{}) (filters.Filter, error) {
    var (
        realm string
        teams []string
    )

    if len(args) > 0 {
        var ok bool
        realm, ok = args[0].(string)
        if !ok {
            return nil, filters.ErrInvalidFilterParameters
        }

        for _, t := range args[1:] {
            if ts, ok := t.(string); ok {
                teams = append(teams, ts)
            } else {
                return nil, filters.ErrInvalidFilterParameters
            }
        }
    }

    return &filter{
        authClient: s.authClient,
        teamClient: s.teamClient,
        realm: realm,
        teams: teams}, nil

}

func (f *filter) Request(ctx filters.FilterContext) {
    println("getting token")
    token, err := getToken(ctx.Request())
    if err != nil {
        unauthorized(ctx)
        return
    }

    println("calling validate")
    uid, realm, err := f.authClient.validate(token)
    if err != nil {
        unauthorized(ctx)
        return
    }

    if f.realm == "" {
        return
    }

    if realm != f.realm {
        unauthorized(ctx)
        return
    }

    if len(f.teams) == 0 {
        return
    }

    teams, err := f.teamClient.getTeams(uid, token)
    if err != nil {
        unauthorized(ctx)
        return
    }

    for _, t := range teams {
        for _, et := range f.teams {
            if t == et {
                return
            }
        }
    }

    unauthorized(ctx)
}

func (f *filter) Response(_ filters.FilterContext) {}
