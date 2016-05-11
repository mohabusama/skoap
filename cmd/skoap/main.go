/*
This command provides an executable http Skipper proxy with the skoap filters.

For the list of command line options, run:

	skoap -help
*/
package main

import (
	"flag"
	"fmt"
	"github.bus.zalan.do/aryszka/skoap"
	"github.com/zalando/skipper"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/builtin"
	"github.com/zalando/skipper/proxy"
	"github.com/zalando/skipper/routing"
	"log"
	"os"
	"strings"
)

const (
	addressFlag        = "address"
	targetAddressFlag  = "target-address"
	preserveHeaderFlag = "preserve-header"
	realmFlag          = "realm"
	scopesFlag         = "scopes"
	teamsFlag          = "teams"
	routesFileFlag     = "routes-file"
	insecureFlag       = "insecure"

	authUrlBaseFlag    = "auth-url"
	defaultAuthUrlBase = "http://[::1]:9081?access_token="

	teamUrlBaseFlag    = "team-url"
	defaultTeamUrlBase = "http://[::1]:9082"
)

const (
	usageHeader = `
skoap - Skipper based reverse proxy with authentication.

Use the skoap proxy to verify authorization tokens before forwarding requests, and optionally check OAuth2 realms
and scoap or team membership. In addition to check incoming requests, optionally set basic authorzation headers
for outgoing requests.

The command supports two modes:
- single route mode: when a target address is specified, only a single route is used and the authorization
  parameters (realm and scopes or teams) are specified as command line flags.
- routes configuration: supports any number of routes with custom predicate and filter settings. The
  authorization parameters are set in the routes file with the auth and authTeam filters.

When used with eskip configuration files, it is possible to apply detailed augmentation of the requests and
responses using Skipper rules.

https://github.com/zalando/skipper

`

	addressUsage = `network address that skoap should listen on`

	targetAddressUsage = `when authenticating to a single network endpoint, set its address (without path) as
the -target-address`

	preserveHeaderUsage = `when forwarding requests, preserve the Authorization header in the outgoing request`

	useTeamCheckUsage = `when this flag set, skoap checks teams instead of oauth2 scopes for authorization`

	realmUsage = `when target address is used to specify the target endpoint, and the requests need to be
authenticated against an OAuth2 realm, set the value of the realm with this flag. Note, that in case of a routes
file is used, the realm can be set for each auth filter reference individually`

	scopesUsage = `a comma separated list of the OAuth2 scopes to be checked in addition to the token validation
and the realm check`

	teamsUsage = `a comma separated list of the teams to be checked in addition to the token validation and the
realm check`

	routesFileUsage = `alternatively to the target address, it is possible to use a full eskip route
configuration, and specify the auth() and authTeam() filters for the routes individually. See also:
https://godoc.org/github.com/zalando/skipper/eskip`

	insecureUsage = `when this flag set, skipper will skip TLS verification`

	authUrlBaseUsage = `URL base of the authentication service. The authentication token found
in the incoming requests will be validated agains this service. It will be passed as the Authorization Bearer
header`

	teamUrlBaseUsage = `URL base of the team service. The user id received from the authentication service will
be appended to this url, and the list of teams that the user is a member of will be requested`
)

type singleRouteClient eskip.Route

var fs *flag.FlagSet

var (
	address        string
	targetAddress  string
	preserveHeader bool
	realm          string
	scopes         string
	teams          string
	routesFile     string
	insecure       bool
	authUrlBase    string
	teamUrlBase    string
)

func (src *singleRouteClient) LoadAll() ([]*eskip.Route, error) {
	return []*eskip.Route{(*eskip.Route)(src)}, nil
}

func (src *singleRouteClient) LoadUpdate() ([]*eskip.Route, []string, error) {
	return nil, nil, nil
}

func usage() {
	fmt.Fprint(os.Stderr, usageHeader)
	fs.PrintDefaults()
}

func init() {
	fs = flag.NewFlagSet("flags", flag.ContinueOnError)
	fs.Usage = usage

	fs.StringVar(&address, addressFlag, "", addressUsage)
	fs.StringVar(&targetAddress, targetAddressFlag, "", targetAddressUsage)
	fs.BoolVar(&preserveHeader, preserveHeaderFlag, false, preserveHeaderUsage)
	fs.StringVar(&realm, realmFlag, "", realmUsage)
	fs.StringVar(&scopes, scopesFlag, "", scopesUsage)
	fs.StringVar(&teams, teamsFlag, "", teamsUsage)
	fs.StringVar(&routesFile, routesFileFlag, "", routesFileUsage)
	fs.BoolVar(&insecure, insecureFlag, false, insecureUsage)
	fs.StringVar(&authUrlBase, authUrlBaseFlag, "", authUrlBaseUsage)
	fs.StringVar(&teamUrlBase, teamUrlBaseFlag, "", teamUrlBaseUsage)

	err := fs.Parse(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}

		os.Exit(-1)
	}
}

func logUsage(message string) {
	fmt.Fprintf(os.Stderr, "%s\n", message)
	os.Exit(-1)
}

func main() {
	if targetAddress == "" && routesFile == "" {
		logUsage("either the target address or a routes file needs to be specified")
	}

	if targetAddress != "" && routesFile != "" {
		logUsage("cannot set both the target address and a routes file")
	}

	singleRouteMode := targetAddress != ""

	if !singleRouteMode && (preserveHeader || realm != "" || scopes != "" || teams != "") {
		logUsage("the preserve-header, realm, scopes and teams flags can be used only together with the target-address flag (single route mode)")
	}

	if scopes != "" && teams != "" {
		logUsage("the scopes and teams flags cannot be used together")
	}

	teamCheckMode := teams != ""

	if authUrlBase == "" {
		authUrlBase = defaultAuthUrlBase
	}

	if teamUrlBase == "" {
		teamUrlBase = defaultTeamUrlBase
	}

	o := skipper.Options{
		Address: address,
		CustomFilters: []filters.Spec{
			skoap.NewAuth(authUrlBase),
			skoap.NewAuthTeam(authUrlBase, teamUrlBase),
			skoap.NewBasicAuth(),
			skoap.NewAuditLog(os.Stderr)},
		AccessLogDisabled: true,
		ProxyOptions:      proxy.OptionsPreserveOriginal}

	if insecure {
		o.ProxyOptions |= proxy.OptionsInsecure
	}

	if targetAddress == "" {
		o.RoutesFile = routesFile
	} else {
		var filterArgs []interface{}
		if realm != "" {
			filterArgs = append(filterArgs, realm)
		}

		args := scopes
		name := skoap.AuthName
		if teamCheckMode {
			args = teams
			name = skoap.AuthTeamName
		}

		if args != "" {
			if realm == "" {
				// realm set to empty
				filterArgs = append(filterArgs, "")
			}

			argss := strings.Split(args, ",")
			for _, a := range argss {
				filterArgs = append(filterArgs, a)
			}
		}

		f := []*eskip.Filter{{
			Name: name,
			Args: filterArgs}}
		if !preserveHeader {
			f = append(f, &eskip.Filter{
				Name: builtin.DropRequestHeaderName,
				Args: []interface{}{"Authorization"}})
		}

		o.CustomDataClients = []routing.DataClient{
			&singleRouteClient{
				Filters: f,
				Backend: targetAddress}}
	}

	err := skipper.Run(o)
	if err != nil {
		log.Fatal(err)
	}
}
