package main

import (
	"flag"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/proxy"
	"github.com/zalando/skipper/routing"
	"github.bus.zalan.do/aryszka/hackauth"
	"log"
	"strings"
	"fmt"
	"os"
)

const (
	addressFlag = "address"
	targetAddressFlag = "target-address"
	realmFlag = "realm"
	teamsFlag = "teams"
	routesFileFlag = "routes-file"
	insecureFlag = "insecure"

	authUrlBaseFlag = "auth-url"
	defaultAuthUrlBase = "http://[::1]:9081?access_token="

	teamUrlBaseFlag = "team-url"
	defaultTeamUrlBase = "http://[::1]:9082"
)

const (
	usageHeader = `
hackauth - Hacky reverse proxy verifying authorization tokens.

Use hackauth to verify authorization tokens before forwarding requests, and optionally check OAuth realms and
team membership.

`

	addressUsage = `network address that hackauth should listen on`

	targetAddressUsage = `when authenticating to a single network endpoint, set its address (without path) as
the -target-address`

	realmUsage = `when target address is used to specify the target endpoint, and requests need to be
authenticated against an OAuth realm, set the value of the realm with the flag. Note, that in case of a routes
file is used, the realm can be set for each hackauth filter reference individually`

	teamsUsage = `when target address is used to specify the target endpoint, and requests need to be
authenticated against one or more teams ('or' relation), set the value of the teams with the flag, as a comma
separated list. The teams flag can be used only together with the realm flag. Note, that in case of a routes
file is used, the realm can be set for each hackauth filter reference individually`

	routesFileUsage = `alternatively to the target address, it is possible to use a full eskip route
configuration, and specify the hackauth() filter for the routes individually. See also:
https://godoc.org/github.com/zalando/skipper/eskip`

	insecureUsage = `when this flag set, skipper will skip TLS verification`

	authUrlBaseUsage = `URL base of the authentication service. The authentication token found
in the incoming requests will appended to this url. Example:
https://info.services.auth.zalando.com/oauth2/tokeninfo?access_token=`

	teamUrlBaseUsage = `URL base of the team service. The user id received from the authentication service will
be appended`
)

type singleRouteClient eskip.Route

var (
	address string
	targetAddress string
	realm string
	teams string
	routesFile string
	insecure bool
	authUrlBase string
	teamUrlBase string
)

func (src *singleRouteClient) LoadAll() ([]*eskip.Route, error) {
	return []*eskip.Route{(*eskip.Route)(src)}, nil
}

func (src *singleRouteClient) LoadUpdate() ([]*eskip.Route, []string, error) {
	return nil, nil, nil
}

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageHeader)
		flag.PrintDefaults()
	}

	flag.StringVar(&address, addressFlag, "", addressUsage)
	flag.StringVar(&targetAddress, targetAddressFlag, "", targetAddressUsage)
	flag.StringVar(&realm, realmFlag, "", realmUsage)
	flag.StringVar(&teams, teamsFlag, "", teamsUsage)
	flag.StringVar(&routesFile, routesFileFlag, "", routesFileUsage)
	flag.BoolVar(&insecure, insecureFlag, false, insecureUsage)
	flag.StringVar(&authUrlBase, authUrlBaseFlag, defaultAuthUrlBase, authUrlBaseUsage)
	flag.StringVar(&teamUrlBase, teamUrlBaseFlag, defaultTeamUrlBase, teamUrlBaseUsage)
	flag.Parse()
}

func logUsage(message string) {
	fmt.Fprint(os.Stderr, message)
	flag.Usage()
	os.Exit(-1)
}

func main() {
	if targetAddress == "" && routesFile == "" {
		logUsage("either the target address or a routes file needs to be specified")
	}

	if targetAddress != "" && routesFile != "" {
		logUsage("cannot set both the target address and a routes file")
	}

	if routesFile != "" && (realm != "" || teams != "") {
		logUsage("the realm and teams flags can be used only together with the target-address flag")
	}

	if realm == "" && teams != "" {
		logUsage("the teams flag can be used only when a realm is specified")
	}

	o := skipper.Options{
		Address: address,
		CustomFilters: []filters.Spec{hackauth.New(authUrlBase, teamUrlBase)},
		AccessLogDisabled: true}

	if insecure {
		o.ProxyOptions |= proxy.OptionsInsecure
	}

	if targetAddress != "" {
		var filterArgs []interface{}
		if realm != "" {
			filterArgs = append(filterArgs, realm)
			if teams != "" {
				ts := strings.Split(teams, ",")
				filterArgs = append(filterArgs, ts)
			}
		}

		o.CustomDataClients = []routing.DataClient{
			&singleRouteClient{
				Filters: []*eskip.Filter{{
					Name: "hackauth",
					Args: filterArgs}},
				Backend: targetAddress}}
	} else {
		o.RoutesFile = routesFile
	}

	log.Fatal(skipper.Run(o))
}
