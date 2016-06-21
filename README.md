# Skoap

## Incubator Help Welcome

The library and command in this repository currently depends on our auth and team service implementation. To make this repository a kinder open source place, we would need to make its dependencies more flexible. At minimum:

- define swagger descriptions for both service dependencies
- in the library, create interfaces for both the auth and the team service

## Skoap

Skoap implements an authentication proxy based on [Skipper](https://github.com/zalando/skipper).

The main package provides a couple Skipper filters as a library, that can be used in any Skipper compilation.
For information on how to extend Skipper with additional filters, see its main documentation and its main
readme:

- [https://godoc.org/github.com/zalando/skipper](https://godoc.org/github.com/zalando/skipper)
- [https://github.com/zalando/skipper/blob/master/readme.md](https://github.com/zalando/skipper/blob/master/readme.md)

Skoap also contains the skoap command, that is a custom compilation of Skipper built with the Skoap filters.
Command example:

```
skoap -address :9090 -routes-file routes.eskip -auth-url https://my-auth.example.org
```

## Authentication mechanism

The auth filter takes the incoming request, and tries to extract the Bearer token from the Authorization header.
Then it validates against a configured service. Depending on the settings, it also can check if the owner of the
token belongs to a specific OAuth2 realm, and it can check if it has at least one of the predefined scopes, or
belongs to a certain team. If any of the expectations are not met, it doesn't forward the request to the target
endpoint, but returns with status 401.

When team checking is configured, Skoap makes an additional request to the configured team service before
forwarding the request, to get the teams of the owner of the token.

As additional features, the package also supports dropping the incoming Authorization header, replacing it with
basic authorization. It also supports simple audit logging.

## Skoap command

The command by default starts a proxy listening on port 80. To change the default listenting address, use the
`-address` flag:

```
skoap -address :9090
```

The authentication and team service needs to be set with command line flags (actually they have
the not so useful defaults: http://[::1]:9081 and http://[::1]:9082/?uid=, but nevermind):

```
skoap -address :9090 -auth-url https://auth.example.org -team-url https://teams.example.org/?uid=
```

Common unexplained flags: `-v`, `-insecure`, `-help`

The command can operate in two modes, and the rest of the command line flags depends on which mode is Skoap
started in:

- single-route mode: run a simple authentication proxy in front of a single http endpoint
- multi-route mode: run a proxy with multiple, flexibly configured routes

### Single-route mode

To start Skoap in single-route mode, the target-address flag needs to be specified:

```
skoap -address :9090 -target-address https://www.example.org
```

The single-route supports additional command line flags, that are typically configured in the route
configuration file when in multi-route mode:

##### -preserve-header

The single route mode drops the Authorization header from the outgoing request by default. With the flag one can
keep the header.

##### -realm

Set the OAuth2 to check in addition to token validation.

##### -scopes

A comma-separated list of OAuth2 scopes to check in addition to token validation.

##### -teams

A comma-separated list of teams to check in addition to token validation. It doesn't work together with scope
checking.

##### -audit-log

Flag enabling the audit log.

##### -audit-log-limit

Set the byte limit for request body in the audit log. Default: 1024.

### Multi-route mode

A more advanced way of using Skoap is to use a routes file, where multiple routes can be configured with
different matching and filtering rules, and with different proxy backend endpoints.

To start Skoap in multi-route mode, use the `-routes-file` flag:

```
skoap -address :9090 -routes-file routes.eskip
```

The route configuration file has to be in 'eskip' format. See more details at:

[https://godoc.org/github.com/zalando/skipper/eskip](https://godoc.org/github.com/zalando/skipper/eskip)

...and see the Skoap specific example below.

In multi-route mode, the realm, scopes, teams and dropping the Authorization header is defined individually for
each route in the config file. In addition to the built-in Skipper filters, Skoap provides additional filters to
support authentication:

##### auth

The `auth` filter validates the bearer token, and optionally the OAuth2 realm and scopes. The first optional
argument is the realm. The rest of the variadic arguments are the scopes. The scope check is successful if any
of the scopes matches. If one wants to validate the scopes but not the realm (discuraged), the first argument
needs to be set to `""`.

##### authTeam

Same as auth, but it validate teams instead of scopes.

##### basicAuth

The `basicAuth` filter sets a basic authorization header for outgoing requests based on the passed in username
and password arguments.

##### auditLog

The `auditLog` prints a simple audit log with the incomgin HTTP method and path, and the returned status code. When the
request is authenticated, it prints the username of the token owner. If the request is rejected due to failed
authentication, it prints the reason. Optionally, it can print the incoming request body with a byte-count
limit or without. The output format is JSON. Example:

```
{"method":"POST","path":"/","status":401,"authStatus":{"rejected":true,"reason":"invalid-token"}}
```

### Routes file example

(The following example assumes some understanding of the
[eskip](https://godoc.org/github.com/zalando/skipper/eskip) format.)

```
///////////////////////////
//                       //
// Skoap example routing //
//                       //
///////////////////////////

// Just check the token
//
// 1. matches all requests that the other routes don't
// 2. validates the incoming Authorization header
// 3. drops the incoming Authorization header
// 4. forwards the request to https://www.example.org
// 5. prints audit log when the response is done
//
catchAll: *
	-> auditLog()
	-> auth()
	-> dropRequestHeader("Authorization")
	-> "https://www.example.org";


// Employees only with hardcoded basic
//
// 1. matches requests to host employees.foo.org
// 2. validates the incoming Authorization header
// 3. validates the realm of the owner of the token in the header
// 4. sets a hardcoded outgoing Authorization header
// 5. forwards the request to https://www.example.org
// 6. prints audit log when the response is done, with the request
//    body included, max. 1024 bytes
//
realmOnly: Host("^employees.foo.org$")
	-> auditLog(1024)
	-> auth("/employees")
	-> basicAuth("user9", "secret")
	-> "https://www.example.org";


// Services with scopes only
//
// 1. matches requests to host services.foo.org
// 2. validates the incoming Authorization header
// 3. validates the realm of the owner of the token in the header
// 4. validates the assigned scopes of the token owner by looking for the first match
// 5. sets a hardcoded outgoing Authorization header
// 6. forwards the request to https://www.example.org
// 7. prints audit log when the response is done, with the request
//    body included, unlimited number of bytes (watch performance!!!)
//
checkScope: Host("^services.foo.org$")
	-> auditLog(-1)
	-> auth("/services", "read-kio", "write-kio")
	-> basicAuth("service9", "secret")
	-> "https://www.example.org";


// Employees in the right team as themselves
//
// 1. matches requests to host employees.foo.org with path /my-home
// 2. validates the incoming Authorization header
// 3. validates the realm of the owner of the token in the header
// 4. validates the team membership of the token owner by looking for the first match
// 5. forwards the request to https://www.example.org with the incoming Authorization header
//
checkTeam: Host("^employees.foo.org$") && Path("/my-home")
	-> authTeam("/employees", "monkey", "mop")
	-> "https://www.example.org";
```

The syntax validity of the configuration file can be checked with the `eskip check` command (part of the Skipper
distribution):

```
eskip check example.eskip
```

### Secure Elasticsearch example

Assuming we have a private Elasticsearch cluster and we want to expose it with an extra layer of oauth2 security.

The following ``eskip`` routes file would allow only ``GET`` & ``POST`` HTTP methods while authenticating the request using ``auth`` filter.

```
esget:
    PathRegexp("/es/.*") && Method("GET")
    -> auth()
    -> modPath(/^\/es\/(.*)$/, "/$1")
    -> "http://private-elasticsearch-cluster";

espost:
    PathRegexp("/es/.*") && Method("POST")
    -> auth()
    -> modPath(/^\/es\/(.*)$/, "/$1")
    -> "http://private-elasticsearch-cluster";
```

Running Skoap with ``auth-url``

```
skoap -address :9090 -routes-file skoap.eskip -auth-url https://auth.example.org
```
