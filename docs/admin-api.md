# Admin API

The erldns Admin API provides a RESTful HTTP interface for managing and querying DNS zones at runtime. It allows you to inspect zone data, query individual records, and perform administrative operations on the DNS server.

## Overview

The Admin API is built on [Cowboy](https://github.com/ninenines/cowboy), a high-performance HTTP server for Erlang/OTP. It supports:

- JSON, HTML, and plain text responses via content negotiation
- Optional TLS encryption
- Optional HTTP Basic Authentication
- Custom middleware and route extensions

### Default Configuration

| Setting | Default Value |
|---------|---------------|
| Host | `0.0.0.0` (all interfaces) |
| Port | `8083` (clear) / `8483` (TLS) |
| TLS | Disabled |
| Authentication | Disabled |

## Endpoints

### List All Zones

Returns metadata about all zones currently loaded in the cache.

```
GET /
```

#### Response

```json
{
  "erldns": {
    "zones": {
      "count": 2,
      "versions": [
        {
          "name": "example.com",
          "version": "1"
        },
        {
          "name": "example.org",
          "version": "2"
        }
      ]
    }
  }
}
```

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `count` | integer | Total number of zones in cache |
| `versions` | array | List of zone metadata objects |
| `versions[].name` | string | Zone name (domain) |
| `versions[].version` | string | Zone version identifier |


### Reset Listener Queues

Resets all DNS listener queues. This can be useful for clearing backlogged requests.

```
DELETE /
```

#### Response

```
HTTP/1.1 204 No Content
```


### Get Zone

Returns detailed information about a specific zone, including all its DNS records.

```
GET /zones/:zonename
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `zonename` | string | The zone name (e.g., `example.com`) |

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `metaonly` | string | `false` | Set to `true` to return only metadata without records |

#### Response (Full)

```json
{
  "erldns": {
    "zone": {
      "name": "example.com",
      "version": "1",
      "records_count": 5,
      "records": [
        {
          "name": "example.com.",
          "type": "SOA",
          "ttl": 3600,
          "content": "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
        },
        {
          "name": "example.com.",
          "type": "NS",
          "ttl": 3600,
          "content": "ns1.example.com."
        },
        {
          "name": "example.com.",
          "type": "A",
          "ttl": 3600,
          "content": "192.0.2.1"
        }
      ]
    }
  }
}
```

#### Response (Metadata Only)

When `?metaonly=true`:

```json
{
  "erldns": {
    "zone": {
      "name": "example.com",
      "version": "1",
      "records_count": 5
    }
  }
}
```

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Zone name |
| `version` | string | Zone version identifier |
| `records_count` | integer | Total number of records in the zone |
| `records` | array | List of DNS records (omitted when `metaonly=true`) |
| `records[].name` | string | Fully qualified record name |
| `records[].type` | string | DNS record type (A, AAAA, CNAME, MX, etc.) |
| `records[].ttl` | integer | Time-to-live in seconds |
| `records[].content` | string | Record data (format varies by type) |

#### Error Response

If the zone is not found:

```
HTTP/1.1 404 Not Found
```


### Delete Zone

Removes a zone from the cache.

```
DELETE /zones/:zonename
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `zonename` | string | The zone name to delete |

#### Response

```
HTTP/1.1 204 No Content
```

#### Error Response

If the zone is not found:

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error": "zone not found"}
```


### List Zone Records

Returns all DNS records in a zone.

```
GET /zones/:zonename/records
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `zonename` | string | The zone name |

#### Response

```json
[
  {
    "name": "example.com.",
    "type": "SOA",
    "ttl": 3600,
    "content": "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
  },
  {
    "name": "example.com.",
    "type": "A",
    "ttl": 3600,
    "content": "192.0.2.1"
  },
  {
    "name": "www.example.com.",
    "type": "CNAME",
    "ttl": 300,
    "content": "example.com."
  }
]
```


### Get Records by Name

Returns DNS records matching a specific name within a zone.

```
GET /zones/:zonename/records/:record_name
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `zonename` | string | The zone name |
| `record_name` | string | The record name to filter by (e.g., `www` or `www.example.com`) |

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by DNS record type (e.g., `A`, `AAAA`, `CNAME`, `MX`) |

#### Examples

Get all records for `www.example.com`:

```
GET /zones/example.com/records/www.example.com
```

Get only A records for `www.example.com`:

```
GET /zones/example.com/records/www.example.com?type=A
```

#### Response

```json
[
  {
    "name": "www.example.com.",
    "type": "A",
    "ttl": 300,
    "content": "192.0.2.1"
  }
]
```


## Authentication

The Admin API supports HTTP Basic Authentication. When enabled, all endpoints require valid credentials.

### Enabling Authentication

Configure credentials in your `sys.config` or `erldns.config`:

```erlang
{erldns, [
    {admin, [
        {credentials, {<<"admin">>, <<"secret">>}}
    ]}
]}
```

Both username and password must be binary strings.

### Making Authenticated Requests

Include the `Authorization` header with Base64-encoded credentials:

```bash
curl -u admin:secret http://localhost:8083/zones/example.com
```

Or manually:

```bash
curl -H "Authorization: Basic YWRtaW46c2VjcmV0" http://localhost:8083/zones/example.com
```

### Unauthorized Response

When authentication fails or credentials are missing:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: basic realm="erldns admin"
```


## TLS Configuration

Enable HTTPS by configuring TLS options:

```erlang
{erldns, [
    {admin, [
        {port, 8483},
        {tls, {true, [
            {certfile, "/path/to/cert.pem"},
            {keyfile, "/path/to/key.pem"}
        ]}}
    ]}
]}
```

The TLS options are passed directly to Erlang's `ssl` module. See the [ssl documentation](https://www.erlang.org/doc/apps/ssl/ssl.html) for all available options.

### Common TLS Options

| Option | Description |
|--------|-------------|
| `certfile` | Path to the PEM-encoded certificate file |
| `keyfile` | Path to the PEM-encoded private key file |
| `cacertfile` | Path to the CA certificate file for client verification |
| `verify` | `verify_peer` or `verify_none` for client certificate verification |


## Configuration Reference

All configuration options are set under `{erldns, [{admin, [...]}]}`:

```erlang
{erldns, [
    {admin, [
        {port, 8083},
        {tls, false},
        {credentials, false},
        {middleware, []},
        {routes, []}
    ]}
]}
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | integer | `8083` / `8483` | Port to listen on (1-65535) |
| `tls` | `false` \| `{true, SslOpts}` | `false` | TLS configuration |
| `credentials` | `false` \| `{User, Pass}` | `false` | HTTP Basic Auth credentials (binaries) |
| `middleware` | list | `[]` | Custom Cowboy middleware modules |
| `routes` | list | `[]` | Additional Cowboy routes |


## Extending the Admin API

### Custom Middleware

Middleware modules intercept all requests before they reach the handlers. This is useful for logging, metrics, custom authentication, or request modification.

#### Creating Middleware

Implement the `cowboy_middleware` behavior:

```erlang
-module(my_admin_middleware).
-behaviour(cowboy_middleware).

-export([execute/2]).

execute(Req, Env) ->
    %% Log the request
    logger:info("Admin API request: ~s ~s", [
        cowboy_req:method(Req),
        cowboy_req:path(Req)
    ]),

    %% Add a custom response header
    Req2 = cowboy_req:set_resp_header(<<"x-custom-header">>, <<"value">>, Req),

    %% Continue processing
    {ok, Req2, Env}.
```

#### Return Values

| Return | Effect |
|--------|--------|
| `{ok, Req, Env}` | Continue to next middleware/handler |
| `{stop, Req}` | Stop processing and return response |

#### Registering Middleware

Add the module to the `middleware` configuration:

```erlang
{admin, [
    {middleware, [my_admin_middleware]}
]}
```

Middleware executes in order, before the built-in authentication middleware.


### Custom Routes

Add new HTTP endpoints without modifying the core erldns code.

#### Creating a Handler

Implement a Cowboy REST handler:

```erlang
-module(my_custom_handler).
-behaviour(cowboy_rest).

-export([
    init/2,
    allowed_methods/2,
    content_types_provided/2,
    to_json/2
]).

init(Req, State) ->
    {cowboy_rest, Req, State}.

allowed_methods(Req, State) ->
    {[<<"GET">>], Req, State}.

content_types_provided(Req, State) ->
    {[
        {<<"application/json">>, to_json}
    ], Req, State}.

to_json(Req, State) ->
    Action = cowboy_req:binding(action, Req),
    Body = json:encode(#{action => Action, status => <<"ok">>}),
    {Body, Req, State}.
```

#### Registering Routes

Add routes to the configuration:

```erlang
{admin, [
    {routes, [
        {"/custom/:action", my_custom_handler, #{}}
    ]}
]}
```

Custom routes are prepended to the default routes, so they take precedence if paths overlap.

#### Route Path Syntax

Routes use Cowboy's path matching:

| Pattern | Example Match | Binding |
|---------|---------------|---------|
| `/static` | `/static` | None |
| `/zones/:name` | `/zones/example.com` | `name = "example.com"` |
| `/files/[...]` | `/files/a/b/c` | Rest = `["a", "b", "c"]` |


## Content Negotiation

All endpoints support content negotiation via the `Accept` header:

| Accept Header | Response Format |
|---------------|-----------------|
| `application/json` | JSON (default) |
| `text/html` | HTML |
| `text/plain` | Plain text |

Example:

```bash
curl -H "Accept: text/html" http://localhost:8083/
```


## Error Handling

The API uses standard HTTP status codes:

| Code | Meaning |
|------|---------|
| `200 OK` | Request successful |
| `204 No Content` | Delete operation successful |
| `400 Bad Request` | Invalid request or operation failed |
| `401 Unauthorized` | Authentication required or failed |
| `404 Not Found` | Zone or record not found |

Error responses include a JSON body with details:

```json
{
  "error": "zone not found"
}
```


## Examples

### List All Zones

```bash
curl http://localhost:8083/
```

### Get Zone with Authentication

```bash
curl -u admin:secret http://localhost:8083/zones/example.com
```

### Get Zone Metadata Only

```bash
curl "http://localhost:8083/zones/example.com?metaonly=true"
```

### Get All MX Records

```bash
curl "http://localhost:8083/zones/example.com/records/example.com?type=MX"
```

### Delete a Zone

```bash
curl -X DELETE http://localhost:8083/zones/example.com
```

### Reset Listener Queues

```bash
curl -X DELETE http://localhost:8083/
```

### Using with jq

```bash
# Get zone count
curl -s http://localhost:8083/ | jq '.erldns.zones.count'

# List all zone names
curl -s http://localhost:8083/ | jq -r '.erldns.zones.versions[].name'

# Get all A records from a zone
curl -s http://localhost:8083/zones/example.com/records | jq '[.[] | select(.type == "A")]'
```


## Architecture

The Admin API consists of:

- **`erldns_admin`** - Main supervisor and startup module
- **`erldns_admin_root_handler`** - Handles `/` endpoint
- **`erldns_admin_zone_handler`** - Handles `/zones/:zonename` endpoint
- **`erldns_admin_zone_records_handler`** - Handles `/zones/:zonename/records[/:record_name]` endpoint
- **`erldns_admin_auth_middleware`** - HTTP Basic Authentication middleware

All handlers implement the `cowboy_rest` behavior and use the built-in OTP `json` module for encoding/decoding.
