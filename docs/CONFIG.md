# Chorus Configuration

The chorus binary requires one command line parameter which specifies the config file path.

The config file must be in TOML format. See the [TOML documentation](https://github.com/toml-lang/toml)

## Configuration Variables

### data_directory

This is the directory where chorus stores data.

Default is "/opt/chorus/var/chorus".

If deployed according to [docs/DEPLOYING.md](docs/DEPLOYING.md), is "/opt/chorus/var/chorus".

### ip_address

This is the IP address that chorus listens on. If deployed directly on the Internet, this should
be an Internet globally accessible IP address. If proxied or if testing locally, this can be
a localhost address.

Default is "127.0.0.1".

### port

This is the port that chorus listens on. If deployed directly on the Internet, this should
probably be 443 which is the expected default port for the "wss://" protocol.

Default is 443.

### hostname

This is the DNS hostname of your relay. This is used for verifying AUTH events, which specify
your relay host name.

Default is localhost

### chorus_is_behind_a_proxy

If chorus is behind a proxy like nginx, set this to true. In this case chorus will look for and
trust the `X-Real-Ip` HTTP request header to get the real IP of the client. This header MUST exist
or the connection will not be served.

Default is false.

### use_tls

If true, chorus will handle TLS, running over HTTPS.  If false, chorus run over HTTP.

If you are proxying via nginx, normally you will set this to false and allow nginx to handle
TLS.

Default is true

### certchain_pem_path

This is the path to your TLS certificate chain file.

If `use_tls` is false, this value is irrelevant.

Default is "/opt/chorus/etc/tls/fullchain.pem"

If deployed according to [docs/DEPLOYING.md](docs/DEPLOYING.md) using the direct method,
systemd service copies letsencrypt TLS certificates into this position on start.

### key_pem_path

This is the path to your TLS private key file.

If `use_tls` is false, this value is irrelevant.

Default is "/opt/chorus/etc/tls/privkey.pem"

If deployed according to [docs/DEPLOYING.md](docs/DEPLOYING.md) using the direct method,
systemd service copies letsencrypt TLS certificates into this position on start.

### name

This is an optional name for your relay, displayed in the NIP-11 response.

Default is "Chorus Default"

### description

This is an optional description for your relay, displayed in the NIP-11 response.

Default is "A default config of the Chorus relay".

### icon_url

This is an optional URL for an graphical icon representing your relay, displayed in the NIP-11 response.

### contact

This is an optional contact for your relay, displayed in the NIP-11 response.

Default is None.

### public_key_hex

This is an optional public key (hex format) for your relay, displayed in the NIP-11 response.

Default is None.

### open_relay

If open_relay true, the relay behaves as an open public relay.

Default is false.

### user_hex_keys

These are the public keys (hex format) of your relay's authorized users. See [BEHAVIOR.md](BEHAVIOR.md) to understand how chorus uses these.

Default is `[]`

### moderator_hex_keys

These are the public keys (hex format) of your relay's moderators. Moderators can moderate the relay using the [NIP 86: Relay Management API](https://github.com/nostr-protocol/nips/pull/1325)

Default is `[]`

### verify_events

This is a boolean indicating whether or not chorus verifies incoming events.

This setting only skips verification of events that are submitted by AUTHed and authorized users. Chorus always verifies incoming AUTH events, and any event that is not submitted by an AUTHed and authorized relay user.

Default is true.

### allow_scraping

This is a boolean indicating whether or not scraping is allowed. Scraping is any filter where all of the following are true:

- `ids` is missing or empty
- `authors` is missing or empty
- There are no `#X` tag filters

Filter that fail to match these conditions will be rejected if `allow_scraping` is false.

If `allow_scraping` is true, be aware that filters that don't match any of these conditions have no indexes to speed up their query, so they scan through every single event on the relay.

The purpose of this setting is as a temporary setting that allows you to dump every single event on your relay.

Default is false.

### allow_scrape_if_limited_to

This is a u32 count of events indicating a filter `limit` value under which a scrape is allowed, irrespective of the `allow_scraping` setting. Such scrapes are not expensive due to the limit.

See `allow_scraping` to learn the definition of a scrape.

The default is 100.

### allow_scrape_if_max_seconds

This is a u64 number of seconds indicating a filter time range under which a scrape is allowed, irrespective of the `allow_scraping` setting. Such scrapes are rarely expensive due to the short time period.

See `allow_scraping` to learn the definition of a scrape.

The default is 7200.

### max_subscriptions

This is an integer indicating the maximum number of subscriptions a connection can have open at a given time.

If you set this too low, clients will be incentivised to resubmit updated subscriptions which will pull down the same events over again, instead of submitting a new subscription that only gets the additional events that the client wants. It may seem intuitive that setting this to a low value like 10 will decrease server load, but it will probably increase server load.

It is strongly recommended to not go below 16.

Default is 128.

### serve_ephemeral

Whether or not to accept and serve all ephemeral events to everybody.

Default is true.

### serve_relay_lists

Whether or not to accept and serve kind 10002 Relay List Metadata (NIP-65) events to everybody.

Default is true.

### server_log_level

How verbose to log issues with the main server code.

Possible values are: Trace, Debug, Info, Warn, Error

Default is Info

### library_log_level

How verbose to log library issues and other general issues

Possible values are: Trace, Debug, Info, Warn, Error

Default is Info

### client_log_level

How verbose to log issues with client requests

Possible values are: Trace, Debug, Info, Warn, Error

Default is Info

### enable_ip_blocking

Whether to block incoming connections based on recent prior behavior

Chorus normally blocks IP addresses for a short period preventing quick reconnections, and for a longer period if the previous connection ended in some error condition.

By setting this variable to false, it will allow all connections, incluing poorly behaving clients that reconnect over and over in a tight loop.

Default is true

### minimum_ban_seconds

Number of seconds to ban an IP address after disconnection.

Enforcing this minimum ban prevents clients from immediately reconnecting which can cause tight loops.

Only relevant if enable_ip_blocking is true.

Default is 1

### timeout_seconds

Number of seconds beyond which chorus times out a client that has no open subscriptions.

Default is 60

### max_connections_per_ip

Maximum number of websocket connections per IP address

Default is 5

### throttling_bytes_per_second

The maximum rate (excluding bursts) of data that will be transmitted over a websocket connection
(both directions, per connection). Beyond this rate (in a sustained way) the connection will be
closed.

Default is 1024576 bytes per second.

### throttling_burst

The allowable bursts of data beyond the normal rate.

We keep a count of how many bytes they are allowed, and that count starts at this number.
As bytes are consumed the count goes down, but we refund throttling_bytes_per_second every
second. If that bucket doesn't have enough, the burst won't be allowed and the connection
will be closed.

Default is 16777216 bytes.

### blossom_directory

Blossom server directory

Set to a filesystem directory where you want chorus to store files.

Blossom allows clients to upload files making them available for the public to download.
Our implementation makes all files publicly readable, but only chorus users can upload
or delete.  See https://github.com/hzrd149/blossom

Default is None
