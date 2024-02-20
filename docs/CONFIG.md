# Chorus Configuration

The chorus binary requires one command line parameter which specifies the config file path.

The config file must be in RON format. See the [RON documentation](https://docs.rs/ron/latest/ron/)

## Configuration Variables

### data_directory

This is the directory where chorus stores data.

Default is "/tmp".

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

### use_tls

If true, chorus will handle TLS, running over HTTPS.  If false, chorus run over HTTP.

If you are proxying via nginx, normally you will set this to false and allow nginx to handle
TLS.

### certchain_pem_path

This is the path to your TLS certificate chain file.

If `use_tls` is false, this value is irrelevant.

Default is "./tls/fullchain.pem".

If deployed according to [docs/DEPLOYING.md](docs/DEPLOYING.md) using the direct method,
this is set to "/opt/chorus/etc/tls/fullchain.pem" and the systemd service copies letsencrypt
TLS certificates into this position on start.

### key_pem_path

This is the path to yoru TLS private key file.

If `use_tls` is false, this value is irrelevant.

Default is "./tls/privkey.pem".

If deployed according to [docs/DEPLOYING.md](docs/DEPLOYING.md) using the direct method,
this is set to "/opt/chorus/etc/tls/privkey.pem" and the systemd service copies letsencrypt
TLS certificates into this position on start.

### name

This is an optional name for your relay, displayed in the NIP-11 response.

Default is None.

### description

This is an optional description for your relay, displayed in the NIP-11 response.

Default is None.

### contact

This is an optional contact for your relay, displayed in the NIP-11 response.

Default is None.

### public_key_hex

This is an optional public key (hex format) for your relay, displayed in the NIP-11 response.

Default is None.

### user_hex_keys

These are the public keys (hex format) of your relay's authorized users. See [BEHAVIOR.md](BEHAVIOR.md) to understand how chorus uses these.

Default is `[]`

### verify_events

This is a boolean indicating whether or not chorus verifies incoming events.

This setting only skips verification of events that are submitted by AUTHed and authorized users. Chorus always verifies incoming AUTH events, and any event that is not submitted by an AUTHed and authorized relay user.

Default is true.

### allow_scraping

This is a boolean indicating whether or not scraping is allowed. Scraping is any filter that does not match one of the following conditions:

- A non-empty `id` list is set
- A non-empty `authors` list is set and a non-empty `kinds` list is set
- A non-empty `authors` list is set and at least one tag is set.
- A non-empty `kinds` list is set and at least one tag is set.
- Has a limit <= 10

Filter that fail to match these conditions will be rejected if `allow_scraping` is false.

If `allow_scraping` is true, be aware that filters that don't match any of these conditions have no indexes to speed up their query, so they scan through every single event on the relay.

The purpose of this setting is as a temporary setting that allows you to dump every single event on your relay.

Default is false.

### max_subscriptions

This is a usize indicating the maximum number of subscriptions a connection can have open at a given time.

If you set this too low, clients will be incentivised to resubmit updated subscriptions which will pull down the same events over again, instead of submitting a new subscription that only gets the additional events that the client wants. It may seem intuitive that setting this to a low value like 10 will decrease server load, but it will probably increase server load.

It is strongly recommended to not go below 16.

Default is 32.

### serve_ephemeral

Accept and serve all ephemeral events to everybody.

Default is true.

### serve_relay_lists

Accept and serve kind 10002 events to everybody.

Default is true.
