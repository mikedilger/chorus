# Personal Relay

A personal relay is a relay that serves as an OUTBOX and an INBOX for a small set of
users, perhaps just yourself.

It hosts your own events and makes them available to the public.

It accepts events that tag your users, but doesn't allow the public to read them back until
they have passed moderation and until then, only your users (after being authenticated) can see
them.

One nice thing about a personal relay is that you are in control, and you have a record
of your events in your possession.

Another nice thing is that you don't have to moderate content if you don't care to.

## The Dark Side

There is a dark side to running a personal relay. If lots of people do this, nostr will
become more difficult for clients, especially clients running on mobile phones. Because
they will need to setup SSL connections to far too many relays.

It may be better for others if people were to use a smaller number of larger relay services.

But who am I to say? You are the sovereign. Here is your personal relay.

## Open Relay

You can run chorus as an open public relay. Just set `open_relay` to true in the config.
