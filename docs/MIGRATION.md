# Migration

## From 1.0 to 2.0

1) Add to your config file `admin_hex_keys` to include the nostr hex keys of administrators.
   These will (eventually) be allowed to manage users and moderators remotely via the management
   interface.  Note that being an admin does NOT automatically grant user or moderator rights,
   it ONLY grants the right to administer users.

2) Users and moderators are now dynamically configured in the database. Use `chorus_cmd` to
   manage them from the command line:

* Adding a user:  `chorus_cmd <chorus.toml> add_user <pubkey> 0`
* Adding a moderator: `chorus_cmd <chorus.toml> add_user <pubkey> 1`
* Removing a user or moderator: `chorus_cmd <chorus.toml> rm_user <pubkey>`
* Listing users and moderators: `chorus_cmd <chorus.toml> dump_users`

3) Remove the following from your config file as these are no longer used:

* `user_hex_keys` - users are now dynamically configured and configuration is in the database.
* `moderator_hex_keys` - moderators are now dynamically configured and configuration is in the database.

4) Configuration setting `public_key_kex` has been renamed `contact_public_key_hex` and is
   used only for the NIP-11 data.

