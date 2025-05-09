# Deploying Chorus

## Internet-accessible IP Address

Nostr relays need to be deployed on machines with Internet-accessible IP addresses.

Generally these are servers in data centres, but you might be able to make a port available
to the Internet on a home machine if your ISP doesn't use CGNAT and you know how to
configure your firewall/router for this. We leave this up to you.

## Operating System

Chorus was developed on and for linux. It might work on other operating systems, but I
won't spend any time getting it working on non-linux systems.

In particular, I wrote [mmap-append](https://github.com/mikedilger/mmap-append) to use
linux specific mmap functionality. Ashkan Kiani came later and generalized the code but
I haven't tried it elsewhere and so I can't vouch for it elsewhere.

## Deploying the files

You'll want to create a `chorus` user. Here is an example for debian based systems:


```bash
sudo useradd -r -d /opt/chorus -s /bin/bash chorus
```

You'll want to make the following directories

```bash
sudo mkdir -p /opt/chorus/{etc,src,var,sbin,lib}
sudo mkdir -p /opt/chorus/var/{chorus,www}
sudo mkdir -p /opt/chorus/lib/systemd/system
sudo chown -R chorus /opt/chorus
```

Now we need to clone the chorus source code. We presume you will do this as yourself, but
we will put it under `/opt/chorus/src`

```bash
sudo chown $(id -u) /opt/chorus/src
cd /opt/chorus/src
git clone https://github.com/mikedilger/chorus
cd chorus
git checkout latest
```

Check if you have `rustc` and `cargo` installed. If so, you can skip this part.

This step comes from [https://rustup.rs](https://rustup.rs)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you are coming back here after some time, you may wish to update rust instead:

```bash
rustup update
```

Now let's continue by building chorus:

```bash
cargo build --release
```

Ok now let's install that (along with the utility binaries):

```bash
sudo install --mode=0700 --owner=chorus ./target/release/{chorus,chorus_compress,chorus_dump,chorus_dump_approvals,chorus_moderate,chorus_cmd} /opt/chorus/sbin/
```

Now let's create our config file

```bash
sudo -u chorus cp /opt/chorus/src/chorus/contrib/chorus.toml /opt/chorus/etc/
```

Go ahead and edit that file to your liking. In particular:

- Change the `ip_address` to your internet-accessible IP address (if you are running directly)
  or to 127.0.0.1 with a local port like 8080 (if you are proxying behind nginx)
- Change the port if necessary
- Change the name, description, banner_url, icon_url, privacy_policy, terms_of_service and
  contact (e.g. your email address) as desired
- Set your contact_public_key_hex (it is an option, so use `Some()`)
- Set hex keys of users for which this relay will act as a personal relay


## Setting up the Service

We describe two options for setting up the service. The first is to run chorus directly.
The second is to run chorus behind an nginx proxy.

If you want chorus to respond on port 443, and you host other virtual servers on the
machine, you'll need to run chorus behind an nginx proxy.

But you can run it on a different port (e.g. 444) too. Remember to open up your firewall
for this if necessary.


### Running chorus directly

Copy the systemd service file from the source code to the install location:

```bash
sudo -u chorus cp /opt/chorus/src/chorus/contrib/chorus-direct.service /opt/chorus/lib/systemd/system/chorus.service
```

Edit this file to change the `letsencrypt` paths to include your actual domain (replace the
`chorus.example.com` part).

NOTE ON TLS CERTIFICATES: We will presume that you manage TLS certificates for your server
with letsencrypt and certbot, and that certificates can be found (as root) under the
`/etc/letsencrypt/` directory. Our systemd service file will copy those certificates
into /opt/chorus/etc/tls each time it starts so it has access to them (it doesn't run as
root so it needs copies that are owned by chorus that it can access).

Make the directory for certificate copies:

```bash
sudo -u chorus mkdir -p --mode=0700 /opt/chorus/etc/tls
```

As root, enable the service and start the service:

```bash
sudo systemctl enable /opt/chorus/lib/systemd/system/chorus.service
sudo systemctl start chorus.service
```

### Running behind nginx

Copy the systemd service file from the source code to the install location:

```bash
sudo -u chorus cp /opt/chorus/src/chorus/contrib/chorus-proxied.service /opt/chorus/lib/systemd/system/chorus.service
```

Copy the nginx config file to the install location:

```bash
sudo -u chorus cp /opt/chorus/src/chorus/contrib/chorus.nginx.conf /opt/chorus/etc/chorus.nginx.conf
```

Change the port on the `proxy_pass` line if you are running chorus on a different port.

As root, enable the service and start the service:

```bash
sudo systemctl enable /opt/chorus/lib/systemd/system/chorus.service
sudo systemctl start chorus.service
```

Link the nginx config file

```bash
sudo ln -s /opt/chorus/etc/chorus.nginx.conf /etc/nginx/sites-available/chorus.nginx.conf
sudo ln -s ../sites-available/chorus.nginx.conf /etc/nginx/sites-enabled/chorus.nginx.conf
```

Restart nginx

```bash
sudo systemctl restart nginx.service
```

## Adding users and moderators

See [MANAGEMENT](MANAGEMENT.md) for how to add users and moderators.

## Monitoring the service

You can watch the logs with a command like this

```bash
sudo journalctl -f -u chorus.service
```

## Updating

````bash
cd /opt/chorus/src/chorus
git pull
cargo build --release
sudo install --mode=0700 --owner=chorus ./target/release/{chorus,chorus_compress,chorus_dump,chorus_dump_approvals,chorus_moderate,chorus_cmd} /opt/chorus/sbin/
sudo systemctl restart chorus.service
````

## Uninstalling

```bash
sudo systemctl disable chorus.service
sudo rm -f /etc/nginx/sites-available/chorus.nginx.conf
sudo rm -f /etc/nginx/sites-enabled/chorus.nginx.conf
sudo systemctl restart nginx.service
sudo rm -rf /opt/chorus
sudo userdel chorus
```
