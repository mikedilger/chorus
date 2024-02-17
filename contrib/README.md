# Deploying Chorus

## Internet-accessible IP Address

Nostr relays need to be deployed on machines with Internet-accessible IP addresses.

Generally these are servers in data centres, but you might be able to make a port available
to the Internet on a home machine if your ISP doesn't use CGNAT and you know how to
configure your firewall/router for this. We leave this up to you.

## Deploying the files

As root, you'll want to create a `chorus` user. Here is an example for debian based systems:


```sh
# useradd -r -d /opt/chorus -s /bin/bash chorus
```

As root, you'll want to make the following directories

```sh
# mkdir -p /opt/chorus/{etc,src,var,sbin,lib}
# mkdir -p /opt/chorus/var/{chorus,www}
# mkdir -p /opt/chorus/lib/systemd/system
# chown -R chorus /opt/chorus
```

Now you can clone the chorus source code onto the server.

If you will be building as a different user (e.g. your personal login), you might want to change
the ownership of this directory to yourself. This is particularly useful if you already have rust
installed via rustup and don't want to install another rust system under the chorus user.

We continue presuming you will be installing rust under the chorus user.

```sh
# sudo -iu chorus
$ cd /opt/chorus/src
$ git clone https://github.com/mikedilger/chorus
$ cd chorus
```

Now we install rust as the chorus user. Beware this uses a fair amount of space for rust package
downloads that is not shared with any other user on the system.

If you have `rustc` and `cargo` installed at the system level you can use those
instead and can skip this step.  This step comes from (https://rustup.rs)[https://rustup.rs]

```sh
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you are coming back here after some time, you may wish to update rust instead:

```sh
$ rustup update
```

Now let's continue by building chorus:

```sh
$ cd /opt/chorus/src/chorus
$ cargo build --release
```

Ok now let's install that:

```sh
$ install --mode=0700 ./target/release/chorus /opt/chorus/sbin/chorus
```

Now let's create our config file

```sh
$ cp /opt/chorus/src/chorus/contrib/chorus.ron /opt/chorus/etc/
```

Go ahead and edit that file to your liking. In particular:

- Change the `ip_address` to your internet-accessible IP address (if you are running directly)
  or to 127.0.0.1 with a local port like 8080 (if you are proxying behind nginx)
- Change the port if necessary
- Change the name, description, and contact (e.g. your email address) as desired
- Set your public_key_hex (it is an option, so use `Some()`)
- Set hex keys of users for which this relay will act as a personal relay


## Setting up the Service

We describe two options for setting up the service. The first is to run chorus directly.
The second is to run chorus behind an nginx proxy.

If you want chorus to respond on port 443, and you host other virtual servers on the
machine, you'll need to run chorus behind an nginx proxy.

But you can run in on a different port (e.g. 444) too. Remember to open up your firewall
for this if necessary.


### Running chorus directly

Copy the systemd service file from the source code to the install location:

```sh
$ cp /opt/chorus/src/chorus/contrib/chorus-direct.service /opt/chorus/lib/systemd/system/chorus.service
```

Edit this file to change the `letsencrypt` paths to include your actual domain (replace the
`chorus.example.com` part).

NOTE ON TLS CERTIFICATES: We will presume that you manage TLS certificates for your server
with letsencrypt and certbot, and that certificates can be found (as root) under the
`/etc/letsencrypt/` directory. Our systemd service file will copy those certificates
into /opt/chorus/etc/tls each time it starts so it has access to them (it doesn't run as
root so it needs copies that are owned by chorus that it can access).

Make the directory for certificate copies:

```sh
$ mkdir -p --mode=0700 /opt/chorus/etc/tls
```

As root, enable the service and start the service:

```sh
# systemctl enable /opt/chorus/lib/systemd/system/chorus.service
# systemctl start chorus.service
```

### Running behind nginx

Copy the systemd service file from the source code to the install location:

```sh
$ cp /opt/chorus/src/chorus/contrib/chorus-proxied.service /opt/chorus/lib/systemd/system/chorus.service
```

Copy the nginx config file to the install location:

```sh
$ cp /opt/chorus/src/chorus/contrib/chorus.nginx.conf /opt/chorus/etc/chorus.nginx.conf
```

Change the port on the `proxy_pass` line if you are running chorus on a different port.

As root, enable the service and start the service:

```sh
# systemctl enable /opt/chorus/lib/systemd/system/chorus.service
# systemctl start chorus.service
```

Link the nginx config file

```sh
# ln -s /opt/chorus/etc/chorus.nginx.conf /etc/nginx/sites-available/chorus.nginx.conf
# ln -s ../sites-available/chorus.nginx.conf /etc/nginx/sites-enabled/chorus.nginx.conf
```

Restart nginx

```sh
# systemctl restart nginx.service
```

## Monitoring the service

You can watch the logs with a command like this

```sh
# journalctl -f -u chorus.service
```

