# Dashboard HTTPS

The dashboard is plain HTTP on port 8080 until you turn HTTPS on. An admin
does that under **Settings → Dashboard HTTPS**, and the choice applies to
every server in the cluster.

HTTPS uses the same port. Open `https://<server>:8080` instead of
`http://`. Plain HTTP keeps working, unless you tick **Send browsers that
open http:// to https://**. The API, `/healthz` and `/metrics` are never
redirected, so scripts and health checks keep working.

## Choosing a certificate

| Option | Good for | Renewal |
|---|---|---|
| **Off** (default) | A home network you trust, or a reverse proxy in front | — |
| **Self-signed** | Encryption with no setup. Browsers warn until you accept the certificate on each device. | Each server makes its own, valid 2 years, and replaces it 30 days before it expires |
| **Upload a certificate** | A certificate from your own certificate authority | Paste a new one before it expires |
| **Certificate files in a folder** | Any tool that already gets certificates: Nginx Proxy Manager, Traefik, Caddy, certbot, acme.sh | Re-read within a minute when the files change |
| **From Nginx Proxy Manager** | People who already use Nginx Proxy Manager for Let's Encrypt | Downloaded again every 12 hours |

Whichever you choose, every server gets the same certificate. A server
that can't reach the source (for example, because it can't see the folder)
uses the copy the others share. If the certificate can't be had at all, the
server falls back to a self-signed one and Settings shows why, so HTTPS
never leads nowhere.

A trusted certificate (not self-signed) is also used for DNS over TLS and
DNS over HTTPS, unless you set `dns.tls.cert_file`. That's what Android's
Private DNS and iOS profiles need.

### Which name to use

A trusted certificate is for a name, such as `dns1.example.com`, not an
address. Open the dashboard with that name. To make the name work at home,
add it under **Local names** pointing at the server's address. A wildcard
certificate (`*.example.com`) covers all your servers. Otherwise use one
certificate per server name, or one certificate that lists every name.

### From Nginx Proxy Manager

1. In Nginx Proxy Manager, request a certificate under **SSL Certificates**
   for the name you'll use, such as `dns1.example.com`. A DNS challenge
   works without opening any port to the internet.
2. Add a user for DNServ under **Users**, with **Certificates** set to
   *View* and **Visibility** set to *All items*. Leave two-factor sign-in
   off for this user, since DNServ signs in by itself to renew.
3. In DNServ, choose **From Nginx Proxy Manager**, enter its admin address
   (usually `http://<its server>:81`), that user's email and password, and
   choose **Sign in and list certificates**. Pick the certificate and save.

The password is stored with your other servers so any of them can renew.
It is never shown again and isn't in backups. Needs Nginx Proxy Manager
2.10 or later, which can download certificates.

### Certificate files in a folder

Mount the folder read-only into the container in `docker-compose.yml`:

```yaml
    volumes:
      - dnserv-data:/data
      - /path/to/npm/letsencrypt:/certs:ro
```

Then enter the paths as the container sees them, such as
`/certs/live/npm-3/fullchain.pem` and `/certs/live/npm-3/privkey.pem`.
Mount the whole letsencrypt folder, not just `live/`: the files there point
into `archive/`. The container runs as user 65532, so the files must be
readable by it.

## Instead: a reverse proxy

You can also leave DNServ on HTTP and put a reverse proxy in front, such as
an Nginx Proxy Manager proxy host pointing at `http://<server>:8080`. Set
`DNSERV_ALLOWED_ORIGINS` to the proxy's host name. If the proxy is on the
internet, limit it to your network (an Access List in Nginx Proxy
Manager), because the dashboard controls your DNS.

## Passkeys

Browsers only allow passkeys on HTTPS and when the dashboard is opened by a
name, never by IP address. So once HTTPS is on (or behind a reverse proxy
with a real certificate), open the dashboard at its name, like
`https://dns1.example.com:8080`, then **Your account > Passkeys > Add a
passkey**.

A passkey is made for the parent domain (`example.com` here), so the same
passkey works on `dns2.example.com` and every other server under it. When
that domain is shared hosting such as `duckdns.org`, the browser refuses and
the passkey is made for that one server's name instead.

The authenticator app and recovery codes keep working, so you can always
sign in from a browser that has no passkey. An admin's **Reset 2FA** also
removes a user's passkeys.

## Locked out

Plain `http://` keeps working unless the redirect is on. If a bad
certificate keeps you out, start the container with `DNSERV_HTTPS=off`,
fix the setting, and remove the variable again.

[Back to the README](../README.md)
