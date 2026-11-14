# Signing in, two-factor and passkeys

Every account signs in with a password plus a second step. There's no way
to turn the second step off. This page covers how that works, how passkeys
fit in when you have more than one server, and how to get back in if you're
locked out.

## The first sign-in

The setup wizard creates the first admin. Other people get an account from
an admin under **Users**. At their first sign-in, each person:

1. Enters their username and password.
2. Scans a QR code with an authenticator app (1Password, Bitwarden, Google
   or Microsoft Authenticator, Authy and so on) and types a code from it.
3. Saves ten recovery codes. Each one works once, in place of an
   authenticator code. Keep them somewhere other than the phone.

After that, signing in is a password plus a 6-digit code from the app, or a
passkey (below).

Accounts are shared by every server in the cluster. A user, password or
second step you change on one server applies to all of them within about a
second.

## Passkeys

A passkey lets you sign in with Face ID, Touch ID, Windows Hello, a device
PIN, a phone or a security key. You can use it on its own, or after your
password in place of the 6-digit code. Your authenticator app and recovery
codes keep working as a backup.

### Before you start

Browsers only allow passkeys when the dashboard:

- uses HTTPS with a certificate the browser trusts, and
- is opened by a name, such as `https://dns1.example.com`, never by an IP
  address.

So set up [Dashboard HTTPS](https.md) first. Let's Encrypt (built in) is
the easiest way to get a trusted certificate. Then make each name work at
home under **Local names** (for example `dns1.example.com` pointing at
`192.168.1.10`).

### Adding a passkey

1. Open the dashboard by its name, for example `https://dns1.example.com`.
2. Go to **Your account > Passkeys > Add a passkey**.
3. Give it a name (for example "MacBook"), enter your password and choose
   **Continue**.
4. Approve the prompt from your browser or device.

Next time, choose **Sign in with a passkey** on the sign-in page.

### With more than one server

A passkey works only on the exact server name it was made on. A passkey made
at `dns1.example.com` doesn't work at `dns2.example.com`, and no other
website under `example.com` can ask for it.

So add one passkey on each server: follow the steps above at
`https://dns1.example.com`, then again at `https://dns2.example.com`. Each
works even while the other server is down. Your account's Passkeys list
shows them all, with the server each one works on.

If your passkeys sync (iCloud Keychain, Google Password Manager, 1Password
and similar), each one is on your other devices too, so you only add one per
server, not one per device.

### Passkeys from older versions

Versions released before 14 November 2026 made each passkey for the whole domain (for
example `example.com`). Those still sign in, but any site under that domain
could ask for them. To replace one:

1. In **Your account > Passkeys**, remove the one whose "Works on" column
   shows the whole domain.
2. Delete it from where your device keeps passkeys too: the Passwords app
   on a Mac, iPhone or iPad; Google Password Manager; or your password
   manager. Search for the domain name.
3. Add a new passkey on each server.

## Signed-in sessions and API tokens

**Your account** lists the browsers signed in to your account, and you can
sign any of them out. Changing your password signs out your other sessions.

Scripts use API tokens instead of signing in. Create one under **Your
account > API tokens**. You pick which of your permissions each token gets,
and you can remove it any time. See the [Admin API](api.md).

## Locked out

| What happened | What to do |
|---|---|
| Wrong password, many times | Wait. After several wrong tries sign-in stops for a few minutes and says "too many failed sign-ins" |
| New phone, no authenticator app | Sign in with a passkey or a recovery code, then **Your account > Two-factor sign-in > Move to a new phone or app** |
| Lost the second step entirely | Ask another admin to choose **Reset 2FA** for you under **Users**. You set it up again at the next sign-in. This also removes your passkeys |
| Forgot your password | Ask another admin to set a new one under **Users** |
| The only admin, and locked out | Run the recovery command below on one server |
| A certificate problem keeps the page from loading | See [Locked out](https.md#locked-out) in the HTTPS guide |

### Recovery command

In the folder with your `docker-compose.yml`, replace `USERNAME` with the
account's username:

```bash
docker compose stop
docker compose run --rm dnserv -reset-mfa USERNAME -reset-password
docker compose start
```

It prints a temporary password. Sign in with it, set up the authenticator
app again, and change the password. Leave out `-reset-password` to keep the
current password and only clear the second step. The reset is recorded in
the audit log. In a cluster, the other servers need to be running for the
reset to apply.

[Back to the README](../README.md)
