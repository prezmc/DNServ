# Backups and settings history

**Settings history.** Every change to settings, devices or groups is kept
as a version (the last 50, on every node). Under **Backups & history** you
can compare any version with now and go back to it. Going back is itself a
new version, so it can be undone. Accounts aren't part of the history, so
going back never brings back an old password or a deleted user.

**Encrypted backups.** A backup is one `.dnsbak` file with the accounts,
API tokens, settings, devices, groups and settings history. It is encrypted
with a passphrase you choose when you set backups up (at least 12
characters). DNServ keeps only a public key made from it: nodes can make
backups on their own but can't read them, and without the passphrase
nobody can open one. Keep it in a password manager.

- **Download a backup now** from the dashboard at any time.
- **Automatic backups** run daily or weekly (Sundays) at a set time, in the
  same time zone as group schedules. Every node keeps its own in
  `/data/backups` (the last 14 by default).
- **A copy off the server:** mount a folder from a NAS or another disk into
  the container (for example `-v /mnt/nas/dnserv:/backups`) and enter
  `/backups` under **Mounted folder**. The leading node writes one copy of each
  backup there.
- **A network share (SMB):** under **Where backups go**, choose **Set up** on **Network share**
  and enter the share as Windows or macOS shows it
  (`\\nas.local\backups\dnserv` or `smb://192.168.1.254/backups`), with
  a user name and password. DNServ talks SMB 2/3 itself, so nothing needs
  mounting on the server. **Check and save** writes, reads and deletes a
  test file first; **Copy a backup now** sends one straight away. The
  leading node writes one copy of each scheduled backup and keeps the same
  number there. The password is stored like the S3 secret key.
- **Off-site in S3:** under **Where backups go**, choose **Set up** on **S3 storage**
  and enter the bucket. Amazon S3, Backblaze B2, Cloudflare R2, Wasabi,
  MinIO and other S3-compatible storage work: leave Endpoint empty for
  Amazon, otherwise enter the service's host (for example
  `s3.us-west-004.backblazeb2.com`, or `https://minio.lan:9000`), and tick
  "bucket in the path" for MinIO and most NAS apps. **Check and save**
  writes, reads and deletes a small test file before saving. The leading
  node then uploads one copy of each scheduled backup and keeps the same
  number there as locally; **Copy a backup now** sends one straight away.
  Give the key access to that bucket only (list, read, write, delete). The
  secret key is stored on your servers, never shown again, and isn't in
  backups. Files are encrypted before upload, so the storage provider can't
  read them.
- **Restore** from a file under Backups & history (replaces the accounts and
  configuration on every node; the cluster's nodes stay as they are), or on
  a brand-new node choose **Restore from a backup** in the setup wizard.

Backup files use XChaCha20-Poly1305. The key comes from an ephemeral X25519
key agreed with the passphrase's key (scrypt, then HKDF-SHA256), and the
readable header (when, which node) is authenticated too.

[Back to the README](../README.md)
