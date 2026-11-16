# Making a release

Servers follow **releases** by default (see [updates.md](updates.md)): they
are offered a new version only when you publish one. Every merge to `main`
still builds an image (`latest`, the "every change" channel), so you can try
it on a test server first.

## Cut a release

1. On GitHub, open **Actions > Release > Run workflow**.
2. Pick how big the change is: **patch** (fixes only, 1.2.0 to 1.2.1),
   **minor** (new features, 1.2.0 to 1.3.0, the default) or **major**
   (something people must act on, 1.2.0 to 2.0.0). Or type an exact
   version. The very first release is 1.0.0.
3. Press **Run workflow**.

That's all. The workflow tags `main`'s current commit (for example
`v1.3.0`), publishes a GitHub Release whose notes list the pull requests
merged since the last release, and starts **Publish image**, which pushes
`ghcr.io/prezmc/dnserv:1.3.0`, `:1.3` and `:stable` (about 5 minutes).
Servers see the new version on their Updates page within a few hours, or at
once with **Check now**, and the page shows the release notes. Servers with
automatic updates install it at their chosen hour.

## Release notes

The notes are generated from pull request titles, so a clear PR title is a
clear release note. The Updates page shows each PR as one line. To add a
paragraph (for example "back up first" or "the witness needs updating
too"), edit the release on GitHub after it is published; the page picks the
edit up at the next check.

## If a release is bad

- Servers that installed it can **Roll back this update** on their Updates
  page. That version is then not offered to them again.
- Fix it on `main` and cut a **patch** release. Everyone on releases moves
  on to it, including servers that rolled back.
- Don't delete a published tag: servers may be running it, and rollback
  uses each version's `sha-` image tag, which stays.

## Also publishing to Docker Hub

Images always go to `ghcr.io/prezmc/dnserv`. To push the same tags to
Docker Hub as well:

1. On hub.docker.com, sign in and open **Account settings > Personal access
   tokens > Generate new token**. Give it **Read & Write** access.
2. In this GitHub repository, open **Settings > Secrets and variables >
   Actions** and add two repository secrets:
   - `DOCKERHUB_USERNAME`: your Docker Hub username
   - `DOCKERHUB_TOKEN`: the token from step 1
3. Run **Actions > Publish image > Run workflow** on `main` (or cut a
   release). The image appears as `<username>/dnserv` with the same tags
   (`latest`, `stable`, version numbers).

To publish under an organization instead, add a repository *variable*
(not a secret) `DOCKERHUB_IMAGE`, for example `myorg/dnserv`.
