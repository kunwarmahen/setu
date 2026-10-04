# setu-catalog-server

The catalog server serves Setu's signed catalog to everyone who uses Setu. It
also counts installs (anonymously) and takes submissions of connectors and
recipes for you to review.

**It never holds your signing key.** You sign the catalog on your own computer
and upload the signed file. The server checks the signature before serving it.
Even if someone took the server over, they couldn't list a connector, change a
hash or bring back a withdrawn version: every Setu checks the signature itself,
and refuses an index older than the one it already has.

## What you need

* A small Linux server or VM with Podman, and a domain name pointing at it.
* Something in front that does HTTPS, such as Caddy, nginx or your host's load
  balancer. The server speaks plain HTTP on `127.0.0.1:8780`.
* Your signing key, made once on **your own computer** (not the server):

  ```
  setu catalog keygen ~/keys/setu.key       # keep setu.key offline; copy setu.key.pub
  ```

## Set it up (about 15 minutes, once)

**1. Build the image**, on the server, from a checkout of the setu repo:

```
podman build -f packages/setu-catalog-server/Containerfile -t setu-catalog .
```

**2. Tell it which key to accept uploads from.** Copy `setu.key.pub` (only
the `.pub`) to the server:

```
podman volume create setu-catalog-data
podman run --rm -v setu-catalog-data:/data:Z -v ./setu.key.pub:/tmp/k.pub:Z,ro \
    setu-catalog setu-catalog-server --trust /tmp/k.pub
```

**3. Make the publish token.** It's a long random string that you keep. Podman
keeps it as a secret, so it isn't stored in a file or your shell history:

```
openssl rand -hex 32 | tee ~/setu-catalog-token.txt | podman secret create setu-catalog-token -
```

Keep `~/setu-catalog-token.txt` somewhere safe (a password manager), and delete
it from the server.

**4. Run it as a service** with the Quadlet unit in `deploy/`:

```
mkdir -p ~/.config/containers/systemd
cp packages/setu-catalog-server/deploy/setu-catalog.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start setu-catalog
loginctl enable-linger "$USER"          # keep it running after you log out
curl -s http://127.0.0.1:8780/health    # {"ok":true,"issued":"","keys":["…"]}
```

**5. Put HTTPS in front.** With Caddy, the whole config is:

```
catalog.example.com {
    reverse_proxy 127.0.0.1:8780
}
```

The unit runs the server with `--behind-proxy`, so installs are counted per real
address and not per proxy. Only use that flag behind a proxy you run;
otherwise anyone can claim any address.

## Publishing (from your own computer)

```
# 1. edit index.json: add, update or withdraw connectors and recipes
setu catalog counts index.json --to https://catalog.example.com   # 2. copy in install totals
setu catalog sign index.json --key ~/keys/setu.key                # 3. sign it
SETU_CATALOG_TOKEN=… setu catalog publish index.json --to https://catalog.example.com
```

Bump `issued` every time. The server refuses an index older than the one it
serves, and so does every Setu.

People start using it with:

```
setu catalog trust setu.key.pub
setu catalog use https://catalog.example.com
```

## Reviewing submissions

```
export SETU_CATALOG_TOKEN=…
setu catalog review --to https://catalog.example.com          # what's waiting
setu catalog review ID --to https://catalog.example.com       # one, in full
setu catalog close ID --verdict accepted --reason "listed in the next index" \
    --to https://catalog.example.com
```

**A recipe:** save it to a folder, read it, and try it:

```
setu catalog review ID --save ~/review --to https://catalog.example.com
yantra --skill-install ~/review/<name>          # shows every file, asks; then use it
setu catalog upload ~/review/<name> --to https://catalog.example.com
```

`upload` stores the recipe on the server under the SHA-256 of its bytes and
prints the `bundle` lines to put in that recipe's entry in `index.json`. Then
sign and publish. Users install it with `yantra --skill-install
catalog:<name>`; Setu checks the bundle against the signed hash first.

A connector arrives as source code at an exact commit. Read it there, and build
the wheel yourself from that commit; never use a wheel the author sends. Then
add it to `index.json` with the wheel's address and `sha256`, sign and publish.
Accepting a submission publishes nothing by itself.

## Certifications and "worked" counts

The server also keeps two things it never judges:

* **Certifications** (`POST /certifications`). Each one is signed by an
  independent certifier and covers one version by hash. The server accepts it
  only if the signature checks out and the hash is what your index lists, then
  keeps it as sent. Whose certifications count is each reader's choice.
  `GET /certifiers` shows who has certified, how many, and since when.
* **Worked/failed reports** (`POST /works`). These come from people's Setu, for
  recipes your index lists, under their `share-installs` switch.
  `setu catalog counts` copies the totals for the version you list into
  `index.json` before you sign it.

## Keeping it

Everything is in the `setu-catalog-data` volume: the served index and its
signature, the trusted keys, install totals, and the submission queue. Back it
up by copying it:

```
podman volume export setu-catalog-data > setu-catalog-$(date +%F).tar
```

Nothing in it is secret except the submitters' contact details. The signing key
is never there, and the token is a Podman secret. Losing the volume loses the
counts and the queue; you can publish the index again from your own copy.

**If the signing key leaks:** make a new one, have the old key vouch for it
(`setu catalog vouch new.key.pub --key old.key`), sign with the new key and the
chain (`--chain`), and trust the new `.pub` on the server. Setus that trust the
old key accept the new one through the chain. Then stop trusting the old key
everywhere (`setu catalog trust --remove OLD_ID`).

## Docker instead

The same `Containerfile` works with Docker:
`docker build -f packages/setu-catalog-server/Containerfile -t setu-catalog .`.
Use `-e SETU_CATALOG_TOKEN` or a Docker secret in place of the Podman secret,
and your own way of keeping it running in place of the Quadlet unit.
