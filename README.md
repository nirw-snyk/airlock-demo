# Airlock Demo

A scripted walkthrough of Snyk **Malicious Code Defense** (internally "Airlock"), a registry proxy that filters npm, PyPI, and Go packages against your security policy before they reach `npm install`, `pip install`, or `go mod download`.

`demo.sh` runs the same walkthrough for any of the three ecosystems and prints a summary table of what actually happened.

> **TODO: region support.** This demo is configured against the Snyk **MT-AU** region (`api.au.snyk.io` / `app.au.snyk.io`). Running it against any other region (US, EU, etc.) needs these changes in addition to the tenant ID:
>
> - [ ] `.npmrc`: change the host in the `registry=` URL from `api.au.snyk.io` to your region's API host.
> - [ ] `pip.conf`: change the host in the `index-url` (and in the `~/.netrc` example comment at the bottom).
> - [ ] `go.env`: change the host in the `GOPROXY=` URL (and in the `~/.netrc` example comment at the bottom).
> - [ ] `~/.netrc`: the `machine` entry must match your region's API host, or pip and Go won't send credentials.
> - [ ] `demo.sh` line 13: `PORTAL_URL` is hardcoded to `https://app.au.snyk.io/malware`. Change it to your region's app host (used for the dashboard wrap-up in section 6).
> - [ ] This README: the dashboard link under [Prerequisites](#prerequisites) and the `api.au.snyk.io` references in Setup steps 2 and 3.
> - [ ] Use a Snyk token issued for your region's tenant. An MT-AU token won't authenticate elsewhere.
> - [ ] Re-verify the tenant policies below in the target region, and re-check that the demo packages behave the same (Unmaintained, Cooldown, and the malware entries depend on that region's advisory data and policy config).
>
> Longer term, `PORTAL_URL` could be derived from the proxy host in `.npmrc` so region is set in one place.

## Setup (start here)

The repo ships with a placeholder tenant. Point it at your own before running anything.

1. **Clone the repo**
   ```bash
   git clone https://github.com/nirw-snyk/airlock-demo.git
   cd airlock-demo
   ```

2. **Change the tenant ID in three files.** Both contain a `TODO` comment marking the spot. The tenant ID is the UUID after `/tenants/` in the URL.

   | File | Line to edit |
   | --- | --- |
   | `.npmrc` | `registry=https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/npm/` |
   | `pip.conf` | `index-url = https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/pypi/simple/` (must end in `/simple/`) |
   | `go.env` | `GOPROXY=https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/golang/` (the path segment is `golang`, not `go`) |

   Or replace it in all three files at once (`sed -i ''` is the macOS form; use `sed -i` on Linux):
   ```bash
   sed -i '' 's/8951eddb-f5c4-4564-986c-1373b4bcbc6a/<YOUR_TENANT_ID>/' .npmrc pip.conf go.env
   ```
   Then delete the `TODO` comment lines. Leave the `BEGIN/END snyk-malicious-code-defense` markers in place, since Snyk tooling manages the lines between them. If your tenant uses a different host than `api.au.snyk.io`, update the host in all three URLs too.

   `demo.sh` reads the proxy URL from these three files, so no script changes are needed. `package-lock.json` and `go.sum` are git-ignored and regenerated on the first install, so they need no edit.

3. **Add your credentials.** No token is committed to this repo.
   - **pip and Go:** add an entry to `~/.netrc`. pip and Go both read it automatically for basic auth, so one entry covers both.
     ```
     machine api.au.snyk.io
     login snyk
     password <your Snyk token>
     ```
   If you already set this up for the PyPI demo, Go needs nothing more.
   - **npm:** put the auth token in your user-level `~/.npmrc`, never in the project `.npmrc`.

4. **Check the config took effect**
   ```bash
   npm config get registry                                  # should print your tenant's npm URL
   PIP_CONFIG_FILE="$PWD/pip.conf" python3 -m pip config list   # should show your tenant's index-url
GOENV="$PWD/go.env" go env GOPROXY                       # should print your tenant's golang URL
   ```

5. **Run the demo**: `./demo.sh --npm`, `./demo.sh --pypi`, or `./demo.sh --go` (see [Usage](#usage)).

## Prerequisites

- `bash`, `node` and `npm` (for `--npm`), `python3` and `pip` (for `--pypi`), Go 1.25 or newer (for `--go`; <https://go.dev/dl/>)
- A Snyk tenant with Malicious Code Defense enabled (dashboard: <https://app.au.snyk.io/malware>)
- A Snyk token for the proxy (see [Setup](#setup-start-here), step 3)

## Configuration

### Scope of the pip config

pip config is user-global by default, so `pip.conf` is deliberately not placed in pip's default location. `demo.sh --pypi` loads it via `PIP_CONFIG_FILE`, so only this demo's installs go through the proxy. To use it manually:

```bash
export PIP_CONFIG_FILE="$PWD/pip.conf"
```

### Scope of the Go config

Go's env file is user-global by default (`go env -w` writes to it), so `go.env` is not placed there. `demo.sh --go` loads it via `GOENV`, so only this demo's `go` commands use the proxy. The script also keeps the module cache inside the project (`go-mod-cache/`) so a module cached by other work on your machine can't make an install succeed without asking the proxy. To use it manually:

```bash
export GOENV="$PWD/go.env" GOMODCACHE="$PWD/go-mod-cache"
```

`GOPROXY` has no `,direct` suffix on purpose. Go falls back to fetching straight from GitHub when a proxy answers 404/410, which would bypass the policy being demoed. A `GOPROXY` set in your shell overrides the file, so `demo.sh` exports it explicitly. No `GONOSUMDB` is needed: the proxy also serves the checksum database.

### Tenant policies

The demo expects these policies on the tenant:

| Policy | Needed for |
| --- | --- |
| Known malware | Section 2 |
| Unmaintained (no release in 12+ months) | Section 3 |
| Cooldown (newly published versions held back) | Section 4 |
| Allow list entry for `object-assign` (npm), `pep8` (PyPI), and `github.com/mitchellh/mapstructure` (Go), covering **all versions**, positioned below Known malware | Section 5 |

If the allow-list entry is missing, section 5 reports "Still blocked" instead of installing.

## Usage

```bash
./demo.sh --npm    # npm walkthrough
./demo.sh --pypi   # PyPI walkthrough
./demo.sh --go     # Go walkthrough
```

Run it from the project directory. The script pauses between sections; press Enter to continue.

| # | Section | npm | PyPI | Go |
| --- | --- | --- | --- | --- |
| 0 | Reset install artifacts | `rm -rf node_modules package-lock.json` | `rm -rf pip-demo-packages` | `rm -rf go-mod-cache go.sum` |
| 1 | Normal install works through the proxy | `uuid`, `lodash`, `p-limit` | `packaging`, `certifi` | `klauspost/compress`, `x/term` + its one dependency `x/sys` (`go mod tidy`, `go run .`) |
| 2 | Known-malicious package blocked | `@onum-releases/ixel` | `maliciouseuropy` (see below) | `bufferzonecorp/net-helper` (see below) |
| 3 | Unmaintained package blocked | `left-pad` | `nose` | `mitchellh/go-homedir` |
| 4 | Cooldown holds back the newest release | `@aws-sdk/client-s3` | `boto3` | `aws-sdk-go-v2/service/s3` |
| 5 | Allow list overrides the unmaintained block | `object-assign` | `pep8` | `mitchellh/mapstructure` |
| 6 | Dashboard wrap-up | Install requests view | Install requests view | Install requests view |
| 7 | Summary table | | | |

Blocked packages show up as `ENOVERSIONS` (npm) or "no matching distribution" (pip). The proxy strips every version before the client can resolve one. Blocked-package tests use `--no-save` (npm) and `--dry-run --no-deps` (pip) so nothing is installed or executed. Go blocked-module tests use `go mod download <module>@latest`, which only fetches the module and never builds or runs it.

For Go, the script re-checks any failure against the public Go proxy (`proxy.golang.org`). A module the Snyk proxy refuses but the public proxy serves is reported as "Blocked". If both fail, it reports "Not proven", since the module may simply not exist.

## Known limitations

- **PyPI malware demo is not proven.** `maliciouseuropy` has been removed from PyPI, so it 404s whether or not the policy engages. The summary table reports it as "Not proven". Replace `KNOWN_MALICIOUS_PKG` in `demo.sh` with a package that is still live on PyPI and covered by an active Snyk advisory (check with `curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/<name>/json`, which should return 200).
- **Go malware demo is not proven (the proxy serves the malicious module).** As of 2026-10-15 the Go proxy path works for normal installs, the checksum DB, Cooldown, Unmaintained and the allow list, but `bufferzonecorp/net-helper` is served at every endpoint (list, `.info`, `.mod`, and the zip), even though Snyk has a malicious-package advisory for it (`SNYK-GOLANG-GITHUBCOMBUFFERZONECORPNETHELPER-16643554`). A policy block returns HTTP 403 with a message naming the rule, so this is not a display issue: the Known malware policy isn't being applied to Go on this tenant. The summary table reports it as "NOT blocked". Most other Go modules in the OpenSSF malicious-packages dataset are already refused by `proxy.golang.org` itself (403), so they can't show a Snyk block. `demo.sh --go` runs `go mod download` on this module, which saves its files under `go-mod-cache/` (never built or run; section 0 deletes them).
- **Very popular stale Go modules are not blocked by Unmaintained.** `pkg/errors` (2020), `go-spew` (2018), `gorilla/mux` and `google/uuid` are served despite being older than 12 months, while less-used ones (`go-homedir`, `jwt-go`, `glog`) are blocked. Check any new Unmaintained target against the proxy before using it.
- **Cooldown targets drift.** If the public and proxy versions match, the release has aged past the cooldown window. Swap `COOLDOWN_PKG` for a package that released in the last few days.
- **Policy changes can break other packages.** A broad rule such as Unmaintained can catch packages used elsewhere in the script. After changing policy, re-check everything in `package.json`, `requirements.txt`, and `go.mod`.
- **Pick allow-list demo packages with zero dependencies.** A blocked transitive dependency fails the install even when the top-level package is allow-listed.
- `package-lock.json`, `go.sum`, and `go-mod-cache/` are git-ignored, and `demo.sh` deletes them in section 0.
