# Airlock Demo

A scripted walkthrough of Snyk **Malicious Code Defense** (internally "Airlock"), a registry proxy that filters npm and PyPI packages against your security policy before they reach `npm install` or `pip install`.

`demo.sh` runs the same walkthrough for either ecosystem and prints a summary table of what actually happened.

> **TODO: region support.** This demo is configured against the Snyk **MT-AU** region (`api.au.snyk.io` / `app.au.snyk.io`). Running it against any other region (US, EU, etc.) needs these changes in addition to the tenant ID:
>
> - [ ] `.npmrc`: change the host in the `registry=` URL from `api.au.snyk.io` to your region's API host.
> - [ ] `pip.conf`: change the host in the `index-url` (and in the `~/.netrc` example comment at the bottom).
> - [ ] `~/.netrc`: the `machine` entry must match your region's API host, or pip won't send credentials.
> - [ ] `demo.sh` line 13: `PORTAL_URL` is hardcoded to `https://app.au.snyk.io/malware`. Change it to your region's app host (used for the dashboard wrap-up in section 6).
> - [ ] This README: the dashboard link under [Prerequisites](#prerequisites) and the `api.au.snyk.io` references in Setup steps 2 and 3.
> - [ ] Use a Snyk token issued for your region's tenant. An MT-AU token won't authenticate elsewhere.
> - [ ] Re-verify the tenant policies below in the target region, and re-check that the demo packages behave the same (Unmaintained, Cooldown, and the `@onum-releases/ixel` malware entry depend on that region's advisory data and policy config).
>
> Longer term, `PORTAL_URL` could be derived from the proxy host in `.npmrc` so region is set in one place.

## Setup (start here)

The repo ships with a placeholder tenant. Point it at your own before running anything.

1. **Clone the repo**
   ```bash
   git clone https://github.com/nirw-snyk/airlock-demo.git
   cd airlock-demo
   ```

2. **Change the tenant ID in two files.** Both contain a `TODO` comment marking the spot. The tenant ID is the UUID after `/tenants/` in the URL.

   | File | Line to edit |
   | --- | --- |
   | `.npmrc` | `registry=https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/npm/` |
   | `pip.conf` | `index-url = https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/pypi/simple/` (must end in `/simple/`) |

   Or replace it in both files at once (`sed -i ''` is the macOS form; use `sed -i` on Linux):
   ```bash
   sed -i '' 's/8951eddb-f5c4-4564-986c-1373b4bcbc6a/<YOUR_TENANT_ID>/' .npmrc pip.conf
   ```
   Then delete the `TODO` comment lines. Leave the `BEGIN/END snyk-malicious-code-defense` markers in place, since Snyk tooling manages the lines between them. If your tenant uses a different host than `api.au.snyk.io`, update the host in both URLs too.

   `demo.sh` reads the proxy URL from these two files, so no script changes are needed. `package-lock.json` is git-ignored and regenerated on the first `npm install`, so it needs no edit.

3. **Add your credentials.** No token is committed to this repo.
   - **pip:** add an entry to `~/.netrc`. pip reads it automatically for basic auth.
     ```
     machine api.au.snyk.io
     login snyk
     password <your Snyk token>
     ```
   - **npm:** put the auth token in your user-level `~/.npmrc`, never in the project `.npmrc`.

4. **Check the config took effect**
   ```bash
   npm config get registry                                  # should print your tenant's npm URL
   PIP_CONFIG_FILE="$PWD/pip.conf" python3 -m pip config list   # should show your tenant's index-url
   ```

5. **Run the demo**: `./demo.sh --npm` or `./demo.sh --pypi` (see [Usage](#usage)).

## Prerequisites

- `bash`, `node` and `npm` (for `--npm`), `python3` and `pip` (for `--pypi`)
- A Snyk tenant with Malicious Code Defense enabled (dashboard: <https://app.au.snyk.io/malware>)
- A Snyk token for the proxy (see [Setup](#setup-start-here), step 3)

## Configuration

### Scope of the pip config

pip config is user-global by default, so `pip.conf` is deliberately not placed in pip's default location. `demo.sh --pypi` loads it via `PIP_CONFIG_FILE`, so only this demo's installs go through the proxy. To use it manually:

```bash
export PIP_CONFIG_FILE="$PWD/pip.conf"
```

### Tenant policies

The demo expects these policies on the tenant:

| Policy | Needed for |
| --- | --- |
| Known malware | Section 2 |
| Unmaintained (no release in 12+ months) | Section 3 |
| Cooldown (newly published versions held back) | Section 4 |
| Allow list entry for `object-assign` (npm) and `pep8` (PyPI), covering **all versions**, positioned below Known malware | Section 5 |

If the allow-list entry is missing, section 5 reports "Still blocked" instead of installing.

## Usage

```bash
./demo.sh --npm    # npm walkthrough
./demo.sh --pypi   # PyPI walkthrough
```

Run it from the project directory. The script pauses between sections; press Enter to continue.

| # | Section | npm | PyPI |
| --- | --- | --- | --- |
| 0 | Reset install artifacts | `rm -rf node_modules package-lock.json` | `rm -rf pip-demo-packages` |
| 1 | Normal install works through the proxy | `uuid`, `lodash`, `p-limit` | `packaging`, `certifi` |
| 2 | Known-malicious package blocked | `@onum-releases/ixel` | `maliciouseuropy` (see caveat below) |
| 3 | Unmaintained package blocked | `left-pad` | `nose` |
| 4 | Cooldown holds back the newest release | `@aws-sdk/client-s3` | `boto3` |
| 5 | Allow list overrides the unmaintained block | `object-assign` | `pep8` |
| 6 | Dashboard wrap-up | Install requests view | Install requests view |
| 7 | Summary table | | |

Blocked packages show up as `ENOVERSIONS` (npm) or "no matching distribution" (pip). The proxy strips every version before the client can resolve one. Blocked-package tests use `--no-save` (npm) and `--dry-run --no-deps` (pip) so nothing is installed or executed.

## Known limitations

- **PyPI malware demo is not proven.** `maliciouseuropy` has been removed from PyPI, so it 404s whether or not the policy engages. The summary table reports it as "Not proven". Replace `KNOWN_MALICIOUS_PKG` in `demo.sh` with a package that is still live on PyPI and covered by an active Snyk advisory (check with `curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/<name>/json`, which should return 200).
- **Cooldown targets drift.** If the public and proxy versions match, the release has aged past the cooldown window. Swap `COOLDOWN_PKG` for a package that released in the last few days.
- **Policy changes can break other packages.** A broad rule such as Unmaintained can catch packages used elsewhere in the script. After changing policy, re-check everything in `package.json` and `requirements.txt`.
- **Pick allow-list demo packages with zero dependencies.** A blocked transitive dependency fails the install even when the top-level package is allow-listed.
- `package-lock.json` is git-ignored, and `demo.sh` deletes it in section 0.
