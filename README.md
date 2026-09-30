# Airlock Demo

A scripted walkthrough of Snyk **Malicious Code Defense** (internally "Airlock"), a registry proxy that filters npm and PyPI packages against your security policy before they reach `npm install` or `pip install`.

`demo.sh` runs the same walkthrough for either ecosystem and prints a summary table of what actually happened.

## Prerequisites

- `bash`, `node` and `npm` (for `--npm`), `python3` and `pip` (for `--pypi`)
- A Snyk tenant with Malicious Code Defense enabled (dashboard: <https://app.au.snyk.io/malware>)
- PyPI support is private preview and opt-in per tenant. Confirm it's enabled on yours before running `--pypi`.
- A Snyk token for the proxy (see [Authentication](#authentication))

## Configuration

### 1. Set your tenant ID

Replace the tenant ID in the registry URLs with your own:

| File | Setting |
| --- | --- |
| `.npmrc` | `registry=https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/npm/` |
| `pip.conf` | `index-url = https://api.au.snyk.io/hidden/tenants/<TENANT_ID>/registry/pypi/simple/` (path must end in `/simple/`) |

`demo.sh` reads the proxy URL from these files, so nothing else needs editing. Keep the `BEGIN/END snyk-malicious-code-defense` marker comments; the Snyk tooling manages the lines between them.

### 2. Authentication

No token is committed to this repo.

- **pip:** add an entry to `~/.netrc`. pip reads it automatically for basic auth.
  ```
  machine api.au.snyk.io
  login snyk
  password <your Snyk token>
  ```
- **npm:** put the token in your user-level `~/.npmrc`, not the project `.npmrc`.

### 3. Scope of the pip config

pip config is user-global by default, so `pip.conf` is deliberately not placed in pip's default location. `demo.sh --pypi` loads it via `PIP_CONFIG_FILE`, so only this demo's installs go through the proxy. To use it manually:

```bash
export PIP_CONFIG_FILE="$PWD/pip.conf"
```

### 4. Tenant policies

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
| 1 | Normal install works through the proxy | `nanoid`, `lodash`, `p-limit` | `packaging`, `certifi` |
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
