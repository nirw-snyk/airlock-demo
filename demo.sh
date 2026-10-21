#!/usr/bin/env bash
# Repeatable Malicious Code Defense (Airlock) demo script.
# Run from inside this project directory. Reads the proxy URL straight out
# of the local .npmrc/pip.conf/go.env so it stays correct even if the tenant/proxy changes.
set -euo pipefail

if [ $# -ne 1 ] || { [ "$1" != "--npm" ] && [ "$1" != "--pypi" ] && [ "$1" != "--go" ]; }; then
  echo "Usage: $0 --npm|--pypi|--go" >&2
  exit 1
fi
ECOSYSTEM="${1#--}"

PORTAL_URL="https://app.au.snyk.io/malware"

pause() { read -rp "-- press enter to continue --" _; }
section() { echo; echo "=== $1 ==="; echo; }
SUMMARY=()
# Records one row for the closing summary table. Called with the real,
# just-observed outcome -- never an assumed one -- so the table reflects what
# this run actually did, not what the script expected to happen.
summarize() { SUMMARY+=("$(printf '%-42s %s' "$1" "$2")"); }
# Echoes the command like a shell prompt, then actually runs it.
run() { printf '\n$ %s\n' "$*"; "$@"; }
# Prints "<public-version>|<proxy-version>" for a given npm package.
npm_compare_versions() {
  local pkg="$1" pub proxy
  printf '\n$ %s\n' "npm view $pkg version --registry $PUBLIC_URL" >&2
  pub=$(npm view "$pkg" version --registry "$PUBLIC_URL")
  printf '\n$ %s\n' "npm view $pkg version --registry \$PROXY_URL" >&2
  proxy=$(npm view "$pkg" version --registry "$PROXY_URL" 2>/dev/null || echo "(none resolved)")
  echo "${pub}|${proxy}"
}
# Go only. Succeeds if the public Go proxy can resolve the module, which lets a
# failed proxy lookup be told apart from a module that simply doesn't exist.
go_public_resolves() { GOPROXY="$PUBLIC_URL" go list -m "$1@latest" >/dev/null 2>&1; }
# Go only. Prints the version `go list -m` resolves for a module via $1 (a GOPROXY value).
go_latest_via() { GOPROXY="$1" go list -m "$2@latest" 2>/dev/null | awk '{print $2}' || true; }
# Go only. Fetches $1@latest through the proxy and sets GO_RESULT to:
#   ok            -- the proxy served it
#   blocked       -- the proxy refused it but the public proxy resolves it
#   unresolvable  -- both failed, so the module may simply not exist (proves nothing)
go_try() {
  local out status
  set +e
  out=$(run go mod download "$1@latest" 2>&1)
  status=$?
  set -e
  echo "$out"
  if [ "$status" -eq 0 ]; then GO_RESULT=ok
  elif go_public_resolves "$1"; then GO_RESULT=blocked
  else GO_RESULT=unresolvable
  fi
}
# Go only. Deletes everything `go mod download` left in the module cache for
# $1@latest: the extracted source tree and the cached zip/.mod/.info. Paths come
# from Go itself (-json) and are only removed if they sit inside $GOMODCACHE.
go_delete_downloaded() {
  local json dir zip
  json=$(go mod download -json "$1@latest" 2>/dev/null) || return 0
  dir=$(printf '%s\n' "$json" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",\{0,1\}$/\1/p')
  zip=$(printf '%s\n' "$json" | sed -n 's/^[[:space:]]*"Zip": "\(.*\)",\{0,1\}$/\1/p')
  [ -n "$zip" ] && zip=$(dirname "$(dirname "$zip")")   # cache/download/<module path>
  local p
  for p in "$dir" "$zip"; do
    case "$p" in
      "$GOMODCACHE"/?*) run rm -rf "$p" ;;
    esac
  done
}
# Whether section 3 actually observed the unmaintained block. npm/pypi assume
# it; Go sets it from the real outcome so section 5 can't claim an override of
# a block that never happened.
UNMAINTAINED_BLOCK_OBSERVED=1

if [ "$ECOSYSTEM" = "npm" ]; then
  PROXY_URL=$(grep '^registry=' .npmrc | head -1 | cut -d= -f2-)
  PUBLIC_URL="https://registry.npmjs.org/"
  KNOWN_MALICIOUS_PKG="@onum-releases/ixel"
  # last published 2024-04-16 (per `npm view left-pad time.modified --registry
  # https://registry.npmjs.org/`), so it's been well past the 12-month
  # unmaintained window for a while. Confirmed still hard-blocked (ENOVERSIONS)
  # through this tenant's proxy as of 2026-09-13.
  UNMAINTAINED_PKG="left-pad"
  # @aws-sdk/client-s3 is AWS-bot-published on a ~24h median cadence (checked
  # over its last 60 releases on 2026-09-13: median gap ~24h, 8/59 gaps >72h),
  # the most reliable "always has something inside the cooldown window"
  # candidate found -- not a 100% guarantee (rare gaps up to ~a week can still
  # let it fully catch up to public, same as eslint did), but needs far less
  # manual upkeep than a slower-moving package like eslint.
  COOLDOWN_PKG="@aws-sdk/client-s3"
  # object-assign (zero dependencies, last published 2017-01-16, obsolete
  # since Object.assign became native) is a permanent allow-list override
  # target: distinct from left-pad (which must stay blocked to demo section 3),
  # and never "ages back into" being fresh the way a cooldown-based target
  # would, so this needs no periodic upkeep. Deliberately zero-dependency --
  # an earlier attempt with is-odd allow-listed only is-odd itself, but
  # is-odd@3.0.1 depends on is-number (also last released 2018, also caught
  # by the unmaintained rule), so the install still failed on the transitive
  # dependency. Requires an Allow-list policy entry for object-assign (all
  # versions) positioned to override the Unmaintained rule -- not yet
  # confirmed added on this tenant as of 2026-09-13.
  ALLOWED_UNMAINTAINED_PKG="object-assign"
elif [ "$ECOSYSTEM" = "go" ]; then
  command -v go >/dev/null || { echo "go not found on PATH (install from https://go.dev/dl/)" >&2; exit 1; }
  SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  PROXY_URL=$(grep '^GOPROXY=' go.env | head -1 | cut -d= -f2-)
  PUBLIC_URL="https://proxy.golang.org"
  # GOENV scopes go.env to this demo (same idea as PIP_CONFIG_FILE). GOPROXY is
  # also exported directly because a GOPROXY already set in your shell would
  # beat the GOENV file and silently route around the proxy. GOMODCACHE is
  # project-local so a module cached by earlier work on this machine can't make
  # an install succeed without ever asking the proxy; -modcacherw keeps it
  # deletable by section 0.
  export GOENV="$SCRIPT_DIR/go.env" GOPROXY="$PROXY_URL"
  export GOMODCACHE="$SCRIPT_DIR/go-mod-cache" GOFLAGS=-modcacherw
  # Section 2 may download the malicious module's files when the proxy doesn't
  # block it. Delete the whole cache on any exit (including Ctrl-C) so they
  # never linger on disk after the demo.
  trap 'rm -rf "$SCRIPT_DIR/go-mod-cache"' EXIT
  # Real malicious module from the OpenSSF malicious-packages dataset (most of
  # the others there 403 on proxy.golang.org itself, so they can't show a Snyk
  # block). Snyk DOES have an advisory for it (SNYK-GOLANG-GITHUBCOMBUFFERZONECORP
  # NETHELPER-16643554, shown as "This is a malicious package" on
  # security.snyk.io), yet through this tenant's proxy it was still served in
  # full on 2026-10-15, same as public -- so the gap is the tenant's Go malware
  # policy/enforcement, not missing advisory data. Section 2 reports what
  # actually happens either way. `go mod download` only fetches the module
  # files; Go never builds or runs a module at download time.
  KNOWN_MALICIOUS_PKG="github.com/bufferzonecorp/net-helper"
  # Section 1 modules are pinned in go.mod (compress v1.19.1 2026-07-20, x/term
  # v0.45.0 2026-07-08 -> its one dependency x/sys v0.47.0 2026-06-30) so they
  # are past the cooldown window (10-20 days here) yet within 12 months, and
  # all three modules released again within the last month. That keeps them out
  # of both the Cooldown and Unmaintained rules. Re-pick when they age out.
  # Archived, zero dependencies, last release 2019-01-27. Verified blocked
  # 2026-10-15 once the 12-month Unmaintained policy was on (403 "blocked by
  # Snyk policy: package has not had a release in the last 12 months").
  # pkg/errors (2020), go-spew (2018), gorilla/mux and google/uuid are also
  # stale but are still served -- very popular modules seem to be exempt -- so
  # always verify a candidate against the proxy before using it here.
  UNMAINTAINED_PKG="github.com/mitchellh/go-homedir"
  # AWS publishes these modules several times a week, so there's usually a
  # release still inside the cooldown window. service/s3 caught up to public by
  # 2026-10-21, so this is now service/dynamodb (held 2 minor versions back on
  # that date: proxy v1.70.3, public v1.72.0). Swap again if the two match.
  COOLDOWN_PKG="github.com/aws/aws-sdk-go-v2/service/dynamodb"
  # Zero dependencies, last release 2022-04-20, archived. Distinct from
  # go-homedir (which must stay blocked for section 3). Zero deps matters: a
  # blocked transitive dependency fails the install even when the top-level
  # module is allow-listed. Requires an Allow-list entry for
  # github.com/mitchellh/mapstructure (all versions) below Known malware.
  ALLOWED_UNMAINTAINED_PKG="github.com/mitchellh/mapstructure"
else
  SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  export PIP_CONFIG_FILE="$SCRIPT_DIR/pip.conf"
  PROXY_URL=$(grep '^index-url' pip.conf | head -1 | sed -E 's/^index-url *= *//')
  PUBLIC_URL="https://pypi.org/simple/"
  # TEMPORARY test value -- maliciouseuropy is confirmed 404/removed from PyPI
  # (verified via https://pypi.org/pypi/maliciouseuropy/json), so this is
  # expected to just 404 through both public and proxy, NOT demonstrate an
  # actual block. Every other candidate found while researching this
  # (sentinelone, pingdomv3, cdm-one, torchtriton, ctx) is also gone. Replace
  # with a package confirmed (a) still live on PyPI and (b) covered by an
  # active Snyk malicious-package advisory once one is found.
  KNOWN_MALICIOUS_PKG="maliciouseuropy"
  # Unmaintained policy for pypi is live on this tenant as of 2026-09-13
  # (confirmed after being enabled) -- it's a genuine age-based rule, not a
  # curated per-package list: every stale-but-still-published candidate tested
  # (nose, pep8, pycrypto, unittest2, pathlib2, enum34,
  # backports.functools_lru_cache, pytest-runner) is now blocked, matching
  # npm's left-pad behavior. `nose` (last release 2015-06-02, superseded by
  # pytest/nose2) is used here for recognizability.
  # NOTE: this rule also swept up `six` (last release 2024-12-04), which used
  # to be requirements.txt's "normal install" proof package -- swapped for
  # `packaging` (actively released) there and in section 1 below so the
  # normal-install path still passes.
  UNMAINTAINED_PKG="nose"
  COOLDOWN_PKG="boto3"
  # pep8 (zero real dependencies -- requires_dist is empty per PyPI metadata,
  # confirmed via `curl -s https://pypi.org/pypi/pep8/json`; last release
  # 2017-10-24, superseded by pycodestyle) is a permanent allow-list override
  # target, distinct from `nose` (which must stay blocked to demo section 3).
  # Requires an Allow-list policy entry for pep8 (all versions) positioned to
  # override the Unmaintained rule -- not yet confirmed added on this tenant.
  ALLOWED_UNMAINTAINED_PKG="pep8"
fi

section "0. Reset to a clean slate"
if [ "$ECOSYSTEM" = "npm" ]; then
  run rm -rf node_modules package-lock.json
elif [ "$ECOSYSTEM" = "go" ]; then
  run rm -rf go-mod-cache go.sum
else
  run rm -rf pip-demo-packages
fi
echo "Proxy in use: $PROXY_URL"
pause

section "1. Prove it's a live, working registry"
if [ "$ECOSYSTEM" = "npm" ]; then
  run npm install
  echo "-> uuid, lodash, and p-limit (plus its yocto-queue dependency)"
  echo "   installed normally through the proxy."
  summarize "uuid, lodash, p-limit+yocto-queue" "Installed normally -- no policy match"
elif [ "$ECOSYSTEM" = "go" ]; then
  run go mod tidy
  run go run .
  echo "-> klauspost/compress, and x/term plus its one dependency x/sys, downloaded"
  echo "   and built through the proxy."
  summarize "klauspost/compress, x/term+x/sys" "Installed normally -- no policy match"
else
  run python3 -m pip install --target pip-demo-packages -r requirements.txt
  echo "-> packaging and certifi installed normally through the proxy."
  summarize "packaging, certifi" "Installed normally -- no policy match"
fi
pause

section "2. Known-malicious package: blocked outright"
if [ "$ECOSYSTEM" = "pypi" ] && [ -z "$KNOWN_MALICIOUS_PKG" ]; then
  echo "No confirmed still-published PyPI malicious-package target is set yet."
  echo "Fill in KNOWN_MALICIOUS_PKG in demo.sh with a package you've verified is"
  echo "still live on PyPI AND covered by an active Snyk malicious-package"
  echo "advisory, then re-run. Skipping this section for now."
  summarize "(none set)" "Skipped -- no confirmed live PyPI malware target"
else
  echo "Package: $KNOWN_MALICIOUS_PKG"
  if [ "$ECOSYSTEM" = "npm" ]; then
    echo "This is a real, currently-published npm package with an active Snyk"
    echo "malicious-package advisory (dependency-confusion / scope-takeover PoC)."
    set +e
    run npm install "$KNOWN_MALICIOUS_PKG" --no-save
    set -e
    echo "-> ENOVERSIONS: the proxy stripped every version before npm could see it."
    summarize "$KNOWN_MALICIOUS_PKG" "Blocked -- known malware rule (ENOVERSIONS)"
  elif [ "$ECOSYSTEM" = "go" ]; then
    echo "This is a real, currently-published Go module from the OpenSSF"
    echo "malicious-packages dataset. 'go mod download' only fetches it; Go never"
    echo "builds or runs a module at download time."
    go_try "$KNOWN_MALICIOUS_PKG"
    case "$GO_RESULT" in
      blocked)
        echo "-> The proxy refused a module the public Go proxy serves normally."
        summarize "$KNOWN_MALICIOUS_PKG" "Blocked -- known malware rule" ;;
      ok)
        echo "-> NOT blocked: the proxy served it exactly like the public proxy does."
        echo "   Snyk has a malicious-package advisory for this module (see"
        echo "   security.snyk.io), so the Known malware policy isn't being enforced for"
        echo "   Go on this tenant yet. Nothing was built or run: the module files were"
        echo "   only fetched into go-mod-cache/."
        echo
        echo "Since nothing stopped the download, delete the malicious module's files now:"
        go_delete_downloaded "$KNOWN_MALICIOUS_PKG"
        summarize "$KNOWN_MALICIOUS_PKG" "NOT blocked -- proxy served it (no malware policy hit)" ;;
      *)
        echo "-> Failed on both proxies, so this doesn't prove the malware rule engaged."
        summarize "$KNOWN_MALICIOUS_PKG" "Not proven -- unresolvable on the public Go proxy too" ;;
    esac
  else
    echo "This is a real, currently-published PyPI package with an active Snyk"
    echo "malicious-package advisory. --dry-run resolves the install without"
    echo "actually installing/executing anything."
    set +e
    # --target (not actually written to since --dry-run is set) is required
    # here so pip doesn't refuse the install outright under PEP 668
    # (externally-managed-environment) on systems like Homebrew's Python.
    run python3 -m pip install "$KNOWN_MALICIOUS_PKG" --dry-run --no-deps --target pip-demo-packages
    set -e
    echo "-> the proxy's index omitted every version before pip could resolve one."
    echo "   NOTE: $KNOWN_MALICIOUS_PKG is confirmed 404/removed from PyPI"
    echo "   entirely, so this doesn't actually prove the malware rule engaged --"
    echo "   see the KNOWN_MALICIOUS_PKG comment in demo.sh for a still-live"
    echo "   replacement once one is found."
    summarize "$KNOWN_MALICIOUS_PKG" "Not proven -- package is 404/removed upstream, not confirmed blocked"
  fi
fi
pause

section "3. Unmaintained package (no release in 12+ months): blocked"
if [ -z "$UNMAINTAINED_PKG" ]; then
  echo "No confirmed unmaintained-policy target is set for this ecosystem yet."
  echo "Fill in UNMAINTAINED_PKG in demo.sh with a package added to the"
  echo "Unmaintained policy on this tenant, then re-run. Skipping for now."
  summarize "(none set)" "Skipped -- no confirmed unmaintained-policy target"
else
  echo "Package: $UNMAINTAINED_PKG"
  if [ "$ECOSYSTEM" = "npm" ]; then
    echo "This is a real, currently-published npm package with no release in"
    echo "well over 12 months -- flagged by the Unmaintained policy, not by"
    echo "reputation or malware signatures."
    set +e
    run npm install "$UNMAINTAINED_PKG" --no-save
    set -e
    echo "-> ENOVERSIONS: same block signature as known-malware, but this time"
    echo "   triggered by staleness, not a malicious-package advisory."
    summarize "$UNMAINTAINED_PKG" "Blocked -- unmaintained rule, 12+ months stale (ENOVERSIONS)"
  elif [ "$ECOSYSTEM" = "go" ]; then
    echo "This is a real, currently-published Go module with no release in years"
    echo "-- flagged by the Unmaintained policy, not by reputation or malware"
    echo "signatures."
    go_try "$UNMAINTAINED_PKG"
    case "$GO_RESULT" in
      blocked)
        echo "-> Refused by the proxy though the public Go proxy serves it, this time"
        echo "   triggered by staleness, not a malicious-package advisory."
        summarize "$UNMAINTAINED_PKG" "Blocked -- unmaintained rule, 12+ months stale" ;;
      ok)
        UNMAINTAINED_BLOCK_OBSERVED=0
        echo "-> NOT blocked: the proxy served it. The Unmaintained policy isn't"
        echo "   enforced for Go on this tenant yet, so section 5 can't show an"
        echo "   override either."
        summarize "$UNMAINTAINED_PKG" "NOT blocked -- unmaintained rule not enforced for Go" ;;
      *)
        UNMAINTAINED_BLOCK_OBSERVED=0
        echo "-> Failed on both proxies, so this doesn't prove the unmaintained rule engaged."
        summarize "$UNMAINTAINED_PKG" "Not proven -- unresolvable on the public Go proxy too" ;;
    esac
  else
    echo "This is a real, currently-published PyPI package flagged by the"
    echo "Unmaintained policy. --dry-run resolves the install without actually"
    echo "installing/executing anything."
    set +e
    run python3 -m pip install "$UNMAINTAINED_PKG" --dry-run --no-deps --target pip-demo-packages
    set -e
    echo "-> the proxy's index omitted every version before pip could resolve one."
    summarize "$UNMAINTAINED_PKG" "Blocked -- unmaintained rule, 12+ months stale"
  fi
fi
pause

section "4. Cooldown policy: brand-new versions held regardless of reputation"
if [ "$ECOSYSTEM" = "npm" ]; then
  IFS='|' read -r LATEST_PUBLIC LATEST_PROXY <<< "$(npm_compare_versions "$COOLDOWN_PKG")"
elif [ "$ECOSYSTEM" = "go" ]; then
  printf '\n$ %s\n' "GOPROXY=$PUBLIC_URL go list -m $COOLDOWN_PKG@latest"
  LATEST_PUBLIC=$(go_latest_via "$PUBLIC_URL" "$COOLDOWN_PKG")
  printf '\n$ %s\n' "GOPROXY=\$PROXY_URL go list -m $COOLDOWN_PKG@latest"
  LATEST_PROXY=$(go_latest_via "$PROXY_URL" "$COOLDOWN_PKG")
  LATEST_PROXY="${LATEST_PROXY:-(none resolved)}"
else
  printf '\n$ %s\n' "python3 -m pip index versions $COOLDOWN_PKG --index-url $PUBLIC_URL"
  # Capture pip's full output before slicing it with head/sed -- piping pip's
  # live stdout straight into `head -1` triggers SIGPIPE once head closes the
  # pipe after one line, which makes pip exit non-zero and (under pipefail +
  # set -e) kills the whole script right here.
  RAW_PUBLIC=$(python3 -m pip index versions "$COOLDOWN_PKG" --index-url "$PUBLIC_URL" 2>/dev/null)
  LATEST_PUBLIC=$(echo "$RAW_PUBLIC" | head -1 | sed -E 's/.*\(([^)]+)\).*/\1/')
  printf '\n$ %s\n' "python3 -m pip index versions $COOLDOWN_PKG --index-url \$PROXY_URL"
  RAW_PROXY=$(python3 -m pip index versions "$COOLDOWN_PKG" --index-url "$PROXY_URL" 2>/dev/null)
  LATEST_PROXY=$(echo "$RAW_PROXY" | head -1 | sed -E 's/.*\(([^)]+)\).*/\1/')
  LATEST_PROXY="${LATEST_PROXY:-(none resolved)}"
fi
echo "Public registry latest : $LATEST_PUBLIC"
echo "Proxy-served latest    : $LATEST_PROXY"
if [ "$LATEST_PUBLIC" != "$LATEST_PROXY" ]; then
  echo "-> The newest release of a completely trustworthy, widely-used package"
  echo "   ($COOLDOWN_PKG) is being held back purely because it hasn't cleared"
  echo "   the cooldown window yet -- this is the safety net for a compromised"
  echo "   maintainer account pushing a malicious release."
  summarize "$COOLDOWN_PKG" "Held -- cooldown rule (proxy: $LATEST_PROXY, public: $LATEST_PUBLIC)"
else
  echo "-> Versions match right now, meaning $LATEST_PUBLIC has aged past the"
  echo "   cooldown window since this script was last updated. Check"
  echo "   $COOLDOWN_PKG's release history for a version published in just the"
  echo "   last few days, swap COOLDOWN_PKG, or pick a different fast-moving"
  echo "   package."
  summarize "$COOLDOWN_PKG" "Not held right now -- aged past cooldown window (both at $LATEST_PUBLIC)"
fi
pause

section "5. Policy override: allow list bypasses the unmaintained block"
echo "Package: $ALLOWED_UNMAINTAINED_PKG"
echo "Like $UNMAINTAINED_PKG above, this package has had no release in years and"
echo "would normally be blocked by the Unmaintained rule -- but it also has an"
echo "explicit Allow-list policy entry (Malicious Code Defense > Policy,"
echo "positioned below Known malware) covering all versions, so it installs"
echo "anyway."
set +e
if [ "$ECOSYSTEM" = "npm" ]; then
  run npm install "$ALLOWED_UNMAINTAINED_PKG" --no-save
elif [ "$ECOSYSTEM" = "go" ]; then
  run go mod download "$ALLOWED_UNMAINTAINED_PKG@latest"
else
  run python3 -m pip install "$ALLOWED_UNMAINTAINED_PKG" --no-deps --target pip-demo-packages
fi
ALLOWED_INSTALL_STATUS=$?
set -e
if [ "$ALLOWED_INSTALL_STATUS" -eq 0 ] && [ "$UNMAINTAINED_BLOCK_OBSERVED" -eq 0 ]; then
  echo "-> Installed, but that proves nothing: $UNMAINTAINED_PKG wasn't blocked in"
  echo "   section 3, so there was no unmaintained block for the allow list to"
  echo "   override. Re-run once the Unmaintained policy is enforced for $ECOSYSTEM."
  summarize "$ALLOWED_UNMAINTAINED_PKG" "Installed -- override not proven (no unmaintained block to override)"
elif [ "$ALLOWED_INSTALL_STATUS" -eq 0 ]; then
  echo "-> Installed successfully despite being unmaintained: the allow-list"
  echo "   entry overrode the same rule that blocked $UNMAINTAINED_PKG above."
  summarize "$ALLOWED_UNMAINTAINED_PKG" "Installed -- allow-list overrides unmaintained rule"
else
  echo "-> Still blocked (ENOVERSIONS / no matching distribution), so the"
  echo "   allow-list entry for $ALLOWED_UNMAINTAINED_PKG isn't in effect yet."
  echo "   Add it under Malicious Code Defense > Policy > Allow list -- cover"
  echo "   'all versions', and keep it positioned below the Known malware policy."
  summarize "$ALLOWED_UNMAINTAINED_PKG" "Still blocked -- allow-list entry not in effect yet"
fi
pause

section "6. Wrap up in the dashboard"
echo "Switch to $PORTAL_URL -> Install requests on the demo tenant."
if [ "$ECOSYSTEM" = "go" ]; then
  echo "Show the requests from this run; the summary below lists what each module actually did."
  MSG=""
else
MSG="Show: normal deps served, "
if [ -z "$KNOWN_MALICIOUS_PKG" ]; then
  MSG+="the malicious-package block wasn't run this time (see section 2), "
else
  MSG+="$KNOWN_MALICIOUS_PKG blocked (known malware rule), "
fi
if [ -z "$UNMAINTAINED_PKG" ]; then
  MSG+="the unmaintained-package block wasn't run this time (see section 3), "
else
  MSG+="$UNMAINTAINED_PKG blocked (unmaintained rule), "
fi
MSG+="$COOLDOWN_PKG held (cooldown rule), $ALLOWED_UNMAINTAINED_PKG let"
MSG+=" through despite being just as unmaintained (allow-list policy"
MSG+=" override) -- five different outcomes, one proxy."
echo "$MSG"
fi

section "7. Summary"
printf '%-42s %s\n' "Package(s)" "Outcome"
printf '%-42s %s\n' "------------------------------------------" "----------------------------------------------------"
for line in "${SUMMARY[@]}"; do
  echo "$line"
done
if [ "$ECOSYSTEM" = "go" ]; then
  echo
  echo "Cleanup: go-mod-cache/ (including any module section 2 downloaded) is deleted on exit."
fi
