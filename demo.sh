#!/usr/bin/env bash
# Repeatable Malicious Code Defense (Airlock) demo script.
# Run from inside this project directory. Reads the proxy URL straight out
# of the local .npmrc/pip.conf so it stays correct even if the tenant/proxy changes.
set -euo pipefail

if [ $# -ne 1 ] || { [ "$1" != "--npm" ] && [ "$1" != "--pypi" ]; }; then
  echo "Usage: $0 --npm|--pypi" >&2
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
else
  run python3 -m pip install "$ALLOWED_UNMAINTAINED_PKG" --no-deps --target pip-demo-packages
fi
ALLOWED_INSTALL_STATUS=$?
set -e
if [ "$ALLOWED_INSTALL_STATUS" -eq 0 ]; then
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

section "7. Summary"
printf '%-42s %s\n' "Package(s)" "Outcome"
printf '%-42s %s\n' "------------------------------------------" "----------------------------------------------------"
for line in "${SUMMARY[@]}"; do
  echo "$line"
done
