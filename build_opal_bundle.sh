#!/bin/bash

set -euo pipefail

# Check if PDP_VANILLA is set to true from command line argument
if [ "${PDP_VANILLA:-}" == "true" ]; then
  echo "Building for pdp-vanilla environment."
fi

# CI and releases compile permit-opa at the commit pinned in tests.yml (the `ref:` of the
# permitio/permit-opa checkout step; release.yml must match it). Build the same commit
# here, so a local image carries the OPA that ships.
pin=$(awk '/repository:[[:space:]]*permitio\/permit-opa/ {f=1; next}
           f && /ref:/ {gsub(/["\047]/, "", $2); print $2; exit}' .github/workflows/tests.yml)
if ! [[ $pin =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: could not read the permit-opa pin from .github/workflows/tests.yml" >&2
  exit 1
fi

if [ ! -d "../permit-opa" ]; then
  git clone git@github.com:permitio/permit-opa.git ../permit-opa
  git -C ../permit-opa -c advice.detachedHead=false checkout --quiet "$pin"
else
  echo "permit-opa directory already exists. Skipping clone operation."
fi

# An existing checkout is left where it is (you may be testing a permit-opa branch on
# purpose), but say when it is not the commit CI and releases build.
head=$(git -C ../permit-opa rev-parse HEAD)
if [ "$head" != "$pin" ]; then
  echo "warning: ../permit-opa is at $head; CI and releases build $pin" >&2
fi

# Always start from an empty custom/: a tarball left over from an earlier run would
# otherwise be what a vanilla build ships.
rm -rf custom
mkdir custom

# Conditionally execute the custom OPA tarball creation section based on the value of PDP_VANILLA
if [ "${PDP_VANILLA:-}" != "true" ]; then
  # Custom OPA tarball creation section
  build_root="$PWD"
  cd "../permit-opa"
  find * \( -name '*go*' -o -name 'LICENSE.md' \) -print0 | xargs -0 tar -czf "$build_root"/custom/custom_opa.tar.gz --exclude '.*'
  cd "$build_root"
  echo "Custom OPA tarball created successfully."
else
  echo "Skipping custom OPA tarball creation for pdp-vanilla environment."
  echo "Build the image with --build-arg OPA_BUILD=vanilla (the default, permit, needs the tarball)."
fi
