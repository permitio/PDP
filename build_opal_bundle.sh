#!/bin/bash

set -e

# Set default value for PDP_VANILLA
PDP_VANILLA=${PDP_VANILLA:-"no"}

# Check if permit-opa directory already exists
if [ ! -d "../permit-opa" ]; then
  # Clone the permit-opa repository into the parent directory if it doesn't exist
  git clone git@github.com:permitio/permit-opa.git ../permit-opa
else
  echo "permit-opa directory already exists. Skipping clone operation."
fi

# Conditionally execute the custom OPA tarball creation section based on the value of PDP_VANILLA
if [ "$PDP_VANILLA" == "no" ]; then
  # Custom OPA tarball creation section
  rm -rf custom
  mkdir custom
  build_root="$PWD"
  cd "../permit-opa"
  find * -name '*go*' -print0 | xargs -0 tar -czf "$build_root"/custom/custom_opa.tar.gz --exclude '.*'
  cd "$build_root"
else
  echo "Skipping custom OPA tarball creation for pdp-vanilla environment."
fi
