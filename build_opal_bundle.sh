#!/bin/bash

set -e

rm -rf custom
mkdir custom

if [ "$CUSTOM_OPAL" != "" ]
then
  echo "Using custom OPAL from $CUSTOM_OPAL"
	tar -czf custom/custom_opal.tar.gz -C "$CUSTOM_OPAL" --exclude opal-server --exclude '.*' packages README.md
fi;

if [ "$CUSTOM_OPA" != "" ]
then
  echo "Using custom OPA from $CUSTOM_OPA"
  build_root="$PWD"
  cd "$CUSTOM_OPA"
  find * -name '*go*' -print0 | xargs -0 tar -czf "$build_root"/custom/custom_opa.tar.gz --exclude '.*'
  cd "$build_root"
fi
