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
  tar -czf custom/custom_opa.tar.gz -C "$CUSTOM_OPA" --exclude '.*' main.go types go.mod go.sum README.md
fi
