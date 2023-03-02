#!/bin/bash

set -e

rm -rf custom_opal
mkdir custom_opal

if [ "$CUSTOM_OPAL" != "" ]
then
	tar -czf custom_opal/custom_opal.tar.gz -C "$CUSTOM_OPAL" --exclude opal-server --exclude '.*' packages README.md
fi
