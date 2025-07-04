#!/bin/bash
#
# Decrypts the checked-in IDA SDKs. In order to not leak the passphrase in the
# workflow log, it is set as an environment variable before being passed to
# GPG.

set -e

gpg --quiet --batch --yes --decrypt \
  "--passphrase=${IDASDK_SECRET}" \
  --output "${RUNNER_WORKSPACE}/build/idasdk91.zip" \
  "${GITHUB_WORKSPACE}/ida/idasdk/idasdk91.zip.gpg"

 gpg --quiet --batch --yes --decrypt \
  "--passphrase=${IDASDK_SECRET}" \
  --output "${RUNNER_WORKSPACE}/build/idasdk_teams82.zip" \
  "${GITHUB_WORKSPACE}/ida/idasdk/idasdk_teams82.zip.gpg"

