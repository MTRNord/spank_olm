#!/bin/sh

set -e

ret=0

for fuzzer in *_fuzzer; do
  exit_code=0
  "./${fuzzer}" || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo FAIL "${fuzzer}"
    ret=1
  fi
done

exit $ret