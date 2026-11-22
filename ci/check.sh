#!/bin/sh
# The project's checks, the same in CI and locally. Runs INSIDE the matching
# container (CLAUDE.md "Commands"), e.g.:
#   docker run --rm -v "$PWD:/src:ro" -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim sh ci/check.sh python
#   docker run --rm -v "$PWD:/src:ro" -w /src node:22-slim sh ci/check.sh js
set -eu
case "${1:-}" in
  python)
    pip install -q -r requirements-dev.txt
    python -m pytest -q
    ruff check --no-cache .
    mypy --cache-dir=/dev/null ;;
  js)
    npm install -g -s typescript@5.6.3
    tsc -p jsconfig.json
    node --test 'tests/js/*.test.js' ;;
  lock)
    # requirements.lock must match requirements.txt. Seeded with the current
    # lock, so pip-compile keeps its pins and only a changed requirements.txt
    # makes a difference (new upstream releases don't).
    pip install -q pip-tools==7.7.0
    cp requirements.lock /tmp/requirements.lock
    pip-compile -q --generate-hashes --strip-extras --allow-unsafe --no-header \
      --output-file=/tmp/requirements.lock requirements.txt
    diff -u requirements.lock /tmp/requirements.lock \
      || { echo "requirements.lock is out of date: regenerate it (README, Docker)." >&2; exit 1; } ;;
  *) echo "usage: ci/check.sh python|js|lock" >&2; exit 2 ;;
esac
