#!/usr/bin/env bash
set -euo pipefail

quote_re() { sed -e 's/[^^]/[&]/g; s/\^/\\^/g; $!a\'$'\n''\\n' <<<"$1" | tr -d '\n'; }

# change to scripts directory
cd $(dirname "$0")
# change to base directory
cd ..

# make sure virtual env is active
if [ -z "${VIRTUAL_ENV:-}" ]; then
    source venv/bin/activate
fi

echo "Building requirements.txt"
echo "turbo-sticks[uwsgi] @ ." | uv pip compile - \
    -o requirements.txt \
    --no-emit-package setuptools \
    --no-header \
    --quiet \
    "$@"

# make a copy of the requirements.txt without the `-e .` target
# so we can use it as a constraints file
CONSTRAINTS=$(mktemp)
sed '/^\.$/d' requirements.txt > "${CONSTRAINTS}"

echo "Building test_requirements.txt"
echo "-e turbo-sticks[dev,uwsgi] @ ." | uv pip compile - \
    -c "${CONSTRAINTS}" \
    -o test_requirements.txt \
    --no-header \
    --quiet \
    "$@"

# rewrite the tmp path back to requirements.txt
sed -i "s/$(quote_re "${CONSTRAINTS}")/requirements.txt/" test_requirements.txt