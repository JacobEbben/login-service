#!/usr/bin/env bash
# Smoke test of a built image, from the outside: starts it like production
# (read-only, no capabilities) and checks what unit tests can't see.
#   deploy/smoke-image.sh <image>
set -euo pipefail
IMAGE="${1:?usage: smoke-image.sh <image>}"
NAME="ls-smoke-$$"
PORT="${SMOKE_PORT:-18081}"
ISSUER="https://login.smoke.invalid"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { echo "SMOKE FAIL: $*" >&2; docker logs --tail 30 "$NAME" >&2 || true; exit 1; }

docker run -d --name "$NAME" --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -v /app/data -p "127.0.0.1:$PORT:8080" -e ISSUER="$ISSUER" \
  -e SECRET_KEY="smoke-test-secret-key-$(date +%s%N)-not-real" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/healthz" 2>/dev/null && break
  sleep 1
done
curl -fsS -o /dev/null "http://127.0.0.1:$PORT/healthz" || fail "/healthz does not answer"

headers="$(curl -fsS -D - -o /dev/null "http://127.0.0.1:$PORT/login")"
grep -qi "^content-security-policy: default-src 'none'" <<< "$headers" || fail "no strict CSP on /login"
grep -qi "^strict-transport-security:" <<< "$headers" || fail "no HSTS"
grep -qi "^set-cookie: __Host-ls_session=" <<< "$headers" || fail "session cookie is not a __Host- cookie"
grep -qi '^server:' <<< "$headers" && fail "a Server header is sent"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[[ "$(code "http://127.0.0.1:$PORT/admin/")" == 404 ]] || fail "/admin is reachable without signing in"
curl -fsS "http://127.0.0.1:$PORT/.well-known/openid-configuration" | grep -q "\"issuer\":\"$ISSUER\"" \
  || curl -fsS "http://127.0.0.1:$PORT/.well-known/openid-configuration" | grep -q "\"issuer\": \"$ISSUER\"" || fail "discovery has the wrong issuer"
curl -fsS "http://127.0.0.1:$PORT/jwks.json" | grep -q '"RS256"' || fail "no signing key published"
docker exec "$NAME" sh -c 'touch /app/login_service/x' 2>/dev/null && fail "the code folder is writable"
docker exec "$NAME" sh -c 'test -s /app/data/keys/signing-key.pem' || fail "signing key not generated in the data volume"
docker exec "$NAME" sh -c 'test ! -e /app/data/secret.key' || fail "SECRET_KEY must come from the environment, not the volume"
docker run --rm --read-only -e ISSUER="$ISSUER" "$IMAGE" python -c "import login_service; login_service.create_app()" >/dev/null 2>&1 \
  && fail "production started without SECRET_KEY"
[[ "$(docker exec "$NAME" stat -c %a /app/data/keys/signing-key.pem)" == 600 ]] || fail "signing key is not private"
[[ "$(docker inspect --format '{{.Config.User}}' "$IMAGE")" == app ]] || fail "the image does not run as the app user"
echo "smoke test passed: $IMAGE"
