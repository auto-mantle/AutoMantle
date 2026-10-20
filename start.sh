#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ $(uname -s) != Linux ]]; then
    echo 'Run this command inside Linux or WSL Ubuntu.' >&2
    exit 1
fi
for tool in curl tar ss; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
if command -v docker >/dev/null && docker version >/dev/null 2>&1; then
    docker_cmd=(docker)
elif command -v docker.exe >/dev/null && docker.exe version >/dev/null 2>&1; then
    docker_cmd=(docker.exe)
else
    echo 'Docker Engine is required to build and export the bundled Java runtime.' >&2
    exit 1
fi
"${docker_cmd[@]}" info >/dev/null || {
    echo 'Docker is unavailable. Start Docker Engine or Docker Desktop.' >&2
    exit 1
}

if [[ ! -e .env ]]; then
    (umask 077; set -o noclobber; cat .env.example > .env)
    echo 'Created private local configuration in .env.'
fi
port=${PORT:-$(sed -n 's/^PORT=//p' .env | tail -n 1 | tr -d '\r')}
port=${port:-8082}
if [[ ! $port =~ ^[0-9]{1,5}$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
    echo 'PORT must be an unquoted number between 1 and 65535.' >&2
    exit 1
fi
if [[ -n $(ss -H -ltn "sport = :$port") ]]; then
    echo "Port $port is already in use. Stop that app or change PORT in .env." >&2
    exit 1
fi

"${docker_cmd[@]}" build --tag automantle-oss-app --file api/Dockerfile .

runtime="$PWD/.runtime"
mkdir -p "$runtime"
image_id=$("${docker_cmd[@]}" image inspect --format '{{.Id}}' automantle-oss-app | tr -d '\r')
if [[ ! -f $runtime/image-id || $(cat "$runtime/image-id") != "$image_id" ]]; then
    "${docker_cmd[@]}" run --rm --entrypoint tar automantle-oss-app \
        -ch -C / app/app.jar opt/java/openjdk | tar -x -C "$runtime"
    printf '%s\n' "$image_id" > "$runtime/image-id"
fi

app_pid=''
cleanup() {
    if [[ -n $app_pid ]]; then
        kill "$app_pid" 2>/dev/null || true
        wait "$app_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$runtime/opt/java/openjdk/bin/java" --enable-native-access=ALL-UNNAMED -Djava.net.preferIPv4Stack=true -jar "$runtime/app/app.jar" \
    '--spring.config.import=file:./.env[.properties]' &
app_pid=$!
ready=false
for ((attempt=0; attempt<90; attempt++)); do
    if ! kill -0 "$app_pid" 2>/dev/null; then
        wait "$app_pid" || true
        echo 'The application exited before becoming ready. See its output above.' >&2
        exit 1
    fi
    if curl --fail --silent --max-time 2 "http://127.0.0.1:$port/" >/dev/null; then
        ready=true
        break
    fi
    sleep 1
done
if [[ $ready != true ]]; then
    echo 'The application did not become ready on loopback within 90 seconds.' >&2
    exit 1
fi
printf '\nAutomantle is ready at http://localhost:%s\n' "$port"
echo 'Keep this terminal open. Ctrl+C stops the app; saved data stays in the embedded database.'
echo 'Launch agents with the gateway CLI using this local address as backendUrl.'
wait "$app_pid"
