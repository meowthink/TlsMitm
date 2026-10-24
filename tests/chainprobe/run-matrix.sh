#!/bin/bash
# Matrix: does the chain reach a strict verifier? plain = ServerCertificate only,
# context = SslStreamCertificateContext with the intermediate + root attached.
set -u
cd "$(dirname "$0")"
mkdir -p out
NODE="/c/Users/meowthink/Downloads/node-v24.21.0-win-x64/node.exe"
EXE="./bin/Debug/net10.0/chainprobe.exe"

taskkill //IM chainprobe.exe //F > /dev/null 2>&1
dotnet build -v q --nologo > out/build.log 2>&1 || { echo "BUILD FAILED"; tail -20 out/build.log; exit 1; }

start_server() { # $1 = mode ; sets SRV and PORT in the caller's shell
  rm -f out/server.log
  "$EXE" "$1" > out/server.log 2>&1 &
  SRV=$!
  for i in $(seq 1 60); do grep -q "PORT=" out/server.log 2>/dev/null && break; sleep 0.25; done
  PORT=$(sed -n 's/.*PORT=\([0-9]*\).*/\1/p' out/server.log | head -1)
}

for mode in plain context; do
  echo "================= server presents: $mode ================="

  PORT=""
  start_server "$mode"
  [ -z "$PORT" ] && { echo "no listener (mode=$mode)"; cat out/server.log; kill $SRV 2>/dev/null; continue; }
  echo "--- node strict client (trusts only root.pem, no AIA) ---"
  "$NODE" node-client.js "$PORT" 2>&1
  kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
  echo "--- server side ---"
  grep -v "^leaf \|^inter \|^offline \|^context:\|^   ctx" out/server.log

  start_server "$mode"
  echo "--- dotnet client ---"
  "$EXE" client "$PORT" 2>&1 | grep -v "^leaf \|^inter \|^offline \|^context:\|^   ctx"
  kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
  echo "--- server side ---"
  grep "handshake" out/server.log
  echo
done
taskkill //IM chainprobe.exe //F > /dev/null 2>&1
