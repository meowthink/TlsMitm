#!/bin/bash
# End-to-end: .NET SslStream presents a leaf issued by a real emSign intermediate; a strict Node
# client using only its DEFAULT store must accept it.
set -u
cd "$(dirname "$0")"
mkdir -p out
# NODE takes a bash path and wins; TLSMITM_NODE is the Windows path the C# harness reads.
NODE="${NODE:-${TLSMITM_NODE:-node}}"
EXE="./bin/Debug/net10.0/chainprobe.exe"

taskkill //IM chainprobe.exe //F > /dev/null 2>&1
rm -f out/emsign.log
"$EXE" emsign ../../TlsMitm/emsign_certs > out/emsign.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do grep -q "PORT=" out/emsign.log 2>/dev/null && break; sleep 0.25; done
PORT=$(sed -n 's/.*PORT=\([0-9]*\).*/\1/p' out/emsign.log | head -1)
echo "--- server ---"
grep -v "^\[EmSignCa\]" out/emsign.log
echo "--- node (default store) ---"
if [ -n "$PORT" ]; then
  "$NODE" node-default-client.js "$PORT" 2>&1
else
  echo "no listener"
fi
sleep 1
kill $SRV 2>/dev/null
echo "--- server after handshake ---"
grep "handshake" out/emsign.log
taskkill //IM chainprobe.exe //F > /dev/null 2>&1
