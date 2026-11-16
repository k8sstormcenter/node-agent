#!/usr/bin/env bash
set -euo pipefail
SERVICES=${1:-6}
CLIENTS=${2:-9}
NS_A=${NS_A:-mesh-a}
NS_B=${NS_B:-mesh-b}
OUT=${OUT:-$PWD/out}
mkdir -p "$OUT"
edges="$OUT/expected-edges.tsv"
: > "$edges"
svc_ns() { local i=$1; if [ $((i % 3)) -eq 0 ]; then echo "$NS_B"; else echo "$NS_A"; fi; }
cli_ns() { local j=$1; if [ $((j % 4)) -eq 0 ]; then echo "$NS_B"; else echo "$NS_A"; fi; }
{
echo "apiVersion: v1"; echo "kind: Namespace"; echo "metadata: {name: $NS_A}"; echo "---"
echo "apiVersion: v1"; echo "kind: Namespace"; echo "metadata: {name: $NS_B}"
for i in $(seq 1 "$SERVICES"); do
  ns=$(svc_ns "$i"); port=$((8000 + i))
  cat <<EOF
---
apiVersion: v1
kind: Service
metadata: {name: svc-$i, namespace: $ns}
spec:
  selector: {app: svc-$i}
  ports: [{port: $port, targetPort: $port}]
EOF
  if [ $((i % 2)) -eq 0 ]; then
    cat <<EOF
---
apiVersion: v1
kind: Service
metadata: {name: svc-$i-headless, namespace: $ns}
spec:
  clusterIP: None
  selector: {app: svc-$i}
  ports: [{port: $port, targetPort: $port}]
EOF
  fi
  cat <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: svc-$i, namespace: $ns, labels: {app: svc-$i}}
spec:
  replicas: 1
  selector: {matchLabels: {app: svc-$i}}
  template:
    metadata: {labels: {app: svc-$i}}
    spec:
      containers:
        - name: srv
          image: docker.io/library/busybox:1.36
          command: ["sh", "-c", "while true; do nc -lk -p $port -e sh -c 'read x; echo pong'; done"]
          resources: {requests: {cpu: 10m, memory: 12Mi}}
EOF
done
for j in $(seq 1 "$CLIENTS"); do
  ns=$(cli_ns "$j")
  t1=$(( (j % SERVICES) + 1 )); t2=$(( ((j + 2) % SERVICES) + 1 )); t3=$(( ((j * 3) % SERVICES) + 1 ))
  targets=""
  for t in $t1 $t2 $t3; do
    tns=$(svc_ns "$t"); port=$((8000 + t))
    host="svc-$t.$tns.svc"
    if [ $((t % 2)) -eq 0 ] && [ $((j % 2)) -eq 0 ]; then host="svc-$t-headless.$tns.svc"; fi
    targets="$targets echo ping | nc -w 2 $host $port >/dev/null 2>&1;"
    printf "%s\t%s\t%s\t%s\t%s\n" "svc-$t" "$tns" "cli-$j" "$ns" "$port" >> "$edges"
  done
  cat <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: cli-$j, namespace: $ns, labels: {app: cli-$j}}
spec:
  replicas: 1
  selector: {matchLabels: {app: cli-$j}}
  template:
    metadata: {labels: {app: cli-$j}}
    spec:
      containers:
        - name: cli
          image: docker.io/library/busybox:1.36
          command: ["sh", "-c", "while true; do$targets sleep 4; done"]
          resources: {requests: {cpu: 10m, memory: 12Mi}}
EOF
done
} > "$OUT/mesh.yaml"
sort -u "$edges" -o "$edges"
echo "manifest: $OUT/mesh.yaml  services=$SERVICES clients=$CLIENTS expected edges=$(wc -l < "$edges") ($(cut -f1,2 "$edges" | sort -u | wc -l) targets)"
