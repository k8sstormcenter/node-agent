#!/usr/bin/env bash
set -u
here=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:?output directory}
SERVICES=${SERVICES:-6}
CLIENTS=${CLIENTS:-9}
MESH2=${MESH2:-1}
LEARN_MIN=${LEARN_MIN:-10}
STEADY_MIN=${STEADY_MIN:-45}
POLL_S=${POLL_S:-20}
NS=${AGENT_NS:-kubescape}
mkdir -p "$OUT"/{watch,metrics,final,logs}
mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) MARK $*" | tee -a "$OUT/marks.log"; }
pids=()

OUT="$OUT/gen" bash "$here/gen-mesh.sh" "$SERVICES" "$CLIENTS"
manifests=("$OUT/gen/mesh.yaml")
cp "$OUT/gen/expected-edges.tsv" "$OUT/expected-edges.tsv"
if [ "$MESH2" = 1 ]; then
  OUT="$OUT/gen2" bash "$here/gen-mesh2.sh"
  manifests+=("$OUT/gen2/mesh2.yaml")
  cat "$OUT/gen2/expected-edges.tsv" >> "$OUT/expected-edges.tsv"
fi

resources=$( { kubectl api-resources --api-group=profiles.sbob -o name; kubectl api-resources --api-group=spdx.softwarecomposition.kubescape.io -o name; } 2>/dev/null | sort -u)
echo "$resources" > "$OUT/resources.txt"

for r in $resources; do
  ( while true; do kubectl get "$r" -A --watch --output-watch-events -o json --request-timeout=0 >> "$OUT/watch/$r.json" 2>> "$OUT/watch/$r.err"; echo "{\"reconnect\":\"$(date -u +%FT%TZ)\"}" >> "$OUT/watch/$r.json"; sleep 2; done ) &
  pids+=($!)
done

poll() {
  while true; do
    t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    for r in $resources; do
      kubectl get "$r" -A -o json 2>/dev/null | jq -c --arg t "$t" --arg r "$r" '{t:$t, res:$r, items:[.items[] | {ns:.metadata.namespace, kind:.kind, name:.metadata.name, rv:.metadata.resourceVersion, uid:.metadata.uid, created:.metadata.creationTimestamp, labels:(.metadata.labels // {}), ann:((.metadata.annotations // {}) | del(.["kubectl.kubernetes.io/last-applied-configuration"])), status:(.status // null)}]}' >> "$OUT/poll.jsonl"
    done
    sleep "$POLL_S"
  done
}
poll &
pids+=($!)

na_pod=$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=node-agent -o name 2>/dev/null | head -1)
[ -n "$na_pod" ] || na_pod=$(kubectl -n "$NS" get pods -o name | grep node-agent | head -1)
st_pod=$(kubectl -n "$NS" get pods -o name | grep -E '/storage-' | head -1)
kubectl -n "$NS" port-forward "$na_pod" 18080:8080 > "$OUT/metrics/pf-agent.log" 2>&1 &
pids+=($!)
kubectl -n "$NS" port-forward "$st_pod" 18443:8443 > "$OUT/metrics/pf-storage.log" 2>&1 &
pids+=($!)
token=$(kubectl -n "$NS" create token node-agent --duration=6h 2>/dev/null || true)

scrape() {
  while true; do
    s=$(date -u +%s)
    curl -s -m 20 http://localhost:18080/metrics | gzip > "$OUT/metrics/agent-$s.prom.gz"
    curl -sk -m 20 https://localhost:18443/metrics | gzip > "$OUT/metrics/storage-$s.prom.gz"
    if [ -n "$token" ] && [ "$(zcat "$OUT/metrics/storage-$s.prom.gz" | grep -c '^storage_')" = 0 ]; then
      curl -sk -m 20 -H "Authorization: Bearer $token" https://localhost:18443/metrics | gzip > "$OUT/metrics/storage-$s.prom.gz"
    fi
    docker exec kind-control-plane crictl stats -o json 2>/dev/null | jq -c --arg t "$s" '{t:($t|tonumber), stats:[.stats[] | {name:.attributes.labels["io.kubernetes.container.name"], pod:.attributes.labels["io.kubernetes.pod.name"], ns:.attributes.labels["io.kubernetes.pod.namespace"], cpu_ns:(.cpu.usageCoreNanoSeconds.value // 0 | tonumber), mem_ws:(.memory.workingSetBytes.value // 0 | tonumber)}]}' >> "$OUT/stats.jsonl"
    for c in node-agent apiserver; do
      cid=$(docker exec kind-control-plane crictl ps -q --name "^$c\$" 2>/dev/null | head -1)
      [ -n "$cid" ] || continue
      pid=$(docker exec kind-control-plane crictl inspect -o go-template --template '{{.info.pid}}' "$cid" 2>/dev/null)
      [ -n "$pid" ] || continue
      docker exec kind-control-plane sh -c "echo $s $c fds=\$(ls /proc/$pid/fd | wc -l) threads=\$(ls /proc/$pid/task | wc -l) inotify=\$(ls -l /proc/$pid/fd 2>/dev/null | grep -c inotify) rss_kb=\$(grep VmRSS /proc/$pid/status | tr -s ' ' | cut -d' ' -f2)" >> "$OUT/procs.txt" 2>/dev/null
    done
    sleep 60
  done
}
scrape &
pids+=($!)

mark apply
for m in "${manifests[@]}"; do kubectl apply -f "$m" > /dev/null; done
for n in $(grep -h -E '^metadata: \{name: [a-z0-9-]+\}$' "${manifests[@]}" | sed -E 's/.*name: ([a-z0-9-]+)\}/\1/' | sort -u); do
  kubectl -n "$n" rollout status deploy --timeout=900s > /dev/null 2>&1 || kubectl -n "$n" get pods -o wide >> "$OUT/rollout-problems.txt"
done
mark running
kubectl get pods -A -o wide > "$OUT/pods-running.txt"
sleep $(( LEARN_MIN * 60 ))
mark steady-start
sleep $(( STEADY_MIN * 60 ))
mark steady-end

for p in $(kubectl get pods -A -l 'app in (cli-1,cli-2,cli-3)' -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  ns=${p%%/*}; pod=${p#*/}
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $ns $pod" >> "$OUT/injections.txt"
  kubectl -n "$ns" exec "$pod" -- sh -c 'cat /etc/passwd > /dev/null; ls /root > /dev/null 2>&1; wget -T 2 -qO- http://1.1.1.1 > /dev/null 2>&1; true' >> "$OUT/injections.txt" 2>&1
done
mark inject
sleep 120
mark end

for r in $resources; do
  kubectl get "$r" -A -o json > "$OUT/final/$r.list.json" 2>/dev/null
done
for ns in $(cut -f2,4 "$OUT/expected-edges.tsv" | tr '\t' '\n' | sort -u); do
  for n in $(kubectl -n "$ns" get runtimeprofiles.profiles.sbob -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    kubectl -n "$ns" get runtimeprofiles.profiles.sbob "$n" -o json > "$OUT/final/rp-$ns-$n.json" 2>/dev/null
  done
done
kubectl get pods -A -o json > "$OUT/final/pods.json"
kubectl get events -A -o json > "$OUT/final/events.json"
for p in $(kubectl -n "$NS" get pods -o name); do
  for c in $(kubectl -n "$NS" get "$p" -o jsonpath='{.spec.containers[*].name}'); do
    kubectl -n "$NS" logs "$p" -c "$c" --timestamps > "$OUT/logs/$(basename "$p")-$c.log" 2>&1
    kubectl -n "$NS" logs "$p" -c "$c" --timestamps --previous > "$OUT/logs/$(basename "$p")-$c.previous.log" 2>/dev/null || rm -f "$OUT/logs/$(basename "$p")-$c.previous.log"
  done
done

for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
pkill -P $$ 2>/dev/null
wait 2>/dev/null
echo "polls: $(wc -l < "$OUT/poll.jsonl") metrics files: $(ls "$OUT/metrics" | wc -l) marks: $(wc -l < "$OUT/marks.log")"
