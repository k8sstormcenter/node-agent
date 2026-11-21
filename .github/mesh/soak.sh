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
BIND=${BIND:-0}
CHURN_MIN=${CHURN_MIN:-20}
LABEL=kubescape.io/user-defined-profile
CP=containerprofiles.spdx.softwarecomposition.kubescape.io
mkdir -p "$OUT"/{watch,metrics,final,logs}
mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) MARK $*" | tee -a "$OUT/marks.log"; }
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
pids=()

mesh_namespaces() { cut -f2,4 "$OUT/expected-edges.tsv" | tr '\t' '\n' | sort -u; }
live_pod() { kubectl -n "$1" get pods -l "app=$2" --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' 2>/dev/null | awk -v o="${3:-}" '$1 != o && NF == 1 {print $1}' | head -1; }
label_pod() {
  kubectl -n "$1" label pod "$2" "$LABEL=$3" --overwrite > /dev/null 2>> "$OUT/bind/errors.log" || return 1
  local t c
  t=$(now)
  for c in $(kubectl -n "$1" get pod "$2" -o jsonpath='{.spec.containers[*].name}'); do
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$1" "$2" "$3" "$c" "$4" >> "$OUT/bind.tsv"
  done
}
bind_docs() {
  local ns w c s
  printf 'ns\tworkload\tcontainer\tdocument\tlearned\n' > "$OUT/bind/docs.tsv"
  for ns in $(mesh_namespaces); do
    kubectl -n "$ns" get "$CP" -o json > "$OUT/bind/list-$ns.json" 2>> "$OUT/bind/errors.log"
    for w in $(kubectl -n "$ns" get deploy -o jsonpath='{.items[*].metadata.name}'); do
      for c in $(kubectl -n "$ns" get deploy "$w" -o jsonpath='{.spec.template.spec.containers[*].name}'); do
        s=$(jq -r --arg w "$w" --arg c "$c" '[.items[] | select(.metadata.labels["kubescape.io/workload-name"] == $w and .metadata.labels["kubescape.io/workload-container-name"] == $c and ((.metadata.annotations // {})["kubescape.io/managed-by"] // "") != "User" and ((.metadata.annotations // {})["kubescape.io/report-series-id"] // "") == "" and (.metadata.name | test("-[0-9a-f]{32}$") | not))] | sort_by(.metadata.creationTimestamp) | last | .metadata.name // empty' "$OUT/bind/list-$ns.json")
        if [ -z "$s" ]; then echo "$ns/$w/$c: no learned profile" >> "$OUT/bind/errors.log"; continue; fi
        kubectl -n "$ns" get "$CP" "$s" -o json | jq --arg n "$w-$c" '{apiVersion, kind, metadata: {name: $n, namespace: .metadata.namespace, annotations: {"kubescape.io/managed-by": "User"}}, spec}' > "$OUT/bind/doc-$ns-$w-$c.json"
        kubectl create -f "$OUT/bind/doc-$ns-$w-$c.json" >> "$OUT/bind/create.log" 2>&1 || echo "$ns/$w/$c: create failed" >> "$OUT/bind/errors.log"
        printf '%s\t%s\t%s\t%s\t%s\n' "$ns" "$w" "$c" "$w-$c" "$s" >> "$OUT/bind/docs.tsv"
      done
    done
  done
}
bind_all() {
  local ns w p
  for ns in $(mesh_namespaces); do
    for w in $(kubectl -n "$ns" get deploy -o jsonpath='{.items[*].metadata.name}'); do
      for p in $(kubectl -n "$ns" get pods -l "app=$w" -o jsonpath='{.items[*].metadata.name}'); do
        label_pod "$ns" "$p" "$w" bind
      done
    done
  done
}
churn() {
  local rounds r j w ns old new p cid start rest i
  rounds=$(( CHURN_MIN / 5 ))
  [ "$rounds" -ge 1 ] || rounds=1
  printf 't\taction\tns\tworkload\told\tnew\n' > "$OUT/churn.tsv"
  mark churn-start
  for r in $(seq 1 "$rounds"); do
    start=$(date +%s)
    for j in 7 8 9; do
      w=cli-$j; ns=$(cli_ns "$j"); old=$(live_pod "$ns" "$w")
      [ -n "$old" ] || continue
      kubectl -n "$ns" delete pod "$old" --wait=false > /dev/null 2>&1
      new=""
      for i in $(seq 1 60); do
        new=$(live_pod "$ns" "$w" "$old")
        [ -n "$new" ] && break
        sleep 2
      done
      printf '%s\tdelete\t%s\t%s\t%s\t%s\n' "$(now)" "$ns" "$w" "$old" "$new" >> "$OUT/churn.tsv"
      [ -n "$new" ] && label_pod "$ns" "$new" "$w" churn
    done
    if [ "$r" = 2 ]; then
      for j in 7 8 9; do
        w=cli-$j; ns=$(cli_ns "$j"); p=$(live_pod "$ns" "$w")
        [ -n "$p" ] || continue
        cid=$(docker exec kind-control-plane crictl ps -q --name '^cli$' --label "io.kubernetes.pod.name=$p" 2>/dev/null | head -1)
        [ -n "$cid" ] && docker exec kind-control-plane crictl stop "$cid" > /dev/null 2>&1
        printf '%s\trestart\t%s\t%s\t%s\t%s\n' "$(now)" "$ns" "$w" "$p" "$cid" >> "$OUT/churn.tsv"
      done
    fi
    rest=$(( 300 - ($(date +%s) - start) ))
    [ "$rest" -gt 0 ] && sleep "$rest"
  done
  mark churn-end
}

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
kubectl create namespace mesh-probe > /dev/null 2>&1
kubectl -n mesh-probe run probe --image=docker.io/library/busybox:1.36 --restart=Never --command -- sleep 100000 > /dev/null
kubectl -n mesh-probe wait --for=condition=Ready pod/probe --timeout=300s > /dev/null 2>&1 || kubectl -n mesh-probe get pods -o wide >> "$OUT/rollout-problems.txt"
mark running
kubectl get pods -A -o wide > "$OUT/pods-running.txt"
sleep $(( LEARN_MIN * 60 ))
if [ "$BIND" = 1 ]; then
  mkdir -p "$OUT/bind"
  printf 't\tns\tpod\tworkload\tcontainer\tphase\n' > "$OUT/bind.tsv"
  mark bind
  bind_docs
  sleep 5
  bind_all
  sleep 60
  mark bound
fi
mark steady-start
pprof_capture() {
  sleep $(( STEADY_MIN * 60 / 3 ))
  mkdir -p "$OUT/pprof"
  for c in agent:node-agent:16060 storage:storage:16061; do
    comp=${c%%:*}; rest=${c#*:}; sel=${rest%%:*}; port=${rest#*:}
    pod=$(kubectl -n "$NS" get pods -o name | grep -E "/$sel-" | head -1)
    [ -n "$pod" ] || continue
    (
      kubectl -n "$NS" port-forward "$pod" "$port:6060" > "$OUT/pprof/pf-$comp.log" 2>&1 &
      pf=$!
      sleep 5
      for i in 1 2 3; do
        curl -s -m 90 -o "$OUT/pprof/$comp-cpu-$i.pb.gz" "http://localhost:$port/debug/pprof/profile?seconds=60" || rm -f "$OUT/pprof/$comp-cpu-$i.pb.gz"
      done
      curl -s -m 30 -o "$OUT/pprof/$comp-heap.pb.gz" "http://localhost:$port/debug/pprof/heap"
      curl -s -m 30 -o "$OUT/pprof/$comp-goroutine.txt" "http://localhost:$port/debug/pprof/goroutine?debug=1"
      kill $pf 2>/dev/null
    ) &
  done
  wait
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) pprof done" >> "$OUT/marks.log"
}
pprof_capture &
pids+=($!)
sleep $(( STEADY_MIN * 60 ))
mark steady-end

INJ_WAIT_S=${INJ_WAIT_S:-720}
NS_A=${NS_A:-mesh-a}
NS_B=${NS_B:-mesh-b}
svc_ns() { if [ $(($1 % 3)) -eq 0 ]; then echo "$NS_B"; else echo "$NS_A"; fi; }
cli_ns() { if [ $(($1 % 4)) -eq 0 ]; then echo "$NS_B"; else echo "$NS_A"; fi; }
pod_of() { kubectl -n "$1" get pods -l "app=$2" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
ip_of() { kubectl -n "$1" get pod "$2" -o jsonpath='{.status.podIP}' 2>/dev/null; }
row() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "$@" >> "$OUT/injections.tsv"; }
act() { local ns=$1 pod=$2 c=$3; shift 3; echo "$(date -u +%FT%T.%3NZ) $ns/$pod/$c: $*" >> "$OUT/injections.log"; kubectl -n "$ns" exec "$pod" -c "$c" -- sh -c "$*" >> "$OUT/injections.log" 2>&1; }
printf 't\tkind\trule\tns\tpod\tcontainer\tworkload\tsubject\tpeer\n' > "$OUT/injections.tsv"
if [ "$BIND" = 1 ]; then
  churn
  sleep 60
fi

ctl=()
for j in 4 5 6; do
  ns=$(cli_ns "$j"); pod=$(pod_of "$ns" "cli-$j")
  [ -n "$pod" ] && ctl+=("$ns/$pod/cli-$j")
done
for c in "${ctl[@]}"; do IFS=/ read -r ns pod w <<< "$c"; act "$ns" "$pod" cli ':'; done
sleep 30
mark control
for c in "${ctl[@]}"; do
  IFS=/ read -r ns pod w <<< "$c"
  peer=$(kubectl -n "$ns" get deploy "$w" -o jsonpath='{.spec.template.spec.containers[0].command[2]}' | grep -o -E '(timeout [0-9]+ )?nc -w 2 [^ ]+ [0-9]+' | head -1)
  row control - "$ns" "$pod" cli "$w" "exec=/bin/sleep" -
  act "$ns" "$pod" cli 'sleep 4'
  if [ -n "$peer" ]; then
    row control - "$ns" "$pod" cli "$w" "peer=$(echo "${peer##*nc -w 2 }" | tr ' ' :)" -
    act "$ns" "$pod" cli "echo ping | $peer > /dev/null"
  fi
done
sleep 60
mark inject
for k in 1 2 3; do
  w=cli-$k; ns=$(cli_ns "$k"); pod=$(pod_of "$ns" "$w")
  [ -n "$pod" ] || continue
  cip=$(ip_of "$ns" "$pod")
  row inject R0001 "$ns" "$pod" cli "$w" "exec=/bin/uname" -
  act "$ns" "$pod" cli 'uname -a > /dev/null'
  row inject R0010 "$ns" "$pod" cli "$w" "path=/etc/shadow" -
  act "$ns" "$pod" cli 'cat /etc/shadow > /dev/null'
  row inject R0002 "$ns" "$pod" cli "$w" "path=/etc/group" -
  act "$ns" "$pod" cli 'cat /etc/group > /dev/null'
  row inject R0006 "$ns" "$pod" cli "$w" "path=*serviceaccount*/token" -
  act "$ns" "$pod" cli 'cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null'
  row inject R0005 "$ns" "$pod" cli "$w" "domain=example.com." -
  act "$ns" "$pod" cli 'nslookup example.com > /dev/null'
  row inject R0011 "$ns" "$pod" cli "$w" "net=1.1.1.1:443" -
  act "$ns" "$pod" cli 'echo | nc -w 2 1.1.1.1 443 > /dev/null'
  x=$(awk -F'\t' -v c="$w" -v n="$ns" '$1 ~ /^svc-[0-9]+$/ {all[$1] = 1} $3 == c && $4 == n {t[$1] = 1} END {for (s in all) if (!(s in t)) print s}' "$OUT/expected-edges.tsv" | sort -t- -k2,2n | head -1)
  [ -n "$x" ] || continue
  xi=${x#svc-}; xns=$(svc_ns "$xi"); xport=$((8000 + xi)); xpod=$(pod_of "$xns" "$x"); xip=$(ip_of "$xns" "$xpod")
  [ -n "$xip" ] || continue
  row inject R0011 "$ns" "$pod" cli "$w" "net=$xip:$xport" "$x"
  row inject R0012 "$xns" "$xpod" srv "$x" "net=$cip:$xport" "$w"
  act "$ns" "$pod" cli "echo ping | nc -w 2 $xip $xport > /dev/null"
done
pip=$(ip_of mesh-probe probe)
for i in 1 2 3; do
  s=svc-$i; sns=$(svc_ns "$i"); spod=$(pod_of "$sns" "$s"); sip=$(ip_of "$sns" "$spod"); port=$((8000 + i))
  [ -n "$sip" ] && [ -n "$pip" ] || continue
  row inject R0012 "$sns" "$spod" srv "$s" "net=$pip:$port" probe
  act mesh-probe probe probe "echo ping | nc -w 2 $sip $port > /dev/null"
done
mark inject-end
sleep "$INJ_WAIT_S"
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
