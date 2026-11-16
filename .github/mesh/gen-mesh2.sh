#!/usr/bin/env bash
set -euo pipefail
OUT=${OUT:-$PWD/out2}
mkdir -p "$OUT"
edges="$OUT/expected-edges.tsv"
: > "$edges"
edge() { printf "%s\t%s\t%s\t%s\t%s\n" "$1" "$2" "$3" "$4" "$5" >> "$edges"; }

cat > "$OUT/mesh2.yaml" <<'EOF'
apiVersion: v1
kind: Namespace
metadata: {name: shop}
---
apiVersion: v1
kind: Namespace
metadata: {name: data}
---
apiVersion: v1
kind: Namespace
metadata: {name: mon}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: rabbit-plugins, namespace: data}
data:
  enabled_plugins: "[rabbitmq_management,rabbitmq_prometheus]."
---
apiVersion: v1
kind: Service
metadata: {name: rabbit, namespace: data}
spec:
  selector: {app: rabbit}
  ports:
    - {name: amqp, port: 5672, targetPort: 5672}
    - {name: http, port: 15672, targetPort: 15672}
    - {name: metrics, port: 15692, targetPort: 15692}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: rabbit, namespace: data, labels: {app: rabbit}}
spec:
  replicas: 1
  selector: {matchLabels: {app: rabbit}}
  template:
    metadata: {labels: {app: rabbit}}
    spec:
      containers:
        - name: rabbit
          image: docker.io/library/rabbitmq:3.13-management-alpine
          env:
            - {name: RABBITMQ_DEFAULT_USER, value: app}
            - {name: RABBITMQ_DEFAULT_PASS, value: app}
          ports: [{containerPort: 5672}, {containerPort: 15672}, {containerPort: 15692}]
          volumeMounts: [{name: plugins, mountPath: /etc/rabbitmq/enabled_plugins, subPath: enabled_plugins}]
          resources: {requests: {cpu: 100m, memory: 200Mi}, limits: {memory: 512Mi}}
      volumes:
        - name: plugins
          configMap: {name: rabbit-plugins}
---
apiVersion: v1
kind: Service
metadata: {name: postgres, namespace: data}
spec:
  selector: {app: postgres}
  ports: [{port: 5432, targetPort: 5432}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: postgres, namespace: data, labels: {app: postgres}}
spec:
  replicas: 1
  selector: {matchLabels: {app: postgres}}
  template:
    metadata: {labels: {app: postgres}}
    spec:
      containers:
        - name: postgres
          image: docker.io/library/postgres:16-alpine
          env:
            - {name: POSTGRES_USER, value: app}
            - {name: POSTGRES_PASSWORD, value: app}
            - {name: POSTGRES_DB, value: app}
          ports: [{containerPort: 5432}]
          resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {memory: 256Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: redis, namespace: data}
spec:
  selector: {app: redis}
  ports: [{port: 6379, targetPort: 6379}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: redis, namespace: data, labels: {app: redis}}
spec:
  replicas: 1
  selector: {matchLabels: {app: redis}}
  template:
    metadata: {labels: {app: redis}}
    spec:
      containers:
        - name: redis
          image: docker.io/library/redis:7-alpine
          ports: [{containerPort: 6379}]
          resources: {requests: {cpu: 20m, memory: 32Mi}, limits: {memory: 128Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: mariadb, namespace: data}
spec:
  selector: {app: mariadb}
  ports: [{port: 3306, targetPort: 3306}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: mariadb, namespace: data, labels: {app: mariadb}}
spec:
  replicas: 1
  selector: {matchLabels: {app: mariadb}}
  template:
    metadata: {labels: {app: mariadb}}
    spec:
      containers:
        - name: mariadb
          image: docker.io/library/mariadb:11
          env: [{name: MARIADB_ROOT_PASSWORD, value: app}]
          ports: [{containerPort: 3306}]
          resources: {requests: {cpu: 50m, memory: 128Mi}, limits: {memory: 384Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: pg-exporter, namespace: data}
spec:
  selector: {app: pg-exporter}
  ports: [{port: 9187, targetPort: 9187}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: pg-exporter, namespace: data, labels: {app: pg-exporter}}
spec:
  replicas: 1
  selector: {matchLabels: {app: pg-exporter}}
  template:
    metadata: {labels: {app: pg-exporter}}
    spec:
      containers:
        - name: exporter
          image: quay.io/prometheuscommunity/postgres-exporter:v0.15.0
          env: [{name: DATA_SOURCE_NAME, value: "postgresql://app:app@postgres.data.svc:5432/app?sslmode=disable"}]
          ports: [{containerPort: 9187}]
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: redis-exporter, namespace: data}
spec:
  selector: {app: redis-exporter}
  ports: [{port: 9121, targetPort: 9121}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: redis-exporter, namespace: data, labels: {app: redis-exporter}}
spec:
  replicas: 1
  selector: {matchLabels: {app: redis-exporter}}
  template:
    metadata: {labels: {app: redis-exporter}}
    spec:
      containers:
        - name: exporter
          image: docker.io/oliver006/redis_exporter:v1.62.0
          args: ["--redis.addr=redis://redis.data.svc:6379"]
          ports: [{containerPort: 9121}]
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: shop}
spec:
  selector: {app: api}
  ports: [{port: 8080, targetPort: 8080}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop, labels: {app: api}}
spec:
  replicas: 1
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: docker.io/library/busybox:1.36
          command: ["sh", "-c"]
          args:
            - |
              mkdir -p /www && echo 'api_up 1' > /www/metrics && echo ok > /www/index.html
              httpd -f -p 8080 -h /www &
              while true; do
                nc -z -w 2 postgres.data.svc 5432
                nc -z -w 2 redis.data.svc 6379
                printf 'AMQP\0\0\t\1' | nc -w 2 rabbit.data.svc 5672 >/dev/null
                wget -qO- --header='Authorization: Basic YXBwOmFwcA==' http://rabbit.data.svc:15672/api/overview >/dev/null
                sleep 3
              done
          ports: [{containerPort: 8080}]
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: web-caddy, namespace: shop}
data:
  Caddyfile: |
    {
      auto_https disable_redirects
    }
    https://web.shop.svc:8443 {
      tls internal
      reverse_proxy api.shop.svc:8080
    }
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec:
  selector: {app: web}
  ports: [{port: 8443, targetPort: 8443}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop, labels: {app: web}}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: web
          image: docker.io/library/caddy:2-alpine
          args: ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
          ports: [{containerPort: 8443}]
          volumeMounts: [{name: caddyfile, mountPath: /etc/caddy}]
          resources: {requests: {cpu: 20m, memory: 32Mi}}
      volumes:
        - name: caddyfile
          configMap: {name: web-caddy}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: loadgen, namespace: shop, labels: {app: loadgen}}
spec:
  replicas: 1
  selector: {matchLabels: {app: loadgen}}
  template:
    metadata: {labels: {app: loadgen}}
    spec:
      containers:
        - name: curl
          image: docker.io/curlimages/curl:8.10.1
          command: ["sh", "-c", "while true; do curl -sk https://web.shop.svc:8443/ >/dev/null; sleep 2; done"]
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: worker, namespace: shop, labels: {app: worker}}
spec:
  replicas: 1
  selector: {matchLabels: {app: worker}}
  template:
    metadata: {labels: {app: worker}}
    spec:
      containers:
        - name: worker
          image: docker.io/library/alpine:3.20
          command: ["sh", "-c"]
          args:
            - |
              while true; do
                printf 'AMQP\0\0\t\1' | nc -w 2 rabbit.data.svc 5672 >/dev/null
                wget -qO- --header='Authorization: Basic YXBwOmFwcA==' http://rabbit.data.svc:15672/api/queues >/dev/null
                nc -z -w 2 mariadb.data.svc 3306
                sleep 4
              done
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: cron, namespace: shop, labels: {app: cron}}
spec:
  replicas: 1
  selector: {matchLabels: {app: cron}}
  template:
    metadata: {labels: {app: cron}}
    spec:
      containers:
        - name: psql
          image: docker.io/library/postgres:16-alpine
          command: ["sh", "-c", "while true; do PGPASSWORD=app psql -h postgres.data.svc -U app -d app -c 'select now()' >/dev/null 2>&1; sleep 5; done"]
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: cache-warmer, namespace: shop, labels: {app: cache-warmer}}
spec:
  replicas: 1
  selector: {matchLabels: {app: cache-warmer}}
  template:
    metadata: {labels: {app: cache-warmer}}
    spec:
      containers:
        - name: redis-cli
          image: docker.io/library/redis:7-alpine
          command: ["sh", "-c", "i=0; while true; do i=$((i+1)); redis-cli -h redis.data.svc SET warm:$i $(date +%s) >/dev/null; sleep 3; done"]
          resources: {requests: {cpu: 10m, memory: 16Mi}}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: prometheus, namespace: mon}
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    scrape_configs:
      - job_name: postgres
        static_configs: [{targets: ["pg-exporter.data.svc:9187"]}]
      - job_name: redis
        static_configs: [{targets: ["redis-exporter.data.svc:9121"]}]
      - job_name: rabbit
        static_configs: [{targets: ["rabbit.data.svc:15692"]}]
      - job_name: api
        static_configs: [{targets: ["api.shop.svc:8080"]}]
---
apiVersion: v1
kind: Service
metadata: {name: prometheus, namespace: mon}
spec:
  selector: {app: prometheus}
  ports: [{port: 9090, targetPort: 9090}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: prometheus, namespace: mon, labels: {app: prometheus}}
spec:
  replicas: 1
  selector: {matchLabels: {app: prometheus}}
  template:
    metadata: {labels: {app: prometheus}}
    spec:
      containers:
        - name: prometheus
          image: docker.io/prom/prometheus:v2.53.0
          args: ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.retention.time=1h", "--storage.tsdb.path=/prometheus"]
          ports: [{containerPort: 9090}]
          volumeMounts: [{name: config, mountPath: /etc/prometheus}]
          resources: {requests: {cpu: 50m, memory: 128Mi}, limits: {memory: 384Mi}}
      volumes:
        - name: config
          configMap: {name: prometheus}
EOF

edge web shop loadgen shop 8443
edge api shop web shop 8080
edge postgres data api shop 5432
edge redis data api shop 6379
edge rabbit data api shop 5672
edge rabbit data api shop 15672
edge rabbit data worker shop 5672
edge rabbit data worker shop 15672
edge mariadb data worker shop 3306
edge postgres data cron shop 5432
edge redis data cache-warmer shop 6379
edge postgres data pg-exporter data 5432
edge redis data redis-exporter data 6379
edge pg-exporter data prometheus mon 9187
edge redis-exporter data prometheus mon 9121
edge rabbit data prometheus mon 15692
edge api shop prometheus mon 8080
sort -u "$edges" -o "$edges"
echo "manifest: $OUT/mesh2.yaml  expected edges=$(wc -l < "$edges") targets=$(cut -f1,2 "$edges" | sort -u | wc -l) clients=$(cut -f3,4 "$edges" | sort -u | wc -l) namespaces=$(cut -f2,4 "$edges" | tr '\t' '\n' | sort -u | tr '\n' ' ')"
