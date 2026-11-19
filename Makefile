# Clearpath. `make test eval` runs entirely offline; cluster/AWS targets need tools.
space := $(subst ,, )
# Windows: use Git for Windows' bash + coreutils. Without this, GNU make would
# silently fall back to cmd.exe and every recipe below would misbehave.
ifeq ($(OS),Windows_NT)
GIT_ROOT ?= C:/Program Files/Git
ifeq ($(wildcard $(subst $(space),\ ,$(GIT_ROOT))/usr/bin/bash.exe),)
$(error Git for Windows not found at "$(GIT_ROOT)"; install it (winget install Git.Git) or pass GIT_ROOT=...)
endif
export PATH := $(GIT_ROOT)/usr/bin;$(GIT_ROOT)/bin;$(PATH)
# Stop Git Bash rewriting POSIX-looking args (e.g. a Helm value of
# /run/containerd/containerd.sock) into C:/Program Files/Git/... paths.
export MSYS_NO_PATHCONV := 1
endif
SHELL := /bin/bash
# Prefer the project venv (POSIX or Windows layout); on Windows `python3` is
# usually the Microsoft Store stub, not a real interpreter.
PY ?= $(or $(wildcard .venv/bin/python),$(wildcard .venv/Scripts/python.exe),python3)
DATE := $(shell date -u +%F)
OUT ?= eval/results/$(DATE)
export PYTHONPATH := $(CURDIR)
# GO_IN_DOCKER=1 runs the Go toolchain in a container. Needed where native Go
# cannot execute its own freshly built (unsigned) binaries, e.g. Windows with
# Smart App Control on. The repo is mounted so bench can write eval/results/.
ifeq ($(GO_IN_DOCKER),1)
GO_IMAGE ?= golang:1.24
GO_RUN = docker run --rm -v "$(CURDIR):/repo" -w /repo/correlator -e GOFLAGS=-buildvcs=false $(GO_IMAGE)
GO = $(GO_RUN) go
GOFMT = $(GO_RUN) gofmt
else
GO ?= go
GOFMT ?= gofmt
endif

# Local images: a tag other than `latest` keeps imagePullPolicy at IfNotPresent,
# so kind uses the loaded image instead of pulling (the registry may be private).
IMAGE_REGISTRY ?= clearpath.local
IMAGE_TAG ?= dev
# Chart versions verified together on the local cluster (bump deliberately).
LINKERD_CHART ?= 2026.11.2
KPS_CHART ?= 93.4.0
LOKI_CHART ?= 7.6.0
TEMPO_CHART ?= 1.24.4
CHAOS_MESH_CHART ?= 2.8.8

.PHONY: help test rules-test llm-up eval-llm deploy-clearpath e2e-live lint typecheck bench eval demo images up-local down chaos aws-up aws-down

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

test: ## unit + property tests (Python and Go), type check
	$(PY) -m pytest -q
	cd correlator && $(GO) vet ./... && $(GO) test -count=1 ./...
	$(PY) -m mypy

# same Prometheus version the cluster runs
PROM_IMAGE ?= quay.io/prometheus/prometheus:v3.16.0
rules-test: ## promtool: lint alerting/SLO rules and run their unit tests (Docker)
	$(PY) scripts/extract_rules.py var/rules
	docker run --rm -v "$(CURDIR):/repo" -w /repo --entrypoint promtool $(PROM_IMAGE) check rules var/rules/alert-rules.yaml var/rules/slo-rules.yaml
	docker run --rm -v "$(CURDIR):/repo" -w /repo --entrypoint promtool $(PROM_IMAGE) test rules observability/tests/symptoms_test.yaml observability/tests/slo_test.yaml

typecheck: ## mypy only
	$(PY) -m mypy

lint: ## ruff + gofmt + terraform fmt (if installed)
	$(PY) -m ruff check . && $(PY) -m ruff format --check .
	cd correlator && test -z "$$($(GOFMT) -l .)"
	-terraform fmt -check -recursive infra/terraform

bench: ## correlator throughput / latency / memory / percolation sweep
	cd correlator && $(GO) run ./cmd/bench -out ../eval/results/bench_correlator.json

eval: ## detection -> localization -> end-to-end; writes $(OUT)/{metrics.json,report.md} and README table
	$(PY) -m detect.evaluate $(OUT)
	$(PY) -m localize.evaluate $(OUT)
	$(PY) -m eval.harness $(OUT)
	@# a symlink where supported; Git Bash's `ln` would copy *into* an existing dir
	rm -rf eval/results/latest && (MSYS=winsymlinks:nativestrict ln -s $(notdir $(OUT)) eval/results/latest 2>/dev/null || cp -r $(OUT) eval/results/latest)

# Local open-weights LLM for the (c)-(e) systems. Qwen2.5-7B-Instruct is
# Apache-2.0 and fits an 8 GB GPU at Q4; GPU_FLAG= runs it on CPU (much slower).
OLLAMA_IMAGE ?= ollama/ollama:0.40.16
LLM_MODEL ?= qwen2.5:7b-instruct
GPU_FLAG ?= --gpus all
llm-up: ## start Ollama in Docker and pull the open-source model
	docker start clearpath-ollama >/dev/null 2>&1 || docker run -d --name clearpath-ollama $(GPU_FLAG) -p 127.0.0.1:11434:11434 -v clearpath-ollama:/root/.ollama $(OLLAMA_IMAGE)
	docker exec clearpath-ollama ollama pull $(LLM_MODEL)
	@# let the agent pod reach it by name when the kind cluster exists
	-docker network connect kind clearpath-ollama 2>/dev/null

eval-llm: ## eval including the LLM systems (c)-(e) and LLM red team, on the local model (needs llm-up)
	CLEARPATH_LLM=ollama CLEARPATH_MODEL=$(LLM_MODEL) OLLAMA_HOST=http://127.0.0.1:11434 $(MAKE) eval

demo: ## replay one held-out incident end to end (mock ServiceNow), then approve
	@# only the demo's own state: var/ also holds the Linkerd CA (var/linkerd), which must survive
	rm -rf var/state var/audit.jsonl && $(PY) -m agent.cli replay --seed 10007
	$(PY) -m agent.cli approve inc-10007 --user $${USER:-$$USERNAME}
	$(PY) -m agent.cli audit-verify

up-local: ## kind + Linkerd + Online Boutique + kube-prometheus-stack + Loki + Tempo + Chaos Mesh + Clearpath
	kind get clusters | grep -q clearpath || kind create cluster --config deploy/kind.yaml
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm repo add grafana https://grafana.github.io/helm-charts
	helm repo add chaos-mesh https://charts.chaos-mesh.org
	helm repo add linkerd-edge https://helm.linkerd.io/edge
	@# a refresh only: on a slow link the large prometheus-community index can time
	@# out; cached indexes still install (and a missing one fails loudly below)
	helm repo update || echo "WARNING: helm repo update failed; continuing with cached chart indexes"
	@# Linkerd first, so Online Boutique pods are created with their proxies (the SLI source).
	@# Install once only: every `helm upgrade` of the control plane regenerates its webhook
	@# certs and restarts it, which once caused a mesh-wide outage. Upgrade deliberately.
	bash scripts/linkerd-certs.sh var/linkerd
	helm status linkerd-crds -n linkerd >/dev/null 2>&1 || helm upgrade --install linkerd-crds linkerd-edge/linkerd-crds --version $(LINKERD_CHART) -n linkerd --create-namespace --set installGatewayAPI=true --wait
	helm status linkerd-control-plane -n linkerd >/dev/null 2>&1 || helm upgrade --install linkerd-control-plane linkerd-edge/linkerd-control-plane --version $(LINKERD_CHART) -n linkerd 	  --set-file identityTrustAnchorsPEM=var/linkerd/ca.crt --set-file identity.issuer.tls.crtPEM=var/linkerd/issuer.crt 	  --set-file identity.issuer.tls.keyPEM=var/linkerd/issuer.key --wait --timeout 10m
	kubectl create ns boutique --dry-run=client -o yaml | kubectl apply -f -
	kubectl annotate ns boutique linkerd.io/inject=enabled --overwrite
	@# first install only: re-applying would reset frontend to 1 replica and kill a pod
	kubectl -n boutique get deploy frontend >/dev/null 2>&1 || kubectl -n boutique apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/v0.10.1/release/kubernetes-manifests.yaml
	@# two frontends, so "lose half the frontend" is absorbed by redundancy (chaos/expectations.yaml)
	kubectl -n boutique scale deploy/frontend --replicas=2
	helm upgrade --install kps prometheus-community/kube-prometheus-stack --version $(KPS_CHART) -n monitoring --create-namespace -f observability/kps-values.yaml --wait
	helm upgrade --install loki grafana/loki --version $(LOKI_CHART) -n monitoring -f observability/loki-values.yaml
	helm upgrade --install tempo grafana/tempo --version $(TEMPO_CHART) -n monitoring
	helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh --version $(CHAOS_MESH_CHART) -n chaos-mesh --create-namespace --set chaosDaemon.runtime=containerd --set chaosDaemon.socketPath=/run/containerd/containerd.sock
	kubectl apply -f observability/linkerd-podmonitor.yaml
	kubectl apply -f observability/prometheus/
	$(MAKE) deploy-clearpath
	kubectl -n boutique rollout status deploy --timeout=300s

deploy-clearpath: ## build the images, load them into kind and (re)deploy only the Clearpath chart
	$(MAKE) images
	kind load docker-image $(IMAGE_REGISTRY)/clearpath-correlator:$(IMAGE_TAG) $(IMAGE_REGISTRY)/clearpath-agent:$(IMAGE_TAG) --name clearpath
	@# one-time migration to the persistent audit volume: an existing RollingUpdate Deployment keeps
	@# API-defaulted rollingUpdate fields that server-side apply cannot clear (invalid with Recreate)
	kubectl -n clearpath patch deploy clearpath-agent --type=json -p='[{"op":"replace","path":"/spec/strategy","value":{"type":"Recreate"}}]' >/dev/null 2>&1 || true
	helm upgrade --install clearpath deploy/helm/clearpath -n clearpath --create-namespace 	  -f deploy/helm/clearpath/values-local.yaml --set image.registry=$(IMAGE_REGISTRY) --set image.tag=$(IMAGE_TAG) --wait
	@# pick up a rebuilt image with the same tag
	kubectl -n clearpath rollout restart deploy/clearpath-agent deploy/clearpath-correlator
	kubectl -n clearpath rollout status deploy/clearpath-agent deploy/clearpath-correlator --timeout=180s

images: ## build the correlator and agent images locally (what up-local loads into kind)
	docker build -t $(IMAGE_REGISTRY)/clearpath-correlator:$(IMAGE_TAG) correlator
	docker build -t $(IMAGE_REGISTRY)/clearpath-agent:$(IMAGE_TAG) -f Dockerfile.agent .

e2e-live: ## live end-to-end: take paymentservice down, diagnose, approve, execute, verify recovery (~10 min)
	bash scripts/e2e-live.sh paymentservice

chaos: ## chaos suite with recovery/alert/budget assertions against the up-local cluster
	kubectl -n monitoring port-forward svc/kps-kube-prometheus-stack-prometheus 9090:9090 >/dev/null 2>&1 & pf=$$!; \
	  trap 'kill $$pf' EXIT; sleep 4; $(PY) chaos/run_suite.py --prom http://localhost:9090 --out $(OUT)

down: ## delete the kind cluster
	kind delete cluster --name clearpath

aws-up: ## PAID: provision EKS etc. Asks for confirmation. See docs/COST.md
	@read -p "This creates billable AWS resources (see docs/COST.md). Type 'yes': " a; [ "$$a" = yes ]
	cd infra/terraform/envs/dev && terraform init && terraform apply

aws-down: ## destroy everything aws-up created, then run the teardown checklist
	cd infra/terraform/envs/dev && terraform destroy
	@echo "Now run the checklist in docs/COST.md#teardown (orphaned ELBs/EBS/ENIs, NAT EIPs, CloudWatch logs)."
