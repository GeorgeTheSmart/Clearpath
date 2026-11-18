# Clearpath. `make test eval` runs entirely offline; cluster/AWS targets need tools.
SHELL := /bin/bash
PY ?= python3
DATE := $(shell date -u +%F)
OUT ?= eval/results/$(DATE)
export PYTHONPATH := $(CURDIR)

.PHONY: help test lint typecheck bench eval demo up-local down chaos aws-up aws-down

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

test: ## unit + property tests (Python and Go), type check
	$(PY) -m pytest -q
	cd correlator && go vet ./... && go test -count=1 ./...
	$(PY) -m mypy

typecheck: ## mypy only
	$(PY) -m mypy

lint: ## ruff + gofmt + terraform fmt (if installed)
	ruff check . && ruff format --check .
	test -z "$$(gofmt -l correlator)"
	-terraform fmt -check -recursive infra/terraform

bench: ## correlator throughput / latency / memory / percolation sweep
	cd correlator && go run ./cmd/bench -out ../eval/results/bench_correlator.json

eval: ## detection -> localization -> end-to-end; writes $(OUT)/{metrics.json,report.md} and README table
	$(PY) -m detect.evaluate $(OUT)
	$(PY) -m localize.evaluate $(OUT)
	$(PY) -m eval.harness $(OUT)
	ln -sfn $(DATE) eval/results/latest

demo: ## replay one held-out incident end to end (mock ServiceNow), then approve
	rm -rf var && $(PY) -m agent.cli replay --seed 10007
	$(PY) -m agent.cli approve inc-10007 --user $$USER
	$(PY) -m agent.cli audit-verify

up-local: ## kind + Online Boutique + kube-prometheus-stack + Loki + Tempo + Chaos Mesh + Clearpath
	kind get clusters | grep -q clearpath || kind create cluster --config deploy/kind.yaml
	kubectl create ns boutique --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n boutique apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/v0.10.1/release/kubernetes-manifests.yaml
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm repo add grafana https://grafana.github.io/helm-charts
	helm repo add chaos-mesh https://charts.chaos-mesh.org
	helm repo update
	helm upgrade --install kps prometheus-community/kube-prometheus-stack -n monitoring --create-namespace -f observability/kps-values.yaml --wait
	helm upgrade --install loki grafana/loki -n monitoring -f observability/loki-values.yaml
	helm upgrade --install tempo grafana/tempo -n monitoring
	helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh -n chaos-mesh --create-namespace --set chaosDaemon.runtime=containerd --set chaosDaemon.socketPath=/run/containerd/containerd.sock
	kubectl apply -f observability/prometheus/
	helm upgrade --install clearpath deploy/helm/clearpath -n clearpath --create-namespace

chaos: ## chaos suite with recovery/alert/budget assertions (needs up-local + port-forward 9090)
	$(PY) chaos/run_suite.py --prom http://localhost:9090 --out $(OUT)

down: ## delete the kind cluster
	kind delete cluster --name clearpath

aws-up: ## PAID: provision EKS etc. Asks for confirmation. See docs/COST.md
	@read -p "This creates billable AWS resources (see docs/COST.md). Type 'yes': " a; [ "$$a" = yes ]
	cd infra/terraform/envs/dev && terraform init && terraform apply

aws-down: ## destroy everything aws-up created, then run the teardown checklist
	cd infra/terraform/envs/dev && terraform destroy
	@echo "Now run the checklist in docs/COST.md#teardown (orphaned ELBs/EBS/ENIs, NAT EIPs, CloudWatch logs)."
