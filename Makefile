GOVULNCHECK_VERSION := v1.6.0

.PHONY: all check test vet verify vulncheck tidy wasm clean lab-up lab-down lab-local lab-test

all: check

## check — runs every gate that CI runs on push/PR
check: verify vet test vulncheck

## verify — module checksum integrity (mirrors go mod verify in CI)
verify:
	go mod verify

## vet — static analysis (mirrors go vet ./... in CI)
vet:
	go vet ./...

## test — full test suite with race detector (mirrors go test in CI)
test:
	go test ./... -v -count=1 -race -timeout 120s

## vulncheck — vulnerability scan pinned to same version as CI
vulncheck:
	@which govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	govulncheck ./...

## tidy — ensure go.mod and go.sum are tidy
tidy:
	go mod tidy

## wasm — build the browser demo WASM binary
wasm:
	GOOS=js GOARCH=wasm go build -o demo/wimse.wasm ./cmd/demo-wasm/
	@GOROOT=$$(go env GOROOT); \
	if [ -f "$$GOROOT/lib/wasm/wasm_exec.js" ]; then \
		cp "$$GOROOT/lib/wasm/wasm_exec.js" demo/wasm_exec.js; \
	else \
		cp "$$GOROOT/misc/wasm/wasm_exec.js" demo/wasm_exec.js; \
	fi
	@echo "WASM built. Run: cd demo && python3 -m http.server 8000"

## hooks — activate the pre-push git hook for this clone (run once after cloning)
hooks:
	git config core.hooksPath .githooks
	@echo "Git pre-push hook enabled."

## lab-up — local multi-cloud lab: Floci AWS + GCP emulators, two trust domains, observer on :8080
LAB_COMPOSE := docker compose -f deploy/local-multicloud/docker-compose.yml
lab-up:
	$(LAB_COMPOSE) up --build -d
	@echo "Observer: http://localhost:8080   (make lab-down to stop)"

## lab-down — stop the lab and remove its containers and networks
lab-down:
	$(LAB_COMPOSE) down --remove-orphans

## lab-local — run the lab as local processes (no Docker, join-token attestation, no cloud steps)
lab-local:
	./deploy/local-multicloud/run-local.sh

## lab-test — unit tests for the lab packages
lab-test:
	go test ./internal/lab/... -v -count=1 -race

## clean — remove generated WASM artifacts
clean:
	rm -f demo/wimse.wasm demo/wasm_exec.js
