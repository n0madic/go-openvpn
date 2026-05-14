# Integration-test orchestration. Targets in execution order:
#
#   make pki    # one-time PKI generation (runs openssl + openvpn in docker)
#   make up     # build and start the OpenVPN 2.6 server (background)
#   make test   # run `go test -tags=integration ./...`
#   make bench  # run all benchmarks (pure-tunnel + netstack) against the live server
#   make logs   # tail server logs
#   make down   # stop and remove the server
#   make all    # pki + up + test + down (one-shot CI flow)
#   make clean  # tear down, wipe PKI

SHELL := /bin/bash
.PHONY: pki up wait down logs test bench all clean

# Override on the command line: `make bench BENCH=BenchmarkTunnelUDPEchoRoundtrip`
BENCH ?= .
BENCHTIME ?= 3s

pki:
	./gen-pki.sh

up: pki
	docker compose up -d --build

wait:
	@printf "Waiting for OpenVPN server to be ready"
	@for i in $$(seq 1 30); do \
	    if docker compose logs openvpn 2>&1 | grep -q "Initialization Sequence Completed"; then \
	        echo " — ready."; \
	        exit 0; \
	    fi; \
	    printf "."; \
	    sleep 1; \
	done; \
	echo " — TIMED OUT. Last logs:"; \
	docker compose logs openvpn | tail -30; \
	exit 1

down:
	-docker compose down --remove-orphans

logs:
	docker compose logs -f openvpn

test: wait
	cd ../.. && go test -tags=integration -count=1 -timeout=120s -v ./test/integration/...
	cd ../../pkg/netstack && go test -tags=integration -count=1 -timeout=120s -v ./...
	cd ../../cmd/openvpn2socks && go test -tags=integration -count=1 -timeout=120s -v ./...

# Run all benchmarks against the live server. Skips regular tests with
# `-run=^$$`. Override the bench filter / duration on the command line:
#   make bench BENCH=BenchmarkTunnelUDPEchoRoundtrip BENCHTIME=5s
bench: wait
	cd ../.. && go test -tags=integration -bench=$(BENCH) -benchmem \
	    -benchtime=$(BENCHTIME) -run=^$$ -timeout=600s ./test/integration/...
	cd ../../pkg/netstack && go test -tags=integration -bench=$(BENCH) -benchmem \
	    -benchtime=$(BENCHTIME) -run=^$$ -timeout=600s ./...

all: up wait test down

clean: down
	rm -rf ./pki
