# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Authors of KSec

CURDIR          := $(shell pwd)
GO_EXEC         := $(shell which go)
LOGNAME         := $(shell logname)
NETNEXT         := 0
DLV_EXEC         = $(GOPATH)/bin/dlv
DLV_LPORT       := 2345
DLV_RPORT       := $(shell expr $(DLV_LPORT) + $(NETNEXT))
KUBEARMOR_PID    = $(shell pgrep KSecMain)


.PHONY: build
build:
	cd $(CURDIR); go mod tidy
ifneq (, $(shell which bpftool))
ifneq (, $(wildcard /sys/kernel/btf/vmlinux))
	cd $(CURDIR); bpftool btf dump file /sys/kernel/btf/vmlinux format c > BPF/vmlinux.h || true
endif
ifneq (, $(shell which llvm-strip))
	if grep -q bpf '/sys/kernel/security/lsm'; then \
		cd $(CURDIR); go generate ./... || true; \
	fi
endif
endif
	cd $(CURDIR); go build -o KSecMain main.go

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -rf KSecMain
	cd $(CURDIR); find . -name .coverprofile | xargs -I {} rm {}

$(DLV_EXEC):
	go get -u github.com/go-delve/delve/cmd/dlv

.PHONY: debug-attach
debug-attach: $(DLV_EXEC)
ifeq ($(KUBEARMOR_PID), )
	$(error kubearmor must be running - execute 'make run' first)
endif
	sudo $(DLV_EXEC) attach $(KUBEARMOR_PID) --headless -l=:$(DLV_LPORT) --log --api-version 2 $(CURDIR)
