# artoo — thin wrapper over build.zig (docs/SPEC.md §12).
#
#   make            debug build
#   make test       offline tests + zig fmt --check + Linux cross-builds
#                   + leak-check (private terms, when the list exists)
#   make leak-check private words from ../homelab/private-terms
#   make install    ReleaseSafe build → ~/.local/bin/artoo + fish completion
#                   (COMPLETION=zsh|bash|none to change or skip it)
#   make run ARGS="gw info"

ZIG    ?= zig
PREFIX ?= $(HOME)/.local
BINDIR := $(PREFIX)/bin

# Shell completion installed with the binary (SPEC §3.5); the script asks
# the binary on every Tab, so it never goes stale.
COMPLETION      ?= fish
XDG_CONFIG_HOME ?= $(HOME)/.config
COMPLETION_fish := $(XDG_CONFIG_HOME)/fish/completions/artoo.fish
COMPLETION_zsh  := $(PREFIX)/share/zsh/site-functions/_artoo
COMPLETION_bash := $(PREFIX)/share/bash-completion/completions/artoo
COMPLETION_FILE := $(COMPLETION_$(COMPLETION))

.DEFAULT_GOAL := build
.PHONY: build test fmt install run clean leak-check

build:
	@$(ZIG) build

test: leak-check
	@$(ZIG) build test fmt cross

leak-check:
	@scripts/leak-check.sh

fmt:
	@$(ZIG) fmt build.zig build.zig.zon src

# Stage next to the target and rename: replacing a running binary in place
# can fail with "text file busy".
install:
ifneq ($(COMPLETION),none)
	@test -n "$(COMPLETION_FILE)" || { echo "COMPLETION must be fish, zsh, bash or none"; exit 2; }
endif
	@$(ZIG) build -Doptimize=ReleaseSafe --prefix zig-out/release
	@install -d $(BINDIR)
	@install -m 0755 zig-out/release/bin/artoo $(BINDIR)/.artoo.tmp
	@mv $(BINDIR)/.artoo.tmp $(BINDIR)/artoo
	@echo "installed $(BINDIR)/artoo ($$($(BINDIR)/artoo --version))"
ifneq ($(COMPLETION),none)
	@install -d $(dir $(COMPLETION_FILE))
	@$(BINDIR)/artoo completion $(COMPLETION) > $(COMPLETION_FILE)
	@echo "installed $(COMPLETION_FILE) ($(COMPLETION) completion)"
endif

run: build
	@./zig-out/bin/artoo $(ARGS)

clean:
	@rm -rf zig-out .zig-cache
