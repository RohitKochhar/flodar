.PHONY: install-hooks check fmt clippy test build audit

install-hooks:
	git config core.hooksPath .githooks
	@echo "Pre-commit hook installed. It will run on every 'git commit'."

check: fmt clippy test build

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all

build:
	cargo build --release --all

audit:
	cargo audit
