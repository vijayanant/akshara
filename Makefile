.PHONY: all test fmt lint check verify

all: verify

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

coverage:
	cargo llvm-cov --workspace --html
	cargo llvm-cov report --cobertura --output-path cobertura.xml --fail-under-lines 85.00

# The "Golden Command" for local dev
verify: fmt lint test
