.PHONY: all test fmt lint check verify

all: verify

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

coverage:
	cargo tarpaulin --out Xml --out Html --fail-under 55.67

# The "Golden Command" for local dev
verify: fmt lint test
