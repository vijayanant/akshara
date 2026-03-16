# Akshara API Reference

**Status:** Auto-generated from Rust source

---

## What Is This?

This directory contains **API reference documentation** generated from the Rust source code.

Unlike specifications (which define the protocol) or guides (which teach usage), the API reference provides **detailed type and function documentation**.

---

## Planned Contents

### Crate Documentation
- [ ] **akshara-aadhaara** — Core cryptographic foundation
- [ ] **akshara-sdk** — High-level SDK for applications
- [ ] **akshara-relay** — Relay server implementation
- [ ] **akshara-wire** — Protocol buffer definitions

### Access Methods

#### Online (rustdoc)
```
cargo doc --open
```

#### Generated HTML
```
docs/api/aadhaara/
docs/api/sdk/
docs/api/relay/
```

---

## For Contributors

To regenerate API docs:

```bash
cd /Users/vj/workspace/sovereign/akshara
cargo doc --no-deps --output-dir docs/api
```

---

## Navigation

- **[Vision](../vision/)** — Philosophy, architecture, why
- **[Specifications](../specs/)** — Protocol requirements
- **[Guides](../guides/)** — Tutorials and how-tos
