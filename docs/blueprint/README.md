# Akshara Blueprint

**The Original Design Notes**

---

## What Is This?

This directory contains the **original design documentation** for Akshara. These documents define the vision, architecture, design decisions, and technical rationale for the entire platform.

**Status:** Design Authority — These documents represent the foundational thinking behind Akshara.

---

## How to Use This

### For Evaluators & Architects
Start here to understand **why** Akshara exists and **why** it's designed this way:

1. **[Product Vision](product/vision.md)** — What problem we're solving
2. **[System Overview](core/system-overview.md)** — Three-layer architecture (L0/L1/L2)
3. **[Design Decisions](core/design-decisions/)** — Key architectural choices

### For Implementers
The **specifications** (`specs/`) contain normative requirements derived from these documents:

- **Blueprint** → Why it exists, design rationale
- **Specs** → What to implement (MUST/SHOULD/MAY), algorithms, test vectors

### For Product People
- **[Features](product/features.md)** — Platform capabilities
- **[Personas](product/persona.md)** — Target users
- **[Deployment Models](platform/deployment-models.md)** — How it's deployed

---

## Contents

| Directory | Content |
|-----------|---------|
| **[product/](product/)** | Vision, features, personas |
| **[core/](core/)** | System overview, design decisions, internals |
| **[identity/](identity/)** | Tiered identity model, BIP-39, identity graphs |
| **[platform/](platform/)** | Primitives, deployment models, linked graphs |
| **[synchronization/](synchronization/)** | Causality, sync protocol (Satyātā grammar) |
| **[sdk/](sdk/)** | SDK core concepts, Rust API guide |

---

## Relationship to Other Docs

| Directory | Purpose |
|-----------|---------|
| **[blueprint/](./)** | Original design notes (this directory) |
| **[specs/](../specs/)** | Implementation specifications (derived from blueprint) |
| **[guides/](../guides/)** | Tutorials and how-tos (to be created) |
| **[api/](../api/)** | Rust API reference (auto-generated) |

---

## Note to Contributors

These documents represent the **original design thinking** for Akshara. They explain the **why** behind architectural choices.

### Relationship to Specifications

| Blueprint | Specifications |
|-----------|---------------|
| Design intent, rationale | Implementation requirements |
| High-level architecture | Algorithms, test vectors |
| Product capabilities | Normative MUST/SHOULD/MAY |

**If they conflict:** The **specifications** take precedence for implementation details. The blueprint is the design origin, but specs reflect the current, implemented reality.

When in doubt:
- **Why was this designed?** → Read blueprint
- **How do I implement this?** → Read specs

---

**Last Updated:** See individual document dates
