# Observability Standards: The "Eyes" of the Fortress

In a Sovereign system, observability is a double-edged sword. We need deep technical visibility to ensure **Integrity**, but we must strictly limit data collection to protect **Privacy**.

---

## 1. The Core Philosophy: "No Metadata, No Secrets"

Every piece of telemetry added to the codebase must be vetted against the **Satyata Audit**:
1.  **Is it a Secret?** (Keys, Nonces, Mnemonics, Plaintexts). **NEVER LOG.**
2.  **Is it PII?** (User names, Emails, IP addresses). **NEVER LOG.**
3.  **Is it Social Metadata?** (Who is talking to whom). **NEVER LOG in the Relay.**
4.  **Is it Debugging Physics?** (Latency, Cache Hits, Merkle Depth, Error Counts). **LOG AGGRESSIVELY.**

---

## 2. Log Level Hierarchy

We follow a strict semantic hierarchy for logs:

| Level | Audience | Requirement |
| :--- | :--- | :--- |
| **ERROR** | Operator | Critical system failure requiring human intervention (e.g., Disk Full). |
| **WARN** | Architect | Invariant violation that was handled but suggests a problem (e.g., Invalid Signature received). |
| **INFO** | User/Audit | High-level milestones (e.g., "Graph Created", "Sync Complete"). |
| **DEBUG** | Developer | Internal logic transitions (e.g., "Path resolved", "Block cached"). |
| **TRACE** | PhD/Security | Step-by-step mathematical execution (e.g., "SLIP-0010 level 3 derived"). |

---

## 3. Metrics (The Statistics of Truth)

We use `metrics` to track the health of the "Adhara" (Foundation).

### 3.1 Naming Convention
`sovereign.[module].[noun].[verb]`
*   *Example:* `sovereign.walker.path.resolve_latency`

### 3.2 Key Performance Indicators (KPIs)
*   **Availability:** Success/Failure rate of signatures and integrity checks.
*   **Latency:** Time taken for recursive Merkle path resolution.
*   **Scale:** Count of blocks and manifests handled per sync session.
*   **Efficiency:** Cache hit/miss ratio in the storage layer.

---

## 4. Tracing (The Request Journey)

We use `tracing` spans to follow logic across async boundaries and crate gates.

### 4.1 Span Rules
1.  **Boundary Spans:** Every public API method must have a `DEBUG` level span.
2.  **Internal Spans:** Complex recursive logic (like `GraphWalker`) must use `TRACE` level spans for each step.
3.  **Attributes:** Spans should include `id` or `graph_id`, but **never** keys.

---

## 5. Implementation Checklist for Developers

When adding a log or metric, ask:
*   [ ] Does this log entry allow an institution to reconstruct a user's social graph?
*   [ ] Does this metric expose the size of a user's private data?
*   [ ] Am I using the `?` (Debug) formatter on a type that might contain a secret?
*   [ ] Is there a counter to track how often this specific error occurs?

***

**Architect’s Note:** *Observability is not about watching our users; it is about watching our math. If the math is healthy, the users are safe.*
