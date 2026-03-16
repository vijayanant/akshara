# SDK Core Concepts: The Developer's Mental Model

Welcome to the Frontier. Building on Sovereign is fundamentally different from building on the traditional cloud. To use this SDK effectively, you must leave the "SaaS Mental Model" behind and embrace the physics of the **Universal Graph**.

---

## 1. Don't Think Files, Think Graphs
In a legacy app, you save a "file" to a "folder." In Sovereign, every piece of data lives in a **Graph**.
*   **Cohesion:** A Graph is a collection of blocks that share a single permission boundary (a `GraphKey`).
*   **Interoperability:** A "Chat" isn't a different *thing* from a "Document." They are both Graphs. This allows a block in your Chat Graph to point to a block in your Patient Record Graph seamlessly.

## 2. You Handle Plaintext, We Handle the Vault
As an App Developer, you should almost never see a CID, a Signature, or a Ciphertext.
*   **The Abstraction:** You interact with the **GraphHandle**.
*   **Automatic Privacy:** When you write data, the SDK canonicalizes, encrypts, and signs it automatically. When you read data, the SDK verifies the authority and decrypts it before it reaches your code.
*   **Structural Safety:** The SDK ensures that every block you write is structurally sound and follows the graph's Constitution.

## 3. Offline is the Default
In Sovereign, there is no "Network Error" when saving data.
*   **Local First:** The "Source of Truth" is the user’s local device. Every write is a local commit.
*   **Background Sync:** The Relay is merely a courier. The SDK manages the **Sync Pipeline** in the background to reconcile your local reality with the rest of the team.
*   **Conflict as an Event:** Conflicts aren't bugs; they are branches in history. Your app should be designed to show these branches to the user, not "Prosecute" one as the winner.

## 4. The Projection: Your View of the Truth
A Graph is an immutable log of every change ever made. You don't "query" the graph like a database; you **Project** it.
*   **The Flow:** `DAG Blocks -> Projector -> App State`.
*   **Efficiency:** The SDK handles incremental projections. If a new chat message arrives, the SDK doesn't re-read the whole history; it just "folds" the new block into your existing list.

## 5. Authority is Mathematical
You don't "Login" to Sovereign. You **Open a Seed**.
*   **Durable Identity:** Your 12-word mnemonic is your absolute identity.
*   **Capability Auditing:** Every action your app sees has been "Audited" by the SDK. If a block appears in your view, the SDK has already proven that the author was authorized to write it.

***

**Architect’s Note:** *This is our 'Glass Abstraction.' We are hiding the cryptographic complexity, but we are exposing the causal reality. If a developer understands these five points, they can build anything from a simple notes app to a complex hospital coordination system.*
