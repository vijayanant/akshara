# Cryptographic Composition: The Order of Secrecy

A common mistake in distributed systems is to treat Encryption (Privacy) and Signatures (Identity) as independent layers. As noted in the Explorer's Log, manual composition leads to the "Surreptitious Forwarding" attack. To build a truly sovereign vault, we must fuse these layers into a single, context-aware operation.

## 1. The Standard: Encrypt-then-Sign
Sovereign mandates the **Encrypt-then-Sign** pattern. 
1.  **Encryption:** The plaintext is first encrypted using **XChaCha20-Poly1305** (AEAD).
2.  **Signature:** The resulting **Ciphertext** is then signed using the author's **Ed25519** key.

### 1.1 Why this Order?
*   **No Spying:** If we signed then encrypted, the signature would be hidden inside the vault. The Relay couldn't verify the author's right to post without seeing the content. 
*   **No Forwarding:** By signing the ciphertext, the author binds their identity to the specific encrypted blob. If an attacker tries to re-encrypt your "signed letter" for someone else, the signature on the outside will no longer match the new ciphertext.

## 2. Binding Context via AEAD (Associated Data)
Encryption in Sovereign is never "Generic." We use the **Associated Data (AD)** field of the AEAD algorithm to anchor every secret to its place in the universe.

When encrypting a block, the SDK MUST feed the following into the AD:
*   **GraphID:** Binds the content to the specific project.
*   **Author Public Key:** Binds the content to the specific creator.
*   **Causal Context (Previous CID):** Binds the content to its specific moment in history.

**Result:** An attacker cannot "cut and paste" a valid encrypted block from a Medical Graph into a Chat Graph. The decryption will fail because the GraphID in the context won't match the Tag.

## 3. Algorithm Choice: User over Cloud
We prioritize **ChaCha20-Poly1305** over AES-GCM. 
*   **The Rationale:** AES is fast on servers but dangerous in software-only environments (timing attacks). ChaCha20 is designed to be fast and immune to timing attacks on **any CPU** (mobile phones, Raspberry Pis). 
*   **The Philosophy:** Sovereign is built for the **Edge**, not the Cloud. We choose the algorithm that protects the user's phone, not the provider's data center.

***

**Architect’s Note:** *This is our 'No Black Box' policy for crypto. We aren't just 'using encryption'; we are anchoring every bit of secret data to its causal and social context. It makes the 'Dumb Warehouse' (Relay) physically incapable of manipulating our state.*
