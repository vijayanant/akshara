# Asynchronous Sharing: The Pre-Key Registry

Sharing in a sovereign system is a **Key Transport** problem. As noted in the Explorer's Log, we must move from "Telephone" logic (both parties online) to "Mailbox" logic (asynchronous coordination). Sovereign achieves this through the **Pre-Key Registry**.

## 1. The Bottleneck: The Offline Handshake
To create a `Lockbox` for Alice, Bob needs Alice's **Public Encryption Key** (X25519). If Alice is offline and Bob doesn't have her in his local address book, the "Courier" model fails.

## 2. The Solution: Pre-Key Bundles
Every user device generates a pool of signed, one-time-use encryption keys—**Pre-Keys**—and uploads them to their **Identity Outpost** on the Relay.

A **Pre-Key Bundle** consists of:
1.  **Static Identity Key:** The long-lived public key of the device.
2.  **Ephemeral Pre-Keys:** A collection of one-time keys, each signed by the Static Key.

## 3. The "Mailbox" Interaction Flow
When Bob wants to share a graph with Alice:
1.  **Fetch:** Bob's SDK asks the Relay for Alice's current Pre-Key Bundle.
2.  **Verify:** Bob's SDK verifies the signature on the bundle against Alice's **Identity Graph**.
3.  **Consume:** Bob's SDK takes ONE of Alice's one-time keys and uses it to perform the Diffie-Hellman exchange.
4.  **Seal:** Bob creates the Lockbox and pushes it to Alice's inbox.
5.  **Done:** When Alice eventually wakes up, she fetches the Lockbox, sees which one-time key was used, and opens the vault.

## 4. Privacy Boundary
The Relay acts as the "Dumb Helper." It holds the mailbox but:
*   It cannot read the Pre-Keys (they are public keys, not secrets).
*   It cannot see the content of the Lockbox.
*   It only facilitates the **Handshake at Rest**.

## 5. Security: Forward Secrecy
By using one-time Pre-Keys, Sovereign ensures that even if Alice's device is compromised a year from now, the attacker cannot use Alice's current keys to decrypt *past* sharing handshakes. The history remains a tomb.

***

**Architect’s Note:** *This is the 'Asynchronous Penalty' we discussed. To stay decentralized but stay useful, we accept a 'Dumb Helper' (the Relay) to hold our mailbox. It’s the only way to build a professional collaboration tool that works in the real world of sleeping users and intermittent Wi-Fi.*
