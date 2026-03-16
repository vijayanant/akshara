# Causality, Time, and Conflict Resolution

In a decentralized web, physical time is a lie. Sovereign replaces "Wall-Clock Now" with **Causal Consistency**.

---

## 1. Establishing Order
We establish the timeline using the edges of the DAG:
*   **The Chain:** If Manifest B lists Manifest A as a parent, B happened after A. 
*   **The Fork:** If two manifests do not share a causal link, they are concurrent.

## 2. Satyata via Identity Anchors
To prevent "Ghost Edits" from stolen or revoked devices:
*   Every Manifest includes an `identity_anchor` (the CID of the author's current Identity Graph state).
*   **The Rule:** A document update is only valid if the author's Identity Timeline says they were authorized at the exact moment of authorship.

## 3. Deterministic Tie-Breaking (Law of the Jungle)
When two branches are concurrent (a Fork), and the app needs to choose a single "Winner":
1.  Compare the raw bytes of the conflicting **Manifest CIDs**.
2.  The CID with the **lexicographically lower value** wins.
3.  **Result:** Every SDK on earth will arrive at the same conclusion without ever talking to each other. Convergence is mathematical.

## 4. Preservation of History
Sovereign never "deletes" the losing branch of a fork. 
*   Both branches remain in the DAG.
*   This allows apps to show "Conflict Badges" and lets users manually merge divergent ideas when math isn't enough to solve a human disagreement.

***

**Architect’s Note:** *This is how we solve the 'No God of Time' problem. We replace the central server's clock with the logic of the graph. It turns 'Conflicts' into 'Events' that we can manage with math.*