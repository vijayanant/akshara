# The Knowledge Exchange: Unified DAG Reconciliation

Sovereign synchronization is a **Reconciliation of Truth** based on the grammar of **Satyātā**. We reject the "Request/Response" terminology of the institutional web and adopt a stateless, mathematical language for converging knowledge across any Directed Acyclic Graph (DAG).

---

## 1. The Unified Identifier: Lakshana (लक्षण)

A **Lakshana** is the defining mark of any addressable entity in the Sovereign Web. In our unified model, there is no structural difference between an Inbox and a Project; they are both graphs identified by a Lakshana.

*   **Inbox Lakshana:** Derived from the user's 24-word seed. It identifies a graph containing **Lockboxes** (invitations to other graphs).
*   **Data Lakshana:** Discovered within a Lockbox. It identifies a graph containing **Index** and **Data** blocks.

---

## 2. The Satyātā Grammar

The protocol consists of three immutable **Knowledge Nouns** and two pure **Mathematical Verbs**:

### 2.1 The Knowledge Nouns (State)
*   **Satyatā (सत्यता):** The State of Truth. Represents the latest signed snapshots (Heads) a peer currently stands upon for a given *Lakshana*.
*   **Abhāva (अभाव):** The State of Absence. The specific list of CIDs that are known to exist in the peer's frontier but are missing from the local store.
*   **Amsha (अंश):** The Portion. A single atomic bitstream (Manifest or Block) delivered to fill a gap.

### 2.2 The Reconciliation Verbs (Logic)
*   **Nirūpana (निरूपण):** Determination. The logic that compares two *Satyatā* states to determine the resulting *Abhāva*.
*   **Pradāna (प्रदान):** Provision. The act of yielding the *Amshas* required to transform absence into presence.

---

## 3. The Sovereign Lifecycle (The Convergent Path)

A device "re-born" from a 24-word seed follows a recursive path to total convergence:

### Phase I: Inbox Reconciliation (Blind Discovery)
1.  **Darshana (Presentation):** Peer presents its **Satyatā** for its **Inbox Lakshana**.
2.  **Nirūpana (Determination):** The other peer identifies the **Abhāva** (The missing Lockboxes).
3.  **Pradāna (Transmission):** The peer streams the **Amsha::Lockbox** items.

### Phase II: Key Rebirth (Authorization)
The SDK attempts to open the received portions using its `SecretIdentity`.
1.  **Success:** SDK now knows the **Data Lakshana** and the symmetric `GraphKey` for a new document.

### Phase III: Targeted Data Reconciliation (Sync)
1.  **Darshana (Presentation):** Peer presents **Satyatā** for a specific **Data Lakshana**.
2.  **Nirūpana (Determination):** The other peer identifies the **Abhāva** (Missing Merkle-diffs).
3.  **Pradāna (Transmission):** The peer streams the **Amsha::Manifest** and **Amsha::Block** items.

---

## 4. Security Invariants of the Exchange

1.  **Blindness:** The Relay never knows the user's Public Identity. It only sees the **Lakshana**.
2.  **Implicit Authorization:** The Relay does not "check permissions." Authorization is cryptographic: if you don't have the **Lakshana** and the **GraphKey**, the arriving *Amshas* are useless noise.
3.  **Reverse Topological Ordering:** **Amshas** are streamed "Head-First." This allows the SDK to verify the provenance of a portion *before* the portion itself arrives, preventing storage poisoning.

***

**Architect’s Note:** *By using the language of Satyātā, we move the conversation from 'Can I have your data?' to 'I have found a gap in my truth; please help me complete it.' This is the essence of a peer-to-peer reality.*
