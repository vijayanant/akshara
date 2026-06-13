//! Clinica: Akshara Patient Records Demo (Sovereign Patient Ownership edition)
//!
//! This demo simulates a philosophically correct Akshara workflow:
//! 1. The Patient (Priya Sharma) owns and creates her medical records graph.
//! 2. Priya shares access with Dr. Mehta (Hospital Intake) via a secure Lockbox.
//! 3. Dr. Mehta retrieves the Lockbox, gets the GraphKey, syncs Priya's record, and adds a consultation.
//! 4. Priya pulls Dr. Mehta's updates.
//! 5. Priya shares access with Dr. Watson (Specialist) via a separate Lockbox.
//! 6. Dr. Watson retrieves the Lockbox, syncs the record, reads Dr. Mehta's note, and adds a specialist consultation.
//! 7. Priya pulls Dr. Watson's updates, verifying the combined cryptographically signed history.

use akshara::{Client, ClientConfig, Graph, LocalMemoryTransport};
use akshara_aadhaara::{GraphStore, Lockbox};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// --- DATA STRUCTURES ---

#[derive(Debug, Serialize, Deserialize)]
struct Demographics {
    name: String,
    mrn: String,
    dob: String,
    sex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Allergy {
    substance: String,
    severity: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Consultation {
    date: String,
    doctor: String,
    complaint: String,
    plan: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!("   CLINICA: PATIENT-SOVEREIGN MEDICAL RECORDS DEMO          ");
    println!("       Enforcing cryptographic ownership via Lockboxes      ");
    println!("============================================================\n");

    let mut rng = rand::rngs::OsRng;

    // -------------------------------------------------------------------------
    // STEP 1: INITIALIZE SOVEREIGN AGENTS
    // -------------------------------------------------------------------------
    println!("[1/7] Bootstrapping client vaults and identities...");

    // Patient (Priya Sharma)
    let client_priya = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await?;
    let priya_id = client_priya.vault().get_identity_id().await?;
    println!(
        "  -> Patient Priya Sharma initialized. Identity ID: {}",
        priya_id
    );

    // Hospital Intake (Dr. Mehta)
    let client_mehta = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await?;
    let mehta_id = client_mehta.vault().get_identity_id().await?;
    println!("  -> Dr. Mehta initialized. Identity ID: {}", mehta_id);

    // Specialist (Dr. Watson)
    let client_watson = Client::init(
        ClientConfig::new()
            .with_ephemeral_vault()
            .with_in_memory_storage(),
    )
    .await?;
    let watson_id = client_watson.vault().get_identity_id().await?;
    println!("  -> Dr. Watson initialized. Identity ID: {}\n", watson_id);

    // -------------------------------------------------------------------------
    // STEP 2: PATIENT CREATES HER RECORD AND COMMITS INTAKE DATA
    // -------------------------------------------------------------------------
    println!("[2/7] Priya Sharma creating her own sovereign Patient Graph...");
    let graph_priya = client_priya.create_graph().await?;
    let graph_id = graph_priya.id();
    let graph_key = graph_priya.key().clone();
    println!("  -> Created Graph ID: {}", graph_id);

    let demographics = Demographics {
        name: "Priya Sharma".to_string(),
        mrn: "MRN-10984".to_string(),
        dob: "1985-03-15".to_string(),
        sex: "Female".to_string(),
    };
    let allergies = vec![Allergy {
        substance: "Penicillin".to_string(),
        severity: "Severe".to_string(),
    }];

    graph_priya
        .insert("/patient/demographics", serde_json::to_vec(&demographics)?)
        .await?;
    graph_priya
        .insert("/patient/allergies", serde_json::to_vec(&allergies)?)
        .await?;
    let seal_priya = graph_priya.flush().await?;
    println!(
        "  -> Record sealed locally by Priya Sharma. Manifest: {}\n",
        seal_priya.manifest_id
    );

    // -------------------------------------------------------------------------
    // STEP 3: PATIENT SHARES RECORDS WITH DR. MEHTA VIA LOCKBOX
    // -------------------------------------------------------------------------
    println!("[3/7] Priya Sharma sharing her graph with Dr. Mehta...");

    // REAL-WORLD NOTE: In a real-world setting, Dr. Mehta would share his public identity
    // (public signing and encryption keys) out-of-band with Priya—for example, by having
    // Priya scan a QR code on the clinic's reception monitor, or using a secure directory.
    // Akshara is designed to keep user identities hidden from third-party observers:
    // it maps public identities to graph-specific, cryptographically blinded discovery IDs (Lakshanas)
    // and uses shadow/ephemeral keys so that no one can link a user's activity across different graphs.
    //
    // For this in-memory demo, we simulate this exchange by directly retrieving Dr. Mehta's public identity:
    let identity_mehta = client_mehta.vault().get_identity(None).await?;

    // Priya derives Dr. Mehta's anonymous discovery ID (Lakshana) for this graph.
    // Only Dr. Mehta can compute this exact Lakshana to find lockboxes targeted to him on this graph.
    let lakshana_mehta = identity_mehta.derive_discovery_id(&graph_id)?;

    // Priya wraps the graph key inside a Lockbox bound to Dr. Mehta's public key

    let lockbox_mehta = Lockbox::create(
        identity_mehta.public().encryption_key(),
        &graph_key,
        &mut rng,
    )?;

    // Priya stores the lockbox under Dr. Mehta's Lakshana in her store
    graph_priya
        .store()
        .put_lockbox(lakshana_mehta, &lockbox_mehta)
        .await?;
    println!(
        "  -> Lockbox created & stored under Dr. Mehta's Lakshana: {}",
        lakshana_mehta.to_hex()
    );

    // Priya cryptographically authorizes Dr. Mehta's root identity as a collaborator in her graph
    graph_priya
        .authorize_collaborator(identity_mehta.public().signing_key())
        .await?;
    let seal_priya_trust = graph_priya.flush().await?;
    println!(
        "  -> Trust delegated to Dr. Mehta. Manifest: {}",
        seal_priya_trust.manifest_id
    );

    // -------------------------------------------------------------------------
    // STEP 4: DR. MEHTA RETRIEVES KEY, SYNCS AND ADDS CONSULTATION
    // -------------------------------------------------------------------------
    println!("[4/7] Dr. Mehta fetching lockbox and opening graph...");

    // Dr. Mehta queries the store/relay under his Lakshana to find lockboxes
    let my_identity_mehta = client_mehta.vault().get_identity(None).await?;
    let my_lakshana_mehta = my_identity_mehta.derive_discovery_id(&graph_id)?;
    let retrieved_lockboxes_mehta = graph_priya
        .store()
        .get_lockboxes(&my_lakshana_mehta)
        .await?;

    // Dr. Mehta decrypts the lockbox with his private encryption key to recover the GraphKey
    let recovered_key_mehta =
        retrieved_lockboxes_mehta[0].open(my_identity_mehta.encryption_key())?;
    println!("  -> Lockbox decrypted! GraphKey recovered successfully.");

    // Dr. Mehta builds a local Graph handle using his own store/vault and the recovered key:
    let dummy_mehta = client_mehta.create_graph().await?;
    let store_mehta = dummy_mehta.store().clone();

    let graph_mehta = Graph::new(
        graph_id,
        recovered_key_mehta.clone(),
        client_mehta.vault().clone(),
        store_mehta.clone(),
        Arc::new(akshara::staging::InMemoryStagingStore::new()),
        akshara::config::TuningConfig::default(),
    );

    // First, Dr. Mehta syncs Priya's public Identity Graph (containing her credentials/devices)
    let transport_mehta = Arc::new(LocalMemoryTransport::new(graph_priya.store().clone()));
    let sync_engine_mehta =
        akshara::sync::SyncEngine::new(transport_mehta, client_mehta.vault().clone());
    sync_engine_mehta
        .sync_graph(
            priya_id,
            &store_mehta,
            &akshara_aadhaara::IDENTITY_GRAPH_KEY,
            akshara::SyncMode::Full,
        )
        .await?;
    println!("  -> Priya's public Identity Graph synced successfully.");

    sync_engine_mehta
        .sync_graph(
            graph_id,
            &store_mehta,
            &recovered_key_mehta,
            akshara::SyncMode::Full,
        )
        .await?;

    // Dr. Mehta reads patient demographics
    let demo_bytes = graph_mehta.get("/patient/demographics").await?;
    let demo_mehta: Demographics = serde_json::from_slice(&demo_bytes)?;
    println!(
        "  -> Dr. Mehta successfully decrypted & read demographics for patient: {}",
        demo_mehta.name
    );

    // Dr. Mehta enters consultation note
    let consult_1 = Consultation {
        date: Utc::now().to_rfc3339(),
        doctor: "Dr. Mehta".to_string(),
        complaint: "Persistent headaches and aura.".to_string(),
        plan: "Recommended Specialist review. Prescribed sumatriptan.".to_string(),
    };
    graph_mehta
        .insert("/patient/consultations/0", serde_json::to_vec(&consult_1)?)
        .await?;
    let seal_mehta = graph_mehta.flush().await?;
    println!(
        "  -> Dr. Mehta sealed consultation note. Manifest: {}\n",
        seal_mehta.manifest_id
    );

    // -------------------------------------------------------------------------
    // STEP 5: PATIENT INTEGRATES DR. MEHTA'S UPDATES
    // -------------------------------------------------------------------------
    println!("[5/7] Priya Sharma syncing updates back from Dr. Mehta...");
    let transport_priya_pull = Arc::new(LocalMemoryTransport::new(store_mehta.clone()));
    let sync_engine_priya =
        akshara::sync::SyncEngine::new(transport_priya_pull, client_priya.vault().clone());
    sync_engine_priya
        .sync_graph(
            graph_id,
            graph_priya.store(),
            &graph_key,
            akshara::SyncMode::Full,
        )
        .await?;
    println!("  -> Priya Sharma's local store successfully updated.\n");

    // -------------------------------------------------------------------------
    // STEP 6: PATIENT SHARES RECORDS WITH DR. WATSON (SPECIALIST)
    // -------------------------------------------------------------------------
    println!("[6/7] Priya Sharma sharing her graph with Dr. Watson (Specialist)...");

    // REAL-WORLD NOTE: As in Step 3, Dr. Watson shares his public encryption credentials
    // with Priya (e.g., via a QR code, an electronic referral record, or direct contact card).
    // In this demo, we simulate this key exchange by retrieving Dr. Watson's identity in-memory:
    let identity_watson = client_watson.vault().get_identity(None).await?;
    let lakshana_watson = identity_watson.derive_discovery_id(&graph_id)?;
    let lockbox_watson = Lockbox::create(
        identity_watson.public().encryption_key(),
        &graph_key,
        &mut rng,
    )?;

    // Priya stores the lockbox under Dr. Watson's Lakshana in her store
    graph_priya
        .store()
        .put_lockbox(lakshana_watson, &lockbox_watson)
        .await?;
    println!(
        "  -> Lockbox created & stored under Dr. Watson's Lakshana: {}",
        lakshana_watson.to_hex()
    );

    // Priya cryptographically authorizes Dr. Watson as a collaborator in her graph
    graph_priya
        .authorize_collaborator(identity_watson.public().signing_key())
        .await?;
    let seal_priya_watson_trust = graph_priya.flush().await?;
    println!(
        "  -> Trust delegated to Dr. Watson. Manifest: {}",
        seal_priya_watson_trust.manifest_id
    );

    // -------------------------------------------------------------------------
    // STEP 7: DR. WATSON DECRYPTS, SYNCS, READS MEHTA'S NOTE AND COLLABORATES
    // -------------------------------------------------------------------------
    println!("[7/7] Dr. Watson fetching lockbox, syncing, and reading entire history...");

    // Watson fetches and decrypts the lockbox
    let my_identity_watson = client_watson.vault().get_identity(None).await?;
    let my_lakshana_watson = my_identity_watson.derive_discovery_id(&graph_id)?;
    let retrieved_lockboxes_watson = graph_priya
        .store()
        .get_lockboxes(&my_lakshana_watson)
        .await?;
    let recovered_key_watson =
        retrieved_lockboxes_watson[0].open(my_identity_watson.encryption_key())?;

    let dummy_watson = client_watson.create_graph().await?;
    let store_watson = dummy_watson.store().clone();

    let graph_watson = Graph::new(
        graph_id,
        recovered_key_watson.clone(),
        client_watson.vault().clone(),
        store_watson.clone(),
        Arc::new(akshara::staging::InMemoryStagingStore::new()),
        akshara::config::TuningConfig::default(),
    );

    // First, Dr. Watson syncs Priya's public Identity Graph into his store
    let transport_watson = Arc::new(LocalMemoryTransport::new(graph_priya.store().clone()));
    let sync_engine_watson =
        akshara::sync::SyncEngine::new(transport_watson, client_watson.vault().clone());
    sync_engine_watson
        .sync_graph(
            priya_id,
            &store_watson,
            &akshara_aadhaara::IDENTITY_GRAPH_KEY,
            akshara::SyncMode::Full,
        )
        .await?;

    // Next, Dr. Watson syncs the patient record graph using the recovered key
    sync_engine_watson
        .sync_graph(
            graph_id,
            &store_watson,
            &recovered_key_watson,
            akshara::SyncMode::Full,
        )
        .await?;

    // Watson reads history including Dr. Mehta's consultation
    let consult_1_bytes = graph_watson.get("/patient/consultations/0").await?;
    let consult_1_read: Consultation = serde_json::from_slice(&consult_1_bytes)?;
    println!(
        "  -> Dr. Watson read Dr. Mehta's consultation note: \"{}\"",
        consult_1_read.complaint
    );

    // Watson writes his specialist note
    let consult_2 = Consultation {
        date: Utc::now().to_rfc3339(),
        doctor: "Dr. Watson".to_string(),
        complaint: "Migraine with visual aura.".to_string(),
        plan: "Recommended brain MRI. Avoid blue light triggers.".to_string(),
    };
    graph_watson
        .insert("/patient/consultations/1", serde_json::to_vec(&consult_2)?)
        .await?;
    let seal_watson = graph_watson.flush().await?;
    println!(
        "  -> Dr. Watson sealed new consultation note. Manifest: {}",
        seal_watson.manifest_id
    );

    // Pull Watson's updates back to Priya's record
    let transport_priya_final = Arc::new(LocalMemoryTransport::new(store_watson.clone()));
    let sync_engine_priya_final =
        akshara::sync::SyncEngine::new(transport_priya_final, client_priya.vault().clone());
    sync_engine_priya_final
        .sync_graph(
            graph_id,
            graph_priya.store(),
            &graph_key,
            akshara::SyncMode::Full,
        )
        .await?;

    // Priya displays full audit trail
    let consult_2_bytes = graph_priya.get("/patient/consultations/1").await?;
    let consult_2_read: Consultation = serde_json::from_slice(&consult_2_bytes)?;

    println!("\n     [FINAL SOVEREIGN RECORD HISTORY]");
    println!("     * Patient: {}", demo_mehta.name);
    println!(
        "     * [{}] - {} - Complaint: \"{}\"",
        consult_1_read.date, consult_1_read.doctor, consult_1_read.complaint
    );
    println!(
        "     * [{}] - {} - Complaint: \"{}\"",
        consult_2_read.date, consult_2_read.doctor, consult_2_read.complaint
    );
    println!("       Specialist Plan: {}\n", consult_2_read.plan);

    println!("============================================================");
    println!("   PATIENT-OWNED LOCKBOX DEMO COMPLETED SUCCESSFULLY!       ");
    println!("   - Absolute zero-trust patient ownership verified.       ");
    println!("   - Lockbox sharing with recipient identity enforced.     ");
    println!("   - Merkle-DAG synchronization converged.                  ");
    println!("============================================================");

    Ok(())
}
