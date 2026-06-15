use kormir::bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
#[cfg(feature = "nostr")]
use kormir::nostr_events::create_attestation_event;
use kormir::{create_enum_event, sign_enum_event};
use lightning::util::ser::Writeable;
#[cfg(feature = "nostr")]
use nostr::{EventId, Keys};
use serde::Serialize;

#[derive(Serialize)]
struct Output {
    oracle_pubkey_hex: String,
    announcement_hex: String,
    attestation_hex: String,
    #[cfg(feature = "nostr")]
    nostr_event_json: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "Usage: bitcaster_create_enum_with_attestation <event-id> <maturity-epoch> <outcomes-json> <attested-outcome>"
        );
        std::process::exit(2);
    }

    let event_id = &args[1];
    let maturity_epoch: u32 = args[2]
        .parse()
        .expect("maturity-epoch must be a u32 unix timestamp");
    let outcomes: Vec<String> =
        serde_json::from_str(&args[3]).expect("outcomes-json must be a JSON string array");
    let attested_outcome = &args[4];

    let secp = Secp256k1::new();
    let oracle_secret = SecretKey::from_slice(&[0x11; 32]).expect("valid oracle secret");
    let oracle_keypair = Keypair::from_secret_key(&secp, &oracle_secret);
    let nonce_secret = SecretKey::from_slice(&[0x22; 32]).expect("valid nonce secret");
    let nonce = nonce_secret.x_only_public_key(&secp).0;

    let announcement = create_enum_event(
        &secp,
        &oracle_keypair,
        event_id,
        &outcomes,
        maturity_epoch,
        &nonce,
    )
    .expect("valid enum announcement");

    let attestation = sign_enum_event(
        &secp,
        &oracle_keypair,
        &announcement,
        attested_outcome,
        &nonce_secret,
    )
    .expect("valid enum attestation");

    let mut announcement_bytes = Vec::new();
    ddk_messages::ser_impls::write_as_tlv(&announcement, &mut announcement_bytes)
        .expect("announcement serialization must succeed");

    #[cfg(feature = "nostr")]
    let nostr_event_json = {
        let secret = nostr::key::SecretKey::from_slice(&oracle_secret.secret_bytes())
            .expect("valid nostr oracle secret");
        let keys = Keys::new(secret);
        let announcement_event_id =
            EventId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .expect("valid fixed announcement event id");
        let event = create_attestation_event(&keys, &attestation, announcement_event_id)
            .expect("valid signed kind-89 attestation event");
        serde_json::to_string(&event).expect("nostr event JSON serialization must succeed")
    };

    let output = Output {
        oracle_pubkey_hex: oracle_keypair.x_only_public_key().0.to_string(),
        announcement_hex: hex::encode(announcement_bytes),
        attestation_hex: hex::encode(attestation.encode()),
        #[cfg(feature = "nostr")]
        nostr_event_json,
    };
    println!(
        "{}",
        serde_json::to_string(&output).expect("output JSON serialization must succeed")
    );
}
