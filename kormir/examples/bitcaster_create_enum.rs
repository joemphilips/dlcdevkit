use kormir::bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use kormir::create_enum_event;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: bitcaster_create_enum <event-id> <maturity-epoch> <outcomes-json>"
        );
        std::process::exit(2);
    }

    let event_id = &args[1];
    let maturity_epoch: u32 = args[2]
        .parse()
        .expect("maturity-epoch must be a u32 unix timestamp");
    let outcomes: Vec<String> =
        serde_json::from_str(&args[3]).expect("outcomes-json must be a JSON string array");

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

    let mut bytes = Vec::new();
    ddk_messages::ser_impls::write_as_tlv(&announcement, &mut bytes)
        .expect("announcement serialization must succeed");
    println!("{}", hex::encode(bytes));
}
