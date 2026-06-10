use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use gloo_utils::format::JsValueSerdeExt;
use kormir::bitcoin::secp256k1::SecretKey;
use kormir::storage::Storage;
use kormir::{Oracle, OracleAnnouncement, OracleAttestation, Readable, Writeable};
use nostr::{Event, EventBuilder, EventId, JsonUtil, Keys, Kind, Tag};
use nostr_sdk::Client;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::error::JsError;
use crate::models::{Announcement, Attestation, EventData};
use crate::storage::{IndexedDb, NSEC_KEY};

mod error;
mod models;
mod storage;
mod utils;

fn encode_announcement_tlv(ann: &OracleAnnouncement) -> String {
    let mut buf = Vec::new();
    ddk_messages::ser_impls::write_as_tlv(ann, &mut buf)
        .expect("TLV serialization of a valid OracleAnnouncement should not fail");
    hex::encode(buf)
}

fn create_announcement_event_with_metadata(
    keys: &Keys,
    announcement: &OracleAnnouncement,
    title: &str,
    description: &str,
) -> Result<Event, JsError> {
    let mut builder = EventBuilder::new(Kind::Custom(88), BASE64.encode(announcement.encode()));
    if !title.is_empty() {
        builder = builder.tag(Tag::parse(["title", title]).map_err(|_| JsError::InvalidArgument)?);
    }
    if !description.is_empty() {
        builder = builder.tag(
            Tag::parse(["description", description]).map_err(|_| JsError::InvalidArgument)?,
        );
    }
    Ok(builder.sign_with_keys(keys)?)
}

fn create_attestation_event(
    keys: &Keys,
    attestation: &OracleAttestation,
    announcement_event_id: EventId,
) -> Result<Event, JsError> {
    Ok(EventBuilder::new(Kind::Custom(89), BASE64.encode(attestation.encode()))
        .tag(Tag::event(announcement_event_id))
        .sign_with_keys(keys)?)
}

#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct Kormir {
    oracle: Oracle<IndexedDb>,
    storage: IndexedDb,
    client: Client,
}

#[wasm_bindgen]
impl Kormir {
    pub async fn new(relays: Vec<String>) -> Result<Kormir, JsError> {
        utils::set_panic_hook();
        let storage = IndexedDb::new().await?;

        let nsec: Option<String> = storage.get_from_indexed_db(NSEC_KEY).await?;
        let nsec: SecretKey = match nsec {
            Some(str) => SecretKey::from_str(&str)?,
            None => {
                let mut entropy = [0u8; 32];
                getrandom::getrandom(&mut entropy).map_err(|_| JsError::Internal)?;
                let nsec = SecretKey::from_slice(&entropy)?;
                storage
                    .save_to_indexed_db(NSEC_KEY, hex::encode(nsec.secret_bytes()))
                    .await?;
                nsec
            }
        };

        let oracle = Oracle::from_signing_key(storage.clone(), nsec)?;
        let client = Client::new(oracle.nostr_keys());
        for relay in &relays {
            client.add_relay(relay.as_str()).await?;
        }
        client.connect().await;

        Ok(Kormir {
            oracle,
            storage,
            client,
        })
    }

    pub async fn restore(str: String) -> Result<(), JsError> {
        let nsec = Keys::parse(&str)?;
        IndexedDb::clear().await?;
        let storage = IndexedDb::new().await?;
        storage
            .save_to_indexed_db(NSEC_KEY, hex::encode(nsec.secret_key().secret_bytes()))
            .await?;
        Ok(())
    }

    pub fn get_public_key(&self) -> String {
        self.oracle.public_key().to_string()
    }

    pub async fn create_enum_event(
        &self,
        event_id: String,
        outcomes: Vec<String>,
        event_maturity_epoch: u32,
        title: String,
        description: String,
    ) -> Result<String, JsError> {
        let ann = self
            .oracle
            .create_enum_event(event_id.clone(), outcomes, event_maturity_epoch)
            .await?;
        let hex = encode_announcement_tlv(&ann);
        let event = create_announcement_event_with_metadata(
            &self.oracle.nostr_keys(),
            &ann,
            &title,
            &description,
        )?;

        self.storage
            .add_announcement_event_id(event_id, event.id.to_hex())
            .await?;

        if let Err(err) = self.client.send_event(&event).await {
            log::warn!("Failed to publish announcement to Nostr relays: {err}");
        }

        Ok(hex)
    }

    pub async fn sign_enum_event(
        &self,
        event_id: String,
        outcome: String,
    ) -> Result<String, JsError> {
        let attestation = self
            .oracle
            .sign_enum_event(event_id.clone(), outcome)
            .await?;

        let event = self
            .storage
            .get_event(event_id.clone())
            .await?
            .ok_or(JsError::NotFound)?;
        let nostr_event_id = EventId::from_hex(&event.announcement_event_id.unwrap())
            .map_err(|_| JsError::InvalidArgument)?;

        let event = create_attestation_event(&self.oracle.nostr_keys(), &attestation, nostr_event_id)?;

        self.storage
            .add_attestation_event_id(event_id, event.id.to_hex())
            .await?;

        if let Err(err) = self.client.send_event(&event).await {
            log::warn!("Failed to publish attestation to Nostr relays: {err}");
        }

        Ok(hex::encode(attestation.encode()))
    }

    /// Re-imports a previously-created announcement so its outcome can be
    /// re-signed on a profile whose local event store was lost (fresh browser
    /// profile restored from the oracle nsec alone). The announcement hex
    /// (a public protocol artifact, mirrored client-side) carries the committed
    /// nonce point(s); because nonce keys are derived deterministically from the
    /// signing key, the original index is recovered by a bounded scan and the
    /// announcement is re-saved. After this call `sign_enum_event(event_id, …)`
    /// succeeds and produces the same committed-nonce signature the mint expects.
    ///
    /// `announcement_tlv_hex` is the TLV-enveloped hex returned by
    /// `create_enum_event` (and stored by the client). Returns the event_id.
    pub async fn import_enum_event(
        &self,
        announcement_tlv_hex: String,
    ) -> Result<String, JsError> {
        let bytes = hex::decode(announcement_tlv_hex)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let ann: OracleAnnouncement = ddk_messages::ser_impls::read_as_tlv(&mut cursor)
            .map_err(|_| JsError::InvalidArgument)?;

        // Reject non-enum announcements: this WASM entry-point is only for
        // enum events (DLC conditional tokens on discrete outcomes). Numeric
        // announcements use a different import path and should not be restored
        // through this function.
        match &ann.oracle_event.event_descriptor {
            kormir::EventDescriptor::EnumEvent(_) => {}
            _ => return Err(JsError::InvalidArgument),
        }

        let event_id = ann.oracle_event.event_id.clone();

        // Non-destructive: if the event is already present in this profile's
        // storage (e.g. created here, or already imported) leave it untouched so
        // a re-import never clobbers a previously-saved attestation. Recovery is
        // only needed when the local store lost the event.
        if self.storage.get_event(event_id.clone()).await?.is_some() {
            return Ok(event_id);
        }

        // 256 indexes is far beyond any realistic per-profile event count while
        // still bounding the scan so a mismatched key fails fast.
        let imported_id = self.oracle.import_announcement(ann, 256).await?;
        Ok(imported_id)
    }

    pub async fn list_events(&self) -> Result<JsValue, JsError> {
        let data = self.storage.list_events().await?;
        let events = data.into_iter().map(EventData::from).collect::<Vec<_>>();
        Ok(JsValue::from_serde(&events)?)
    }

    pub async fn decode_announcement(str: String) -> Result<Announcement, JsError> {
        let bytes = hex::decode(str)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let ann = OracleAnnouncement::read(&mut cursor)?;
        Ok(ann.into())
    }

    pub async fn decode_attestation(str: String) -> Result<Attestation, JsError> {
        let bytes = hex::decode(str)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let attestation = OracleAttestation::read(&mut cursor)?;
        Ok(attestation.into())
    }

    pub fn create_announcement_nostr_event_json(
        nsec: String,
        announcement_hex: String,
        title: String,
        description: String,
    ) -> Result<String, JsError> {
        let keys = Keys::parse(&nsec)?;
        let bytes = hex::decode(announcement_hex)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let ann = ddk_messages::ser_impls::read_as_tlv::<OracleAnnouncement, _>(&mut cursor)?;
        let event = create_announcement_event_with_metadata(&keys, &ann, &title, &description)?;
        Ok(event.as_json())
    }

    pub fn create_attestation_nostr_event_json(
        nsec: String,
        attestation_hex: String,
        announcement_event_id: String,
    ) -> Result<String, JsError> {
        let keys = Keys::parse(&nsec)?;
        let bytes = hex::decode(attestation_hex)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let attestation = OracleAttestation::read(&mut cursor)?;
        let announcement_event_id =
            EventId::from_hex(&announcement_event_id).map_err(|_| JsError::InvalidArgument)?;
        let event = create_attestation_event(&keys, &attestation, announcement_event_id)?;
        Ok(event.as_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddk_messages::oracle_msgs::OracleAttestation;
    use lightning::util::ser::Readable;

    #[test]
    fn exported_event_kinds_are_nip88_base64_binary() {
        let keys = Keys::generate();
        let secp = kormir::bitcoin::secp256k1::Secp256k1::new();
        let oracle_secret = kormir::bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let nonce_secret = kormir::bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        let keypair = secp256k1_zkp::Keypair::from_secret_key(&secp, &oracle_secret);
        let nonce = nonce_secret.x_only_public_key(&secp).0;
        let ann = kormir::create_enum_event(
            &secp,
            &keypair,
            "match-1",
            &["YES".to_string(), "NO".to_string()],
            1_700_000_000,
            &nonce,
        )
        .unwrap();
        let att = kormir::sign_enum_event(&secp, &keypair, &ann, "YES", &nonce_secret).unwrap();

        let announcement_event =
            create_announcement_event_with_metadata(&keys, &ann, "title", "description").unwrap();
        assert_eq!(announcement_event.kind, Kind::Custom(88));
        assert!(announcement_event
            .tags
            .iter()
            .any(|t| t.kind() == nostr::TagKind::Title));
        let ann_content = BASE64.decode(&announcement_event.content).unwrap();
        assert_eq!(ann_content, ann.encode());

        let attestation_event =
            create_attestation_event(&keys, &att, announcement_event.id).unwrap();
        assert_eq!(attestation_event.kind, Kind::Custom(89));
        let att_content = BASE64.decode(&attestation_event.content).unwrap();
        let mut cursor = kormir::lightning::io::Cursor::new(att_content);
        let parsed = OracleAttestation::read(&mut cursor).unwrap();
        parsed.validate(&secp, &ann).unwrap();
    }
}
