use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use gloo_utils::format::JsValueSerdeExt;
use kormir::bitcoin::secp256k1::SecretKey;
use kormir::storage::{OracleEventData, Storage};
use kormir::{Oracle, OracleAnnouncement, OracleAttestation, Readable, Writeable};
use nostr::{Event, EventBuilder, EventId, JsonUtil, Keys, Kind, Tag};
use nostr_sdk::Client;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::error::JsError;
use crate::models::{Announcement, Attestation, EventData, PreparedOracleEvent};
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
        builder = builder
            .tag(Tag::parse(["description", description]).map_err(|_| JsError::InvalidArgument)?);
    }
    Ok(builder.sign_with_keys(keys)?)
}

fn create_attestation_event(
    keys: &Keys,
    attestation: &OracleAttestation,
    announcement_event_id: EventId,
) -> Result<Event, JsError> {
    Ok(
        EventBuilder::new(Kind::Custom(89), BASE64.encode(attestation.encode()))
            .tag(Tag::event(announcement_event_id))
            .sign_with_keys(keys)?,
    )
}

struct PreparedEvent {
    artifact_hex: String,
    event: Event,
}

impl From<PreparedEvent> for PreparedOracleEvent {
    fn from(prepared: PreparedEvent) -> Self {
        Self {
            artifact_hex: prepared.artifact_hex,
            nostr_event_json: prepared.event.as_json(),
        }
    }
}

async fn prepare_announcement<S: Storage>(
    oracle: &Oracle<S>,
    event_id: String,
    outcomes: Vec<String>,
    maturity: u32,
    title: &str,
    description: &str,
) -> Result<PreparedEvent, JsError> {
    let ann = match oracle.storage.get_event(event_id.clone()).await? {
        Some(existing) => {
            oracle.validate_enum_authority(&existing)?;
            match &existing.announcement.oracle_event.event_descriptor {
                kormir::EventDescriptor::EnumEvent(descriptor)
                    if descriptor.outcomes == outcomes
                        && existing.announcement.oracle_event.event_maturity_epoch == maturity => {}
                _ => return Err(JsError::InvalidArgument),
            }
            if let Some(json) = &existing.private_authority.announcement_event_json {
                return prepared_announcement_from_retained(
                    oracle,
                    &existing,
                    json,
                    title,
                    description,
                );
            }
            existing.announcement
        }
        None => {
            let mut entropy = [0u8; 32];
            getrandom::getrandom(&mut entropy).map_err(|_| JsError::Internal)?;
            let nonce = SecretKey::from_slice(&entropy).map_err(|_| JsError::Internal)?;
            oracle
                .create_enum_event_with_nonce(event_id.clone(), outcomes, maturity, nonce)
                .await?
        }
    };
    let event =
        create_announcement_event_with_metadata(&oracle.nostr_keys(), &ann, title, description)?;
    let mut retained = oracle
        .storage
        .get_event(event_id.clone())
        .await?
        .ok_or(JsError::NotFound)?;
    retained.announcement_event_id = Some(event.id.to_hex());
    retained.private_authority.announcement_event_json = Some(event.as_json());
    match oracle.merge_enum_authority(retained).await {
        Ok(_) => Ok(PreparedEvent {
            artifact_hex: encode_announcement_tlv(&ann),
            event,
        }),
        Err(error) => {
            let winner = oracle
                .storage
                .get_event(event_id)
                .await?
                .ok_or(JsError::NotFound)?;
            let json = winner
                .private_authority
                .announcement_event_json
                .as_ref()
                .ok_or_else(|| JsError::from(error))?;
            prepared_announcement_from_retained(oracle, &winner, json, title, description)
        }
    }
}

fn prepared_announcement_from_retained<S: Storage>(
    oracle: &Oracle<S>,
    data: &OracleEventData,
    json: &str,
    title: &str,
    description: &str,
) -> Result<PreparedEvent, JsError> {
    verify_retained_announcement(oracle, data, &data.event_id, json)?;
    let event = Event::from_json(json).map_err(|_| JsError::InvalidArgument)?;
    let mut tags = vec![];
    if !title.is_empty() {
        tags.push(Tag::parse(["title", title]).map_err(|_| JsError::InvalidArgument)?);
    }
    if !description.is_empty() {
        tags.push(Tag::parse(["description", description]).map_err(|_| JsError::InvalidArgument)?);
    }
    if event.tags.iter().collect::<Vec<_>>() != tags.iter().collect::<Vec<_>>() {
        return Err(JsError::InvalidArgument);
    }
    Ok(PreparedEvent {
        artifact_hex: encode_announcement_tlv(&data.announcement),
        event,
    })
}

fn retained_announcement_id(data: &OracleEventData) -> Result<EventId, JsError> {
    let id = data
        .announcement_event_id
        .as_ref()
        .ok_or(JsError::InvalidArgument)?;
    EventId::from_hex(id).map_err(|_| JsError::InvalidArgument)
}

fn verify_retained_announcement<S: Storage>(
    oracle: &Oracle<S>,
    data: &OracleEventData,
    event_id: &str,
    announcement_event_json: &str,
) -> Result<EventId, JsError> {
    let event = kormir::private_backup::validate_announcement_event_json(
        &data.announcement,
        announcement_event_json,
    )?;
    if event.kind != Kind::Custom(88)
        || event.pubkey != oracle.nostr_keys().public_key()
        || BASE64
            .decode(&event.content)
            .map_err(|_| JsError::InvalidArgument)?
            != data.announcement.encode()
        || data.event_id != event_id
        || data.announcement.oracle_event.event_id != event_id
        || data.announcement.oracle_public_key != oracle.public_key()
        || !matches!(
            data.announcement.oracle_event.event_descriptor,
            kormir::EventDescriptor::EnumEvent(_)
        )
    {
        return Err(JsError::InvalidArgument);
    }
    if data.announcement_event_id.is_some() && retained_announcement_id(data)? != event.id {
        return Err(JsError::InvalidArgument);
    }
    data.announcement
        .validate(&kormir::bitcoin::secp256k1::Secp256k1::verification_only())
        .map_err(|_| JsError::InvalidArgument)?;
    Ok(event.id)
}

fn recover_enum_attestation(
    data: &OracleEventData,
    outcome: &str,
) -> Result<Option<OracleAttestation>, JsError> {
    let Some(attestation) = data.attestation() else {
        return Ok(None);
    };
    if attestation.outcomes != [outcome] || attestation.signatures.len() != 1 {
        return Err(JsError::EventAlreadySigned);
    }
    attestation
        .validate(
            &kormir::bitcoin::secp256k1::Secp256k1::verification_only(),
            &data.announcement,
        )
        .map_err(|_| JsError::InvalidArgument)?;
    Ok(Some(attestation))
}

fn prepared_attestation_from_retained(
    data: &OracleEventData,
    outcome: &str,
) -> Result<PreparedEvent, JsError> {
    let attestation =
        recover_enum_attestation(data, outcome)?.ok_or(JsError::EventAlreadySigned)?;
    let json = data
        .private_authority
        .attestation_event_json
        .as_ref()
        .ok_or(JsError::EventAlreadySigned)?;
    let dto = kormir::private_backup::PrivateEnumAuthority {
        schema_version: 1,
        announcement_tlv_hex: encode_announcement_tlv(&data.announcement),
        announcement_event_json: data
            .private_authority
            .announcement_event_json
            .clone()
            .ok_or(JsError::InvalidArgument)?,
        nonce_scalar_hex: None,
        signed_outcome: Some(outcome.to_owned()),
        attestation_hex: Some(hex::encode(attestation.encode())),
        attestation_event_json: Some(json.clone()),
        publication_record_json: None,
    };
    kormir::private_backup::validate_enum_authority(
        &dto,
        Some(&data.announcement.oracle_public_key.to_string()),
    )?;
    Ok(PreparedEvent {
        artifact_hex: hex::encode(attestation.encode()),
        event: Event::from_json(json).map_err(|_| JsError::InvalidArgument)?,
    })
}

async fn prepare_attestation<S: Storage>(
    oracle: &Oracle<S>,
    event_id: String,
    outcome: String,
    announcement_event_json: String,
) -> Result<PreparedEvent, JsError> {
    let mut data = oracle
        .storage
        .get_event(event_id.clone())
        .await?
        .ok_or(JsError::NotFound)?;
    let parent = verify_retained_announcement(oracle, &data, &event_id, &announcement_event_json)?;
    let recovered = recover_enum_attestation(&data, &outcome)?;
    data.announcement_event_id = Some(parent.to_hex());
    data.private_authority.announcement_event_json = Some(announcement_event_json.clone());
    oracle.merge_enum_authority(data).await?;
    let attestation = match recovered {
        Some(attestation) => attestation,
        None => match oracle
            .sign_enum_event(event_id.clone(), outcome.clone())
            .await
        {
            Ok(attestation) => attestation,
            Err(kormir::error::Error::EventAlreadySigned) => {
                let current = oracle
                    .storage
                    .get_event(event_id.clone())
                    .await?
                    .ok_or(JsError::NotFound)?;
                recover_enum_attestation(&current, &outcome)?.ok_or(JsError::EventAlreadySigned)?
            }
            Err(error) => return Err(error.into()),
        },
    };
    let latest = oracle
        .storage
        .get_event(event_id.clone())
        .await?
        .ok_or(JsError::NotFound)?;
    if latest.private_authority.attestation_event_json.is_some() {
        return prepared_attestation_from_retained(&latest, &attestation.outcomes[0]);
    }
    let event = create_attestation_event(&oracle.nostr_keys(), &attestation, parent)?;
    let mut retained = oracle
        .storage
        .get_event(event_id.clone())
        .await?
        .ok_or(JsError::NotFound)?;
    retained.announcement_event_id = Some(parent.to_hex());
    retained.private_authority.announcement_event_json = Some(announcement_event_json);
    retained.attestation_event_id = Some(event.id.to_hex());
    retained.private_authority.attestation_event_json = Some(event.as_json());
    match oracle.merge_enum_authority(retained).await {
        Ok(_) => Ok(PreparedEvent {
            artifact_hex: hex::encode(attestation.encode()),
            event,
        }),
        Err(error) => {
            let winner = oracle
                .storage
                .get_event(event_id)
                .await?
                .ok_or(JsError::NotFound)?;
            if winner.private_authority.attestation_event_json.is_none() {
                return Err(error.into());
            }
            prepared_attestation_from_retained(&winner, &attestation.outcomes[0])
        }
    }
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
                IndexedDb::restore_signing_key(&hex::encode(nsec.secret_bytes())).await?;
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
        IndexedDb::restore_signing_key(&hex::encode(nsec.secret_key().secret_bytes())).await?;
        Ok(())
    }

    pub fn get_public_key(&self) -> String {
        self.oracle.public_key().to_string()
    }

    pub async fn prepare_enum_event(
        &self,
        event_id: String,
        outcomes: Vec<String>,
        event_maturity_epoch: u32,
        title: String,
        description: String,
    ) -> Result<PreparedOracleEvent, JsError> {
        Ok(prepare_announcement(
            &self.oracle,
            event_id,
            outcomes,
            event_maturity_epoch,
            &title,
            &description,
        )
        .await?
        .into())
    }

    pub async fn prepare_enum_attestation(
        &self,
        event_id: String,
        outcome: String,
        announcement_event_json: String,
    ) -> Result<PreparedOracleEvent, JsError> {
        Ok(
            prepare_attestation(&self.oracle, event_id, outcome, announcement_event_json)
                .await?
                .into(),
        )
    }

    pub async fn create_enum_event(
        &self,
        event_id: String,
        outcomes: Vec<String>,
        event_maturity_epoch: u32,
        title: String,
        description: String,
    ) -> Result<String, JsError> {
        let prepared = prepare_announcement(
            &self.oracle,
            event_id,
            outcomes,
            event_maturity_epoch,
            &title,
            &description,
        )
        .await?;

        if let Err(err) = self.client.send_event(&prepared.event).await {
            log::warn!("Failed to publish announcement to Nostr relays: {err}");
        }

        Ok(prepared.artifact_hex)
    }

    pub async fn sign_enum_event(
        &self,
        event_id: String,
        outcome: String,
    ) -> Result<String, JsError> {
        let data = self
            .storage
            .get_event(event_id.clone())
            .await?
            .ok_or(JsError::NotFound)?;
        let parent = data
            .private_authority
            .announcement_event_json
            .ok_or(JsError::InvalidArgument)?;
        let prepared = prepare_attestation(&self.oracle, event_id, outcome, parent).await?;
        if self.client.send_event(&prepared.event).await.is_err() {
            log::warn!("Failed to publish attestation to Nostr relays");
        }
        Ok(prepared.artifact_hex)
    }

    /// Re-imports a previously-created announcement so its outcome can be
    /// re-signed on a profile whose local event store was lost (fresh browser
    /// profile restored from the oracle nsec alone). The announcement hex
    /// (a public protocol artifact, mirrored client-side) carries the committed
    /// nonce point(s); because nonce keys are derived deterministically from the
    /// signing key, the original index is recovered by a bounded scan and the
    /// announcement is re-saved. Use `prepare_enum_attestation` with the retained
    /// signed kind-88 JSON to restore its exact Nostr ID before signing.
    /// This produces the same committed-nonce signature the mint expects.
    ///
    /// `announcement_tlv_hex` is the TLV-enveloped hex returned by
    /// `create_enum_event` (and stored by the client). Returns the event_id.
    pub async fn import_enum_event(&self, announcement_tlv_hex: String) -> Result<String, JsError> {
        let bytes = hex::decode(&announcement_tlv_hex)?;
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

        if encode_announcement_tlv(&ann) != announcement_tlv_hex {
            return Err(JsError::InvalidArgument);
        }
        // 256 indexes is far beyond any realistic per-profile event count while
        // still bounding the scan so a mismatched key fails fast.
        let imported_id = self.oracle.import_announcement(ann, 256).await?;
        Ok(imported_id)
    }

    /// Side-effect-free validation. Returns public facts only.
    pub fn validate_enum_authority(
        private_dto_json: String,
        expected_oracle_pubkey: Option<String>,
    ) -> Result<String, JsError> {
        let validated = kormir::private_backup::validate_enum_authority_json(
            &private_dto_json,
            expected_oracle_pubkey.as_deref(),
        )?;
        Ok(serde_json::to_string(&validated.summary)?)
    }

    pub async fn import_enum_authority(&self, private_dto_json: String) -> Result<String, JsError> {
        let validated = kormir::private_backup::validate_enum_authority_json(
            &private_dto_json,
            Some(&self.oracle.public_key().to_string()),
        )?;
        Ok(self
            .oracle
            .merge_enum_authority(validated.data)
            .await?
            .event_id)
    }

    pub async fn export_enum_authority(
        &self,
        event_id: String,
        announcement_event_json: String,
        publication_record_json: Option<String>,
    ) -> Result<String, JsError> {
        let mut data = self
            .storage
            .get_event(event_id.clone())
            .await?
            .ok_or(JsError::NotFound)?;
        verify_retained_announcement(&self.oracle, &data, &event_id, &announcement_event_json)?;
        data.private_authority.announcement_event_json = Some(announcement_event_json.clone());
        let nonce = self.oracle.export_enum_nonce(event_id).await?;
        let mut dto = kormir::private_backup::PrivateEnumAuthority {
            schema_version: 1,
            announcement_tlv_hex: encode_announcement_tlv(&data.announcement),
            announcement_event_json,
            nonce_scalar_hex: nonce.map(|secret| hex::encode(secret.secret_bytes())),
            signed_outcome: data
                .private_authority
                .choice
                .clone()
                .or_else(|| data.signatures.first().map(|entry| entry.0.clone())),
            attestation_hex: data
                .attestation()
                .map(|attestation| hex::encode(attestation.encode())),
            attestation_event_json: data.private_authority.attestation_event_json.clone(),
            publication_record_json: publication_record_json
                .or(data.private_authority.staged_publication_json.clone()),
        };
        if let Some(json) = &dto.publication_record_json {
            if json.len() > kormir::private_backup::MAX_PRIVATE_AUTHORITY_BYTES {
                return Err(JsError::InvalidArgument);
            }
            let record: serde_json::Value = serde_json::from_str(json)?;
            dto.signed_outcome = Some(
                record["chosenOutcome"]
                    .as_str()
                    .ok_or(JsError::InvalidArgument)?
                    .to_owned(),
            );
            if !record["attestation"].is_null() {
                dto.attestation_hex = Some(
                    record["attestation"]["attestationHex"]
                        .as_str()
                        .ok_or(JsError::InvalidArgument)?
                        .to_owned(),
                );
                dto.attestation_event_json = Some(
                    record["attestation"]["eventJson"]
                        .as_str()
                        .ok_or(JsError::InvalidArgument)?
                        .to_owned(),
                );
            }
        }
        let validated = kormir::private_backup::validate_enum_authority(
            &dto,
            Some(&self.oracle.public_key().to_string()),
        )?;
        let retained = self.oracle.merge_enum_authority(validated.data).await?;
        dto.signed_outcome = retained.private_authority.choice.clone();
        dto.attestation_hex = retained
            .attestation()
            .map(|attestation| hex::encode(attestation.encode()));
        dto.attestation_event_json = retained.private_authority.attestation_event_json;
        dto.publication_record_json = retained.private_authority.staged_publication_json;
        kormir::private_backup::validate_enum_authority(
            &dto,
            Some(&self.oracle.public_key().to_string()),
        )?;
        Ok(serde_json::to_string(&dto)?)
    }

    pub async fn staged_enum_publication(
        &self,
        event_id: String,
    ) -> Result<Option<String>, JsError> {
        Ok(self
            .storage
            .get_event(event_id)
            .await?
            .ok_or(JsError::NotFound)?
            .private_authority
            .staged_publication_json)
    }

    pub async fn acknowledge_enum_publication(
        &self,
        event_id: String,
        exact_publication_record_json: String,
    ) -> Result<(), JsError> {
        Ok(self
            .oracle
            .acknowledge_enum_publication(event_id, &exact_publication_record_json)
            .await?)
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
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::future::Future;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    #[derive(Clone, Copy, Default, PartialEq)]
    enum Failure {
        #[default]
        None,
        Read,
        Nonce,
        Announcement,
        AnnouncementId,
        Signatures,
        AttestationId,
    }

    #[derive(Default)]
    struct TestState {
        events: HashMap<String, OracleEventData>,
        next_nonce: u32,
        signature_saves: usize,
        failure: Failure,
    }

    #[derive(Clone, Default)]
    struct TestStorage(Rc<RefCell<TestState>>);

    impl TestStorage {
        fn fail(&self, failure: Failure) {
            self.0.borrow_mut().failure = failure;
        }

        fn data(&self) -> OracleEventData {
            self.0.borrow().events["match-1"].clone()
        }
    }

    impl Storage for TestStorage {
        async fn compare_exchange_event(
            &self,
            expected: Option<OracleEventData>,
            next: OracleEventData,
        ) -> Result<bool, kormir::error::Error> {
            let mut state = self.0.borrow_mut();
            if (expected.is_none() && state.failure == Failure::Announcement)
                || (!next.signatures.is_empty() && state.failure == Failure::Signatures)
                || (next.announcement_event_id.is_some()
                    && state.failure == Failure::AnnouncementId)
                || (next.attestation_event_id.is_some() && state.failure == Failure::AttestationId)
            {
                return Err(kormir::error::Error::StorageFailure);
            }
            let matches = match (state.events.get(&next.event_id), expected.as_ref()) {
                (None, None) => true,
                (Some(old), Some(expected)) => kormir::storage::same_event(old, expected)?,
                _ => false,
            };
            if matches {
                if !next.signatures.is_empty()
                    && expected
                        .as_ref()
                        .is_none_or(|old| old.signatures.is_empty())
                {
                    state.signature_saves += 1;
                }
                state.events.insert(next.event_id.clone(), next);
            }
            Ok(matches)
        }

        async fn get_next_nonce_indexes(
            &self,
            num: usize,
        ) -> Result<Vec<u32>, kormir::error::Error> {
            let mut state = self.0.borrow_mut();
            if state.failure == Failure::Nonce {
                return Err(kormir::error::Error::StorageFailure);
            }
            let indexes = (state.next_nonce..state.next_nonce + num as u32).collect();
            state.next_nonce += num as u32;
            Ok(indexes)
        }

        async fn save_announcement(
            &self,
            announcement: OracleAnnouncement,
            indexes: Vec<u32>,
        ) -> Result<String, kormir::error::Error> {
            let mut state = self.0.borrow_mut();
            if state.failure == Failure::Announcement {
                return Err(kormir::error::Error::StorageFailure);
            }
            let event_id = announcement.oracle_event.event_id.clone();
            state.events.insert(
                event_id.clone(),
                OracleEventData {
                    event_id: event_id.clone(),
                    announcement,
                    indexes,
                    private_authority: Default::default(),
                    signatures: vec![],
                    announcement_event_id: None,
                    attestation_event_id: None,
                },
            );
            Ok(event_id)
        }

        async fn save_signatures(
            &self,
            event_id: String,
            sigs: Vec<(String, kormir::Signature)>,
        ) -> Result<OracleEventData, kormir::error::Error> {
            let mut state = self.0.borrow_mut();
            if state.failure == Failure::Signatures {
                return Err(kormir::error::Error::StorageFailure);
            }
            let data = state
                .events
                .get_mut(&event_id)
                .ok_or(kormir::error::Error::NotFound)?;
            if !data.signatures.is_empty() {
                return Err(kormir::error::Error::EventAlreadySigned);
            }
            data.signatures = sigs;
            let saved = data.clone();
            state.signature_saves += 1;
            Ok(saved)
        }

        async fn get_event(
            &self,
            event_id: String,
        ) -> Result<Option<OracleEventData>, kormir::error::Error> {
            let state = self.0.borrow();
            if state.failure == Failure::Read {
                return Err(kormir::error::Error::StorageFailure);
            }
            Ok(state.events.get(&event_id).cloned())
        }
    }

    fn ready<F: Future>(future: F) -> F::Output {
        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        match std::pin::pin!(future).as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("in-memory storage must complete without I/O"),
        }
    }

    fn oracle(storage: TestStorage) -> Oracle<TestStorage> {
        Oracle::from_signing_key(storage, SecretKey::from_slice(&[1u8; 32]).unwrap()).unwrap()
    }

    fn announcement(oracle: &Oracle<TestStorage>) -> PreparedEvent {
        ready(prepare_announcement(
            oracle,
            "match-1".into(),
            vec!["YES".into(), "NO".into()],
            1_700_000_000,
            "title",
            "description",
        ))
        .unwrap()
    }

    fn attestation(oracle: &Oracle<TestStorage>, parent: &Event) -> Result<PreparedEvent, JsError> {
        ready(prepare_attestation(
            oracle,
            "match-1".into(),
            "YES".into(),
            parent.as_json(),
        ))
    }

    #[test]
    fn announcement_retry_after_private_commit_preserves_nonce_and_exact_envelope() {
        let storage = TestStorage::default();
        let owner = oracle(storage.clone());
        storage.fail(Failure::AnnouncementId);
        assert!(ready(prepare_announcement(
            &owner,
            "match-1".into(),
            vec!["YES".into(), "NO".into()],
            1_700_000_000,
            "title",
            "description"
        ))
        .is_err());
        let before = storage.data().announcement;
        storage.fail(Failure::None);
        let prepared = announcement(&owner);
        assert_eq!(before, storage.data().announcement);
        let retry = announcement(&owner);
        assert!(prepared.event.as_json() == retry.event.as_json());
        assert!(matches!(
            storage.data().private_authority.nonce,
            kormir::storage::EnumNonceAuthority::Explicit { .. }
        ));
    }

    #[test]
    fn local_preparation_retains_exact_signed_envelopes_without_a_relay_client() {
        let storage = TestStorage::default();
        let oracle = oracle(storage.clone());
        let prepared = announcement(&oracle);
        let exported: PreparedOracleEvent = PreparedEvent {
            artifact_hex: prepared.artifact_hex.clone(),
            event: prepared.event.clone(),
        }
        .into();
        let exact88 = Event::from_json(exported.nostr_event_json()).unwrap();
        exact88.verify().unwrap();
        assert_eq!(
            storage.data().announcement_event_id,
            Some(exact88.id.to_hex())
        );
        let bytes = hex::decode(exported.artifact_hex()).unwrap();
        let mut cursor = kormir::lightning::io::Cursor::new(bytes);
        let parsed: OracleAnnouncement = ddk_messages::ser_impls::read_as_tlv(&mut cursor).unwrap();
        assert_eq!(parsed, storage.data().announcement);
        assert_eq!(BASE64.decode(&exact88.content).unwrap(), parsed.encode());

        let prepared89 = attestation(&oracle, &exact88).unwrap();
        prepared89.event.verify().unwrap();
        assert_eq!(prepared89.event.kind, Kind::Custom(89));
        assert_eq!(
            storage.data().attestation_event_id,
            Some(prepared89.event.id.to_hex())
        );
        assert!(prepared89
            .event
            .tags
            .iter()
            .any(|tag| tag == &Tag::event(exact88.id)));
        let bytes = hex::decode(&prepared89.artifact_hex).unwrap();
        assert_eq!(BASE64.decode(&prepared89.event.content).unwrap(), bytes);
        let mut cursor = kormir::lightning::io::Cursor::new(bytes);
        let parsed89 = OracleAttestation::read(&mut cursor).unwrap();
        parsed89
            .validate(&kormir::bitcoin::secp256k1::Secp256k1::new(), &parsed)
            .unwrap();
        assert_eq!(parsed89.outcomes, ["YES"]);
        assert_eq!(storage.0.borrow().next_nonce, 0);
    }

    #[test]
    fn local_preparation_stops_on_storage_failure_before_returning_artifacts() {
        for failure in [Failure::Announcement, Failure::AnnouncementId] {
            let storage = TestStorage::default();
            storage.fail(failure);
            let oracle = oracle(storage.clone());
            let result = ready(prepare_announcement(
                &oracle,
                "match-1".into(),
                vec!["YES".into()],
                1,
                "",
                "",
            ));
            assert!(matches!(result, Err(JsError::StorageFailure)));
            assert_eq!(storage.0.borrow().signature_saves, 0);
        }
        for failure in [Failure::Read, Failure::Signatures, Failure::AttestationId] {
            let storage = TestStorage::default();
            let oracle = oracle(storage.clone());
            let prepared = announcement(&oracle);
            storage.fail(failure);
            assert!(matches!(
                attestation(&oracle, &prepared.event),
                Err(JsError::StorageFailure)
            ));
            assert_eq!(storage.data().attestation_event_id, None);
        }
    }

    #[test]
    fn local_preparation_recovers_saved_same_outcome_after_interrupted_client_save() {
        let storage = TestStorage::default();
        let first_oracle = oracle(storage.clone());
        let prepared = announcement(&first_oracle);
        storage.fail(Failure::AttestationId);
        assert!(matches!(
            attestation(&first_oracle, &prepared.event),
            Err(JsError::StorageFailure)
        ));
        let saved = storage.data();
        assert_eq!(saved.signatures.len(), 1);
        assert_eq!(saved.attestation_event_id, None);
        let signature = saved.attestation().unwrap().encode();
        storage.fail(Failure::None);
        let reloaded = oracle(storage.clone());
        let recovered = attestation(&reloaded, &prepared.event).unwrap();
        assert_eq!(hex::decode(recovered.artifact_hex).unwrap(), signature);
        assert_eq!(storage.data().signatures, saved.signatures);
        assert_eq!(storage.data().indexes, saved.indexes);
        assert_eq!(storage.0.borrow().signature_saves, 1);
    }

    #[test]
    fn local_preparation_refuses_conflicting_outcome_and_exact_parent() {
        let storage = TestStorage::default();
        let oracle = oracle(storage.clone());
        let prepared = announcement(&oracle);
        attestation(&oracle, &prepared.event).unwrap();
        let saved = storage.data();
        let result = ready(prepare_attestation(
            &oracle,
            "match-1".into(),
            "NO".into(),
            prepared.event.as_json(),
        ));
        assert!(matches!(result, Err(JsError::EventAlreadySigned)));
        let other_parent = create_announcement_event_with_metadata(
            &oracle.nostr_keys(),
            &saved.announcement,
            "changed title",
            "description",
        )
        .unwrap();
        assert_ne!(other_parent.id, prepared.event.id);
        assert!(matches!(
            attestation(&oracle, &other_parent),
            Err(JsError::InvalidArgument)
        ));
        assert_eq!(storage.data().signatures, saved.signatures);
        assert_eq!(
            storage.data().announcement_event_id,
            saved.announcement_event_id
        );
        assert_eq!(
            storage.data().attestation_event_id,
            saved.attestation_event_id
        );
        assert_eq!(storage.0.borrow().signature_saves, 1);
    }

    #[test]
    fn local_preparation_recovers_imported_announcement_from_verified_exact88() {
        let original = oracle(TestStorage::default());
        let prepared = announcement(&original);
        let storage = TestStorage::default();
        let restored = oracle(storage.clone());
        let mut imported = original.storage.data();
        imported.announcement_event_id = None;
        imported.private_authority.announcement_event_json = None;
        ready(restored.merge_enum_authority(imported)).unwrap();
        assert_eq!(storage.data().announcement_event_id, None);
        let result = attestation(&restored, &prepared.event).unwrap();
        assert_eq!(
            storage.data().announcement_event_id,
            Some(prepared.event.id.to_hex())
        );
        assert!(result
            .event
            .tags
            .iter()
            .any(|tag| tag == &Tag::event(prepared.event.id)));
        let original_attestation = attestation(&original, &prepared.event).unwrap();
        assert_eq!(result.artifact_hex, original_attestation.artifact_hex);
    }

    #[test]
    fn local_preparation_import_binding_failure_prevents_signing() {
        let original = oracle(TestStorage::default());
        let prepared = announcement(&original);
        let storage = TestStorage::default();
        let restored = oracle(storage.clone());
        let mut imported = original.storage.data();
        imported.announcement_event_id = None;
        imported.private_authority.announcement_event_json = None;
        ready(restored.merge_enum_authority(imported)).unwrap();
        storage.fail(Failure::AnnouncementId);
        assert!(matches!(
            attestation(&restored, &prepared.event),
            Err(JsError::StorageFailure)
        ));
        assert_eq!(storage.data().announcement_event_id, None);
        assert_eq!(storage.data().signatures.len(), 0);
        assert_eq!(storage.0.borrow().signature_saves, 0);
        assert!(matches!(
            retained_announcement_id(&storage.data()),
            Err(JsError::InvalidArgument)
        ));
    }

    #[test]
    fn local_preparation_refuses_unverified_or_unrelated_import_envelopes() {
        let original = oracle(TestStorage::default());
        let prepared = announcement(&original);
        let storage = TestStorage::default();
        let restored = oracle(storage.clone());
        let mut imported = original.storage.data();
        imported.announcement_event_id = None;
        imported.private_authority.announcement_event_json = None;
        ready(restored.merge_enum_authority(imported)).unwrap();
        let foreign_signer = create_announcement_event_with_metadata(
            &Keys::generate(),
            &storage.data().announcement,
            "title",
            "description",
        )
        .unwrap();
        let wrong_content = EventBuilder::new(Kind::Custom(88), "not an announcement")
            .sign_with_keys(&restored.nostr_keys())
            .unwrap();
        let wrong_kind = EventBuilder::new(Kind::Custom(89), prepared.event.content.clone())
            .sign_with_keys(&restored.nostr_keys())
            .unwrap();
        let mut tampered = prepared.event.clone();
        tampered.content.push('x');
        for json in [
            String::new(),
            foreign_signer.as_json(),
            wrong_content.as_json(),
            wrong_kind.as_json(),
            tampered.as_json(),
        ] {
            let result = ready(prepare_attestation(
                &restored,
                "match-1".into(),
                "YES".into(),
                json,
            ));
            assert!(matches!(result, Err(JsError::InvalidArgument)));
            assert_eq!(storage.data().announcement_event_id, None);
            assert_eq!(storage.data().signatures.len(), 0);
        }
    }

    #[test]
    fn local_preparation_refuses_invalid_recovered_signature() {
        let storage = TestStorage::default();
        let oracle = oracle(storage.clone());
        let prepared = announcement(&oracle);
        attestation(&oracle, &prepared.event).unwrap();
        storage
            .0
            .borrow_mut()
            .events
            .get_mut("match-1")
            .unwrap()
            .signatures[0]
            .1 = kormir::Signature::from_slice(&[0; 64]).unwrap();
        assert!(matches!(
            attestation(&oracle, &prepared.event),
            Err(JsError::InvalidArgument)
        ));
        assert_eq!(storage.0.borrow().signature_saves, 1);
    }

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

#[cfg(all(test, target_arch = "wasm32"))]
mod indexeddb_tests {
    use super::*;
    use kormir::private_backup::PrivateEnumAuthority;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    async fn reopen() -> Kormir {
        Kormir::restore("03".repeat(32)).await.unwrap();
        let storage = IndexedDb::new().await.unwrap();
        let oracle =
            Oracle::from_signing_key(storage.clone(), SecretKey::from_slice(&[3; 32]).unwrap())
                .unwrap();
        let client = Client::new(oracle.nostr_keys());
        Kormir {
            storage,
            oracle,
            client,
        }
    }

    async fn test_database() -> rexie::Rexie {
        rexie::Rexie::builder("kormir")
            .version(1)
            .add_object_store(rexie::ObjectStore::new("oracle"))
            .build()
            .await
            .unwrap()
    }

    async fn stored_record_bytes() -> Vec<u8> {
        let database = test_database().await;
        let tx = database
            .transaction(&["oracle"], rexie::TransactionMode::ReadOnly)
            .unwrap();
        let records = tx
            .store("oracle")
            .unwrap()
            .get_all(None, None, None, None)
            .await
            .unwrap();
        tx.done().await.unwrap();
        let records: Vec<(serde_json::Value, serde_json::Value)> = records
            .into_iter()
            .map(|(key, value)| (key.into_serde().unwrap(), value.into_serde().unwrap()))
            .collect();
        serde_json::to_vec(&records).unwrap()
    }

    async fn remove_signing_key() {
        let database = test_database().await;
        let tx = database
            .transaction(&["oracle"], rexie::TransactionMode::ReadWrite)
            .unwrap();
        tx.store("oracle")
            .unwrap()
            .delete(&JsValue::from_serde(NSEC_KEY).unwrap())
            .await
            .unwrap();
        tx.done().await.unwrap();
    }

    fn assert_signing_key_refusal<T>(result: Result<T, JsError>) {
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("Signing key installation must refuse retained records"),
        };
        assert!(matches!(error, JsError::SigningKeyConflict));
        assert!(error.to_string() == "Retained oracle data prevents signing key installation");
    }

    async fn signing_key_install_preserves_retained_authority() {
        IndexedDb::clear().await.unwrap();
        let owner = reopen().await;
        owner
            .prepare_enum_event(
                "retained-authority".into(),
                vec!["YES".into(), "NO".into()],
                1,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
        owner.storage.get_next_nonce_indexes(7).await.unwrap();
        owner
            .storage
            .save_to_indexed_db("unknown-record", serde_json::json!({"future": [1, 2]}))
            .await
            .unwrap();
        let before = stored_record_bytes().await;
        Kormir::restore("03".repeat(32)).await.unwrap();
        assert!(stored_record_bytes().await == before);
        assert_signing_key_refusal(Kormir::restore("04".repeat(32)).await);
        assert!(stored_record_bytes().await == before);
        let restarted = Kormir::new(vec![]).await.unwrap();
        assert!(restarted.get_public_key() == owner.get_public_key());
        assert!(stored_record_bytes().await == before);
        let prepared = restarted
            .prepare_enum_event(
                "retained-authority".into(),
                vec!["YES".into(), "NO".into()],
                1,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
        restarted
            .prepare_enum_attestation(
                "retained-authority".into(),
                "YES".into(),
                prepared.nostr_event_json(),
            )
            .await
            .unwrap();
        assert_eq!(
            restarted.storage.get_next_nonce_indexes(1).await.unwrap(),
            vec![7]
        );
    }

    async fn missing_key_install_refuses_retained_records() {
        for key in [
            "oracle_data/retained-authority",
            "nonce_index",
            "unknown-record",
        ] {
            IndexedDb::clear().await.unwrap();
            let owner = reopen().await;
            owner
                .prepare_enum_event(
                    "retained-authority".into(),
                    vec!["YES".into(), "NO".into()],
                    1,
                    String::new(),
                    String::new(),
                )
                .await
                .unwrap();
            let data = owner
                .storage
                .get_event("retained-authority".into())
                .await
                .unwrap()
                .unwrap();
            IndexedDb::clear().await.unwrap();
            let storage = IndexedDb::new().await.unwrap();
            match key {
                "oracle_data/retained-authority" => {
                    storage.save_to_indexed_db(key, data).await.unwrap()
                }
                "nonce_index" => storage.save_to_indexed_db(key, 7u32).await.unwrap(),
                _ => storage
                    .save_to_indexed_db(key, serde_json::json!({"future": [1, 2]}))
                    .await
                    .unwrap(),
            }
            let before = stored_record_bytes().await;
            assert_signing_key_refusal(Kormir::new(vec![]).await);
            assert!(stored_record_bytes().await == before);
            assert_signing_key_refusal(Kormir::restore("03".repeat(32)).await);
            assert!(stored_record_bytes().await == before);
        }
        IndexedDb::clear().await.unwrap();
        let owner = reopen().await;
        owner.storage.get_next_nonce_indexes(1).await.unwrap();
        remove_signing_key().await;
        let before = stored_record_bytes().await;
        assert_signing_key_refusal(Kormir::restore("03".repeat(32)).await);
        assert!(stored_record_bytes().await == before);
        assert_signing_key_refusal(Kormir::new(vec![]).await);
        assert!(stored_record_bytes().await == before);
    }

    async fn fresh_and_key_only_install_succeeds() {
        IndexedDb::clear().await.unwrap();
        Kormir::new(vec![]).await.unwrap();
        Kormir::restore("04".repeat(32)).await.unwrap();
        let replaced = Kormir::new(vec![]).await.unwrap();
        let expected = Oracle::from_signing_key(
            replaced.storage.clone(),
            SecretKey::from_slice(&[4; 32]).unwrap(),
        )
        .unwrap();
        assert!(replaced.get_public_key() == expected.public_key().to_string());
        IndexedDb::clear().await.unwrap();
        Kormir::restore("0a".repeat(32)).await.unwrap();
        let before = stored_record_bytes().await;
        IndexedDb::restore_signing_key(&"0A".repeat(32))
            .await
            .unwrap();
        assert!(stored_record_bytes().await == before);
        IndexedDb::clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn private_authority_real_indexeddb_restart_race_and_exact_handoff() {
        missing_key_install_refuses_retained_records().await;
        signing_key_install_preserves_retained_authority().await;
        fresh_and_key_only_install_succeeds().await;
        IndexedDb::clear().await.unwrap();
        let first = reopen().await;
        let prepared = first
            .prepare_enum_event(
                "restored-event".into(),
                vec!["YES".into(), "NO".into()],
                1,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
        let exported = first
            .export_enum_authority("restored-event".into(), prepared.nostr_event_json(), None)
            .await
            .unwrap();
        let unsigned: PrivateEnumAuthority = serde_json::from_str(&exported).unwrap();
        let summary = kormir::private_backup::validate_enum_authority_json(&exported, None)
            .unwrap()
            .summary;
        IndexedDb::clear().await.unwrap();
        let restored = reopen().await;
        restored
            .import_enum_authority(exported.clone())
            .await
            .unwrap();
        let restarted = reopen().await;
        assert!(restarted
            .storage
            .get_event("restored-event".into())
            .await
            .unwrap()
            .unwrap()
            .indexes
            .is_empty());
        let (yes, no) = futures::join!(
            restarted.prepare_enum_attestation(
                "restored-event".into(),
                "YES".into(),
                prepared.nostr_event_json()
            ),
            restored.prepare_enum_attestation(
                "restored-event".into(),
                "NO".into(),
                prepared.nostr_event_json()
            )
        );
        assert_eq!(usize::from(yes.is_ok()) + usize::from(no.is_ok()), 1);
        let exact = yes.or(no).unwrap();
        let reloaded = reopen().await;
        let data = reloaded
            .storage
            .get_event("restored-event".into())
            .await
            .unwrap()
            .unwrap();
        let outcome = data.private_authority.choice.clone().unwrap();
        let retry = reloaded
            .prepare_enum_attestation(
                "restored-event".into(),
                outcome.clone(),
                prepared.nostr_event_json(),
            )
            .await
            .unwrap();
        assert!(retry.nostr_event_json() == exact.nostr_event_json());
        reloaded
            .import_enum_authority(exported.clone())
            .await
            .unwrap();
        assert!(
            reloaded
                .storage
                .get_event("restored-event".into())
                .await
                .unwrap()
                .unwrap()
                .private_authority
                .choice
                .as_ref()
                == Some(&outcome)
        );
        let mut signed = unsigned;
        signed.signed_outcome = Some(outcome.clone());
        signed.attestation_hex = Some(exact.artifact_hex());
        signed.attestation_event_json = Some(exact.nostr_event_json());
        let publication = serde_json::json!({ "binding": { "oracleEventId":summary.event_id, "oraclePubkey":summary.oracle_pubkey, "outcomes":summary.outcomes, "announcementEventJson":signed.announcement_event_json }, "chosenOutcome":outcome, "attestation": { "attestationHex":signed.attestation_hex, "eventJson":signed.attestation_event_json }, "relayPublished":true }).to_string();
        signed.publication_record_json = Some(publication.clone());
        reloaded
            .import_enum_authority(serde_json::to_string(&signed).unwrap())
            .await
            .unwrap();
        let staged = reopen().await;
        assert!(
            staged
                .staged_enum_publication("restored-event".into())
                .await
                .unwrap()
                .as_deref()
                == Some(publication.as_str())
        );
        assert!(staged
            .acknowledge_enum_publication("restored-event".into(), "{}".into())
            .await
            .is_err());
        staged
            .acknowledge_enum_publication("restored-event".into(), publication.clone())
            .await
            .unwrap();
        assert!(reopen()
            .await
            .staged_enum_publication("restored-event".into())
            .await
            .unwrap()
            .is_none());
        signed.nonce_scalar_hex = None;
        IndexedDb::clear().await.unwrap();
        let terminal = reopen().await;
        terminal
            .import_enum_authority(serde_json::to_string(&signed).unwrap())
            .await
            .unwrap();
        assert!(terminal.import_enum_authority(exported).await.is_err());
        let exact_again = terminal
            .prepare_enum_attestation(
                "restored-event".into(),
                signed.signed_outcome.unwrap(),
                prepared.nostr_event_json(),
            )
            .await
            .unwrap();
        assert!(exact_again.nostr_event_json() == exact.nostr_event_json());
        assert!(terminal
            .oracle
            .export_enum_nonce("restored-event".into())
            .await
            .unwrap()
            .is_none());
        let unrelated = terminal
            .prepare_enum_event(
                "unrelated".into(),
                vec!["YES".into(), "NO".into()],
                1,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
        let newer = terminal
            .export_enum_authority("unrelated".into(), unrelated.nostr_event_json(), None)
            .await
            .unwrap();
        let next = kormir::private_backup::validate_enum_authority_json(&newer, None)
            .unwrap()
            .summary;
        assert_ne!(summary.nonce_point, next.nonce_point);
        let choice_event = terminal
            .prepare_enum_event(
                "choice-crash".into(),
                vec!["YES".into(), "NO".into()],
                1,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
        let mut chosen = terminal
            .storage
            .get_event("choice-crash".into())
            .await
            .unwrap()
            .unwrap();
        chosen.private_authority.choice = Some("YES".into());
        terminal.oracle.merge_enum_authority(chosen).await.unwrap();
        let after_choice_crash = reopen().await;
        assert!(after_choice_crash
            .prepare_enum_attestation(
                "choice-crash".into(),
                "NO".into(),
                choice_event.nostr_event_json()
            )
            .await
            .is_err());
        assert!(after_choice_crash
            .storage
            .get_event("choice-crash".into())
            .await
            .unwrap()
            .unwrap()
            .signatures
            .is_empty());
        after_choice_crash
            .prepare_enum_attestation(
                "choice-crash".into(),
                "YES".into(),
                choice_event.nostr_event_json(),
            )
            .await
            .unwrap();
        let race_event = terminal
            .prepare_enum_event(
                "import-race".into(),
                vec!["YES".into(), "NO".into()],
                1,
                String::new(),
                String::new(),
            )
            .await
            .unwrap();
        let stale = terminal
            .export_enum_authority("import-race".into(), race_event.nostr_event_json(), None)
            .await
            .unwrap();
        let competitor = reopen().await;
        let (signed_race, imported_race) = futures::join!(
            terminal.prepare_enum_attestation(
                "import-race".into(),
                "YES".into(),
                race_event.nostr_event_json()
            ),
            competitor.import_enum_authority(stale)
        );
        assert!(signed_race.is_ok());
        assert!(imported_race.is_ok());
        let after_race = reopen()
            .await
            .storage
            .get_event("import-race".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_race.private_authority.choice.as_deref(), Some("YES"));
        assert_eq!(after_race.signatures.len(), 1);
        assert!(after_race
            .private_authority
            .attestation_event_json
            .is_some());
        terminal.storage.get_next_nonce_indexes(300).await.unwrap();
        Kormir::restore("03".repeat(32)).await.unwrap();
        let same_key_login = reopen().await;
        assert!(
            same_key_login
                .storage
                .get_event("restored-event".into())
                .await
                .unwrap()
                .unwrap()
                .private_authority
                .attestation_event_json
                .as_deref()
                == Some(exact.nostr_event_json().as_str())
        );
        assert_eq!(
            same_key_login
                .storage
                .get_next_nonce_indexes(1)
                .await
                .unwrap(),
            vec![300]
        );
        let legacy = same_key_login
            .oracle
            .create_enum_event("legacy-high".into(), vec!["YES".into(), "NO".into()], 1)
            .await
            .unwrap();
        let legacy88 =
            create_announcement_event_with_metadata(&terminal.oracle.nostr_keys(), &legacy, "", "")
                .unwrap();
        let legacy_export = terminal
            .export_enum_authority("legacy-high".into(), legacy88.as_json(), None)
            .await
            .unwrap();
        let legacy_dto: PrivateEnumAuthority = serde_json::from_str(&legacy_export).unwrap();
        assert!(!legacy_export.contains("indexes"));
        let listed: serde_json::Value = terminal.list_events().await.unwrap().into_serde().unwrap();
        assert!(!listed
            .to_string()
            .contains(legacy_dto.nonce_scalar_hex.as_ref().unwrap()));
        IndexedDb::clear().await.unwrap();
    }
}
