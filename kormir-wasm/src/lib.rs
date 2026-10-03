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

trait PreparationStorage: Storage {
    async fn retain_announcement_id(&self, event_id: String, id: String) -> Result<(), JsError>;
    async fn retain_attestation_id(&self, event_id: String, id: String) -> Result<(), JsError>;
}

impl PreparationStorage for IndexedDb {
    async fn retain_announcement_id(&self, event_id: String, id: String) -> Result<(), JsError> {
        self.add_announcement_event_id(event_id, id).await
    }

    async fn retain_attestation_id(&self, event_id: String, id: String) -> Result<(), JsError> {
        self.add_attestation_event_id(event_id, id).await
    }
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

async fn prepare_announcement<S: PreparationStorage>(
    oracle: &Oracle<S>,
    event_id: String,
    outcomes: Vec<String>,
    maturity: u32,
    title: &str,
    description: &str,
) -> Result<PreparedEvent, JsError> {
    let ann = oracle
        .create_enum_event(event_id.clone(), outcomes, maturity)
        .await?;
    let event =
        create_announcement_event_with_metadata(&oracle.nostr_keys(), &ann, title, description)?;
    oracle
        .storage
        .retain_announcement_id(event_id, event.id.to_hex())
        .await?;
    Ok(PreparedEvent {
        artifact_hex: encode_announcement_tlv(&ann),
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
    let event = Event::from_json(announcement_event_json).map_err(|_| JsError::InvalidArgument)?;
    event.verify().map_err(|_| JsError::InvalidArgument)?;
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

async fn prepare_attestation<S: PreparationStorage>(
    oracle: &Oracle<S>,
    event_id: String,
    outcome: String,
    announcement_event_json: String,
) -> Result<PreparedEvent, JsError> {
    let data = oracle
        .storage
        .get_event(event_id.clone())
        .await?
        .ok_or(JsError::NotFound)?;
    let parent = verify_retained_announcement(oracle, &data, &event_id, &announcement_event_json)?;
    let recovered = recover_enum_attestation(&data, &outcome)?;
    if data.announcement_event_id.is_none() {
        oracle
            .storage
            .retain_announcement_id(event_id.clone(), parent.to_hex())
            .await?;
    }
    let attestation = match recovered {
        Some(attestation) => attestation,
        None => oracle.sign_enum_event(event_id.clone(), outcome).await?,
    };
    let event = create_attestation_event(&oracle.nostr_keys(), &attestation, parent)?;
    oracle
        .storage
        .retain_attestation_id(event_id, event.id.to_hex())
        .await?;
    Ok(PreparedEvent {
        artifact_hex: hex::encode(attestation.encode()),
        event,
    })
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
        let event = self
            .storage
            .get_event(event_id.clone())
            .await?
            .ok_or(JsError::NotFound)?;
        let nostr_event_id = retained_announcement_id(&event)?;
        let attestation = self
            .oracle
            .sign_enum_event(event_id.clone(), outcome)
            .await?;

        let event =
            create_attestation_event(&self.oracle.nostr_keys(), &attestation, nostr_event_id)?;

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
    /// announcement is re-saved. Use `prepare_enum_attestation` with the retained
    /// signed kind-88 JSON to restore its exact Nostr ID before signing.
    /// This produces the same committed-nonce signature the mint expects.
    ///
    /// `announcement_tlv_hex` is the TLV-enveloped hex returned by
    /// `create_enum_event` (and stored by the client). Returns the event_id.
    pub async fn import_enum_event(&self, announcement_tlv_hex: String) -> Result<String, JsError> {
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

        fn retain_id(
            &self,
            event_id: String,
            id: String,
            announcement: bool,
        ) -> Result<(), JsError> {
            let mut state = self.0.borrow_mut();
            let failure = if announcement {
                Failure::AnnouncementId
            } else {
                Failure::AttestationId
            };
            if state.failure == failure {
                return Err(JsError::StorageFailure);
            }
            let data = state.events.get_mut(&event_id).ok_or(JsError::NotFound)?;
            if announcement {
                data.announcement_event_id = Some(id);
            } else {
                data.attestation_event_id = Some(id);
            }
            Ok(())
        }
    }

    impl Storage for TestStorage {
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

    impl PreparationStorage for TestStorage {
        async fn retain_announcement_id(
            &self,
            event_id: String,
            id: String,
        ) -> Result<(), JsError> {
            self.retain_id(event_id, id, true)
        }

        async fn retain_attestation_id(&self, event_id: String, id: String) -> Result<(), JsError> {
            self.retain_id(event_id, id, false)
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
        assert_eq!(storage.0.borrow().next_nonce, 1);
    }

    #[test]
    fn local_preparation_stops_on_storage_failure_before_returning_artifacts() {
        for failure in [
            Failure::Nonce,
            Failure::Announcement,
            Failure::AnnouncementId,
        ] {
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
        ready(restored.import_announcement(original.storage.data().announcement, 256)).unwrap();
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
        ready(restored.import_announcement(original.storage.data().announcement, 256)).unwrap();
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
        ready(restored.import_announcement(original.storage.data().announcement, 256)).unwrap();
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
