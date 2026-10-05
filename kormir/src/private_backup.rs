//! Validated private enum authority transfer. No secret data implements Debug.
use crate::{
    error::Error,
    storage::{EnumNonceAuthority, EnumPrivateAuthority, OracleEventData},
    EventDescriptor, OracleAnnouncement, OracleAttestation, Readable, Writeable,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use nostr::{Event, JsonUtil, Kind};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const MAX_PRIVATE_AUTHORITY_BYTES: usize = 65_535;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateEnumAuthority {
    pub schema_version: u32,
    pub announcement_tlv_hex: String,
    pub announcement_event_json: String,
    pub nonce_scalar_hex: Option<String>,
    pub signed_outcome: Option<String>,
    pub attestation_hex: Option<String>,
    pub attestation_event_json: Option<String>,
    pub publication_record_json: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnumAuthoritySummary {
    pub event_id: String,
    pub oracle_pubkey: String,
    pub outcomes: Vec<String>,
    pub nonce_point: String,
}

pub struct ValidatedEnumAuthority {
    pub summary: EnumAuthoritySummary,
    pub data: OracleEventData,
}

pub fn validate_enum_authority_json(
    json: &str,
    expected_oracle_pubkey: Option<&str>,
) -> Result<ValidatedEnumAuthority, Error> {
    if json.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    let raw: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
    let fields = [
        "schemaVersion",
        "announcementTlvHex",
        "announcementEventJson",
        "nonceScalarHex",
        "signedOutcome",
        "attestationHex",
        "attestationEventJson",
        "publicationRecordJson",
    ];
    let object = raw.as_object().ok_or(Error::InvalidAnnouncement)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(Error::InvalidAnnouncement);
    }
    let dto: PrivateEnumAuthority =
        serde_json::from_value(raw).map_err(|_| Error::InvalidAnnouncement)?;
    validate_enum_authority(&dto, expected_oracle_pubkey)
}

pub fn validate_enum_authority(
    dto: &PrivateEnumAuthority,
    expected_oracle_pubkey: Option<&str>,
) -> Result<ValidatedEnumAuthority, Error> {
    if dto.schema_version != 1
        || serde_json::to_vec(dto).map_err(|_| Error::Internal)?.len() > MAX_PRIVATE_AUTHORITY_BYTES
    {
        return Err(Error::InvalidAnnouncement);
    }
    let bytes = hex::decode(&dto.announcement_tlv_hex).map_err(|_| Error::InvalidAnnouncement)?;
    let mut cursor = crate::lightning::io::Cursor::new(&bytes);
    let announcement: OracleAnnouncement = ddk_messages::ser_impls::read_as_tlv(&mut cursor)
        .map_err(|_| Error::InvalidAnnouncement)?;
    let mut canonical = Vec::new();
    ddk_messages::ser_impls::write_as_tlv(&announcement, &mut canonical)
        .map_err(|_| Error::InvalidAnnouncement)?;
    if canonical != bytes || hex::encode(&canonical) != dto.announcement_tlv_hex {
        return Err(Error::InvalidAnnouncement);
    }
    let secp = Secp256k1::new();
    announcement
        .validate(&secp)
        .map_err(|_| Error::InvalidAnnouncement)?;
    let EventDescriptor::EnumEvent(descriptor) = &announcement.oracle_event.event_descriptor else {
        return Err(Error::InvalidEventDescriptor);
    };
    if announcement.oracle_event.oracle_nonces.len() != 1 {
        return Err(Error::InvalidNonces);
    }
    let pubkey = announcement.oracle_public_key.to_string();
    if expected_oracle_pubkey.is_some_and(|expected| expected != pubkey) {
        return Err(Error::InvalidAnnouncement);
    }
    let parent = signed_event(
        &dto.announcement_event_json,
        88,
        &pubkey,
        &announcement.encode(),
    )?;
    let nonce = match &dto.nonce_scalar_hex {
        Some(scalar) => {
            let secret = SecretKey::from_str(scalar).map_err(|_| Error::InvalidNonces)?;
            if hex::encode(secret.secret_bytes()) != *scalar
                || secret.x_only_public_key(&secp).0 != announcement.oracle_event.oracle_nonces[0]
            {
                return Err(Error::InvalidNonces);
            }
            EnumNonceAuthority::Explicit {
                scalar: scalar.clone(),
            }
        }
        None => EnumNonceAuthority::Terminal,
    };
    if dto
        .signed_outcome
        .as_ref()
        .is_some_and(|choice| !descriptor.outcomes.contains(choice))
    {
        return Err(Error::InvalidOutcome);
    }
    let (signatures, attestation_event_id) =
        match (&dto.attestation_hex, &dto.attestation_event_json) {
            (None, None) if dto.nonce_scalar_hex.is_some() => (vec![], None),
            (Some(hex), Some(json)) => {
                let bytes = hex::decode(hex).map_err(|_| Error::InvalidAnnouncement)?;
                let mut cursor = crate::lightning::io::Cursor::new(&bytes);
                let attestation =
                    OracleAttestation::read(&mut cursor).map_err(|_| Error::InvalidAnnouncement)?;
                if attestation.event_id != announcement.oracle_event.event_id
                    || attestation.encode() != bytes
                    || hex::encode(&bytes) != *hex
                {
                    return Err(Error::InvalidAnnouncement);
                }
                attestation
                    .validate(&secp, &announcement)
                    .map_err(|_| Error::InvalidAnnouncement)?;
                if attestation.outcomes.len() != 1
                    || attestation.signatures.len() != 1
                    || dto.signed_outcome.as_ref() != attestation.outcomes.first()
                {
                    return Err(Error::InvalidOutcome);
                }
                let event = signed_event(json, 89, &pubkey, &bytes)?;
                let parents: Vec<_> = event
                    .tags
                    .iter()
                    .filter(|tag| tag.as_slice().first().is_some_and(|value| value == "e"))
                    .collect();
                if parents.len() != 1
                    || parents[0].as_slice().len() != 2
                    || parents[0].as_slice().get(1) != Some(&parent.id.to_hex())
                {
                    return Err(Error::InvalidAnnouncement);
                }
                (
                    vec![(attestation.outcomes[0].clone(), attestation.signatures[0])],
                    Some(event.id.to_hex()),
                )
            }
            _ => return Err(Error::InvalidAnnouncement),
        };
    let summary = EnumAuthoritySummary {
        event_id: announcement.oracle_event.event_id.clone(),
        oracle_pubkey: pubkey,
        outcomes: descriptor.outcomes.clone(),
        nonce_point: announcement.oracle_event.oracle_nonces[0].to_string(),
    };
    if let Some(publication) = &dto.publication_record_json {
        validate_publication(publication, dto, &summary)?;
    }
    Ok(ValidatedEnumAuthority {
        data: OracleEventData {
            event_id: summary.event_id.clone(),
            announcement,
            indexes: vec![],
            signatures,
            announcement_event_id: Some(parent.id.to_hex()),
            attestation_event_id,
            private_authority: EnumPrivateAuthority {
                nonce,
                choice: dto.signed_outcome.clone(),
                announcement_event_json: Some(dto.announcement_event_json.clone()),
                attestation_event_json: dto.attestation_event_json.clone(),
                staged_publication_json: dto.publication_record_json.clone(),
            },
        },
        summary,
    })
}

/// Validate the exact public parent used by preparation as well as private import.
pub fn validate_announcement_event_json(
    announcement: &OracleAnnouncement,
    json: &str,
) -> Result<Event, Error> {
    announcement
        .validate(&Secp256k1::verification_only())
        .map_err(|_| Error::InvalidAnnouncement)?;
    signed_event(
        json,
        88,
        &announcement.oracle_public_key.to_string(),
        &announcement.encode(),
    )
}

fn signed_event(json: &str, kind: u16, pubkey: &str, bytes: &[u8]) -> Result<Event, Error> {
    if json.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    let raw: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
    let fields = [
        "id",
        "pubkey",
        "created_at",
        "kind",
        "tags",
        "content",
        "sig",
    ];
    let object = raw.as_object().ok_or(Error::InvalidAnnouncement)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(Error::InvalidAnnouncement);
    }
    let event = Event::from_json(json).map_err(|_| Error::InvalidAnnouncement)?;
    event.verify().map_err(|_| Error::InvalidAnnouncement)?;
    if event.kind != Kind::Custom(kind)
        || event.pubkey.to_hex() != pubkey
        || event.content != BASE64.encode(bytes)
    {
        return Err(Error::InvalidAnnouncement);
    }
    Ok(event)
}

fn validate_publication(
    json: &str,
    dto: &PrivateEnumAuthority,
    summary: &EnumAuthoritySummary,
) -> Result<(), Error> {
    if json.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
    let binding = &value["binding"];
    if binding["oracleEventId"].as_str() != Some(&summary.event_id)
        || binding["oraclePubkey"].as_str() != Some(&summary.oracle_pubkey)
        || binding["announcementEventJson"].as_str() != Some(&dto.announcement_event_json)
        || binding["outcomes"] != serde_json::json!(summary.outcomes)
        || value["chosenOutcome"].as_str() != dto.signed_outcome.as_deref()
        || dto.signed_outcome.is_none()
    {
        return Err(Error::InvalidAnnouncement);
    }
    match (&dto.attestation_hex, &dto.attestation_event_json) {
        (None, None) if value.get("attestation").is_some_and(|v| v.is_null()) => {}
        (Some(hex), Some(event))
            if value["attestation"]["attestationHex"].as_str() == Some(hex)
                && value["attestation"]["eventJson"].as_str() == Some(event) => {}
        _ => return Err(Error::InvalidAnnouncement),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{MemoryStorage, Storage},
        Oracle,
    };
    use nostr::{EventBuilder, Tag};

    fn oracle(storage: MemoryStorage) -> Oracle<MemoryStorage> {
        Oracle::from_signing_key(storage, SecretKey::from_slice(&[3; 32]).unwrap()).unwrap()
    }

    async fn fixture(signed: bool) -> (Oracle<MemoryStorage>, PrivateEnumAuthority) {
        let oracle = oracle(MemoryStorage::new());
        let ann = oracle
            .create_enum_event_with_nonce(
                "private-event".into(),
                vec!["YES".into(), "NO".into()],
                1,
                SecretKey::from_slice(&[2; 32]).unwrap(),
            )
            .await
            .unwrap();
        let parent = EventBuilder::new(Kind::Custom(88), BASE64.encode(ann.encode()))
            .sign_with_keys(&oracle.nostr_keys())
            .unwrap();
        let mut tlv = vec![];
        ddk_messages::ser_impls::write_as_tlv(&ann, &mut tlv).unwrap();
        let mut dto = PrivateEnumAuthority {
            schema_version: 1,
            announcement_tlv_hex: hex::encode(tlv),
            announcement_event_json: parent.as_json(),
            nonce_scalar_hex: Some("02".repeat(32)),
            signed_outcome: None,
            attestation_hex: None,
            attestation_event_json: None,
            publication_record_json: None,
        };
        if signed {
            let att = oracle
                .sign_enum_event("private-event".into(), "YES".into())
                .await
                .unwrap();
            let event = EventBuilder::new(Kind::Custom(89), BASE64.encode(att.encode()))
                .tag(Tag::event(parent.id))
                .sign_with_keys(&oracle.nostr_keys())
                .unwrap();
            dto.signed_outcome = Some("YES".into());
            dto.attestation_hex = Some(hex::encode(att.encode()));
            dto.attestation_event_json = Some(event.as_json());
        }
        (oracle, dto)
    }

    #[tokio::test]
    async fn explicit_restore_signs_and_terminal_import_cannot_regain_nonce() {
        let (_, unsigned) = fixture(false).await;
        let restored = oracle(MemoryStorage::new());
        let valid =
            validate_enum_authority(&unsigned, Some(&restored.public_key().to_string())).unwrap();
        restored.merge_enum_authority(valid.data).await.unwrap();
        let att = restored
            .sign_enum_event("private-event".into(), "YES".into())
            .await
            .unwrap();
        let mut terminal = unsigned.clone();
        let parent = Event::from_json(&terminal.announcement_event_json).unwrap();
        let event = EventBuilder::new(Kind::Custom(89), BASE64.encode(att.encode()))
            .tag(Tag::event(parent.id))
            .sign_with_keys(&restored.nostr_keys())
            .unwrap();
        terminal.signed_outcome = Some("YES".into());
        terminal.attestation_hex = Some(hex::encode(att.encode()));
        terminal.attestation_event_json = Some(event.as_json());
        terminal.nonce_scalar_hex = None;
        let terminal_data = validate_enum_authority(&terminal, None).unwrap().data;
        restored.merge_enum_authority(terminal_data).await.unwrap();
        assert!(restored
            .export_enum_nonce("private-event".into())
            .await
            .unwrap()
            .is_none());
        assert!(restored
            .merge_enum_authority(validate_enum_authority(&unsigned, None).unwrap().data)
            .await
            .is_err());
        assert!(restored
            .sign_enum_event("private-event".into(), "NO".into())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn legacy_export_uses_retained_index_above_255_and_new_authority_is_redacted() {
        let original = oracle(MemoryStorage::new());
        original.storage.get_next_nonce_indexes(300).await.unwrap();
        let ann = original
            .create_enum_event("legacy".into(), vec!["YES".into()], 1)
            .await
            .unwrap();
        let legacy_row = original
            .storage
            .get_event("legacy".into())
            .await
            .unwrap()
            .unwrap();
        let mut old_format = serde_json::to_value(&legacy_row).unwrap();
        old_format
            .as_object_mut()
            .unwrap()
            .remove("private_authority");
        let decoded: OracleEventData = serde_json::from_value(old_format).unwrap();
        assert!(matches!(
            decoded.private_authority.nonce,
            EnumNonceAuthority::Legacy
        ));
        assert!(original
            .storage
            .compare_exchange_event(Some(legacy_row), decoded)
            .await
            .unwrap());
        let nonce = original
            .export_enum_nonce("legacy".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            nonce.x_only_public_key(&Secp256k1::new()).0,
            ann.oracle_event.oracle_nonces[0]
        );
        let (_, dto) = fixture(false).await;
        let data = validate_enum_authority(&dto, None).unwrap().data;
        assert!(!format!("{data:?}").contains(dto.nonce_scalar_hex.as_ref().unwrap()));
    }

    #[tokio::test]
    async fn local_choice_precedes_signing_and_survives_stale_import() {
        let (owner, dto) = fixture(false).await;
        let (yes, no) = tokio::join!(
            owner.sign_enum_event("private-event".into(), "YES".into()),
            owner.sign_enum_event("private-event".into(), "NO".into())
        );
        assert_eq!(usize::from(yes.is_ok()) + usize::from(no.is_ok()), 1);
        let before = owner
            .storage
            .get_event("private-event".into())
            .await
            .unwrap()
            .unwrap();
        let merged = owner
            .merge_enum_authority(validate_enum_authority(&dto, None).unwrap().data)
            .await
            .unwrap();
        assert_eq!(merged.signatures, before.signatures);
        assert_eq!(
            merged.private_authority.choice,
            before.private_authority.choice
        );
    }

    #[tokio::test]
    async fn rejects_foreign_malformed_and_conflicting_private_payloads_without_mutation() {
        let (_, dto) = fixture(true).await;
        assert!(validate_enum_authority(&dto, Some(&"00".repeat(32))).is_err());
        let mut bad = dto.clone();
        bad.announcement_tlv_hex.push_str("00");
        assert!(validate_enum_authority(&bad, None).is_err());
        bad = dto.clone();
        bad.nonce_scalar_hex = Some("04".repeat(32));
        assert!(validate_enum_authority(&bad, None).is_err());
        bad = dto.clone();
        bad.signed_outcome = Some("NO".into());
        assert!(validate_enum_authority(&bad, None).is_err());
        bad = dto.clone();
        bad.attestation_hex = Some("00".into());
        assert!(validate_enum_authority(&bad, None).is_err());
        bad = dto.clone();
        bad.publication_record_json = Some("x".repeat(MAX_PRIVATE_AUTHORITY_BYTES));
        assert!(validate_enum_authority(&bad, None).is_err());
        let (_, mut unsigned) = fixture(false).await;
        unsigned.nonce_scalar_hex = None;
        assert!(validate_enum_authority(&unsigned, None).is_err());
    }

    #[tokio::test]
    async fn rejects_foreign_inner_event_id_with_valid_signature_and_exact_parent() {
        let (owner, mut dto) = fixture(true).await;
        let bytes = hex::decode(dto.attestation_hex.as_ref().unwrap()).unwrap();
        let mut attestation =
            OracleAttestation::read(&mut crate::lightning::io::Cursor::new(&bytes)).unwrap();
        attestation.event_id = "foreign-event".into();
        let announcement = owner
            .storage
            .get_event("private-event".into())
            .await
            .unwrap()
            .unwrap()
            .announcement;
        // DLC signatures authenticate the outcome, but this upstream check does not bind the event ID.
        assert!(attestation
            .validate(&Secp256k1::new(), &announcement)
            .is_ok());
        let parent = Event::from_json(&dto.announcement_event_json).unwrap();
        let event = EventBuilder::new(Kind::Custom(89), BASE64.encode(attestation.encode()))
            .tag(Tag::event(parent.id))
            .sign_with_keys(&owner.nostr_keys())
            .unwrap();
        assert!(event.verify().is_ok());
        dto.attestation_hex = Some(hex::encode(attestation.encode()));
        dto.attestation_event_json = Some(event.as_json());
        assert!(validate_enum_authority(&dto, None).is_err());
        assert!(validate_enum_authority_json(&serde_json::to_string(&dto).unwrap(), None).is_err());
    }

    #[tokio::test]
    async fn rejects_extended_event_json_noncanonical_base64_and_extended_parent_tag() {
        let (owner, dto) = fixture(true).await;
        let mut bad = dto.clone();
        let mut parent: serde_json::Value =
            serde_json::from_str(&dto.announcement_event_json).unwrap();
        parent["extra"] = serde_json::json!(true);
        bad.announcement_event_json = parent.to_string();
        assert!(validate_enum_authority(&bad, None).is_err());
        let parent = Event::from_json(&dto.announcement_event_json).unwrap();
        let altered = EventBuilder::new(Kind::Custom(88), format!("{}=", parent.content))
            .sign_with_keys(&owner.nostr_keys())
            .unwrap();
        bad = dto.clone();
        bad.announcement_event_json = altered.as_json();
        assert!(validate_enum_authority(&bad, None).is_err());
        let attestation = Event::from_json(dto.attestation_event_json.as_ref().unwrap()).unwrap();
        let extended = EventBuilder::new(Kind::Custom(89), attestation.content)
            .tag(Tag::parse(["e", &parent.id.to_hex(), "wss://relay.example"]).unwrap())
            .sign_with_keys(&owner.nostr_keys())
            .unwrap();
        bad = dto.clone();
        bad.attestation_event_json = Some(extended.as_json());
        assert!(validate_enum_authority(&bad, None).is_err());
        let mut missing: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&dto).unwrap()).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("publicationRecordJson");
        assert!(validate_enum_authority_json(&missing.to_string(), None).is_err());
    }

    #[tokio::test]
    async fn exact_staged_publication_requires_matching_acknowledgment() {
        let (_, mut dto) = fixture(true).await;
        let summary = validate_enum_authority(&dto, None).unwrap().summary;
        let publication = serde_json::json!({ "binding": { "oracleEventId":summary.event_id, "oraclePubkey":summary.oracle_pubkey, "outcomes":summary.outcomes, "announcementEventJson":dto.announcement_event_json }, "chosenOutcome":"YES", "attestation": { "attestationHex":dto.attestation_hex, "eventJson":dto.attestation_event_json }}).to_string();
        dto.publication_record_json = Some(publication.clone());
        let owner = oracle(MemoryStorage::new());
        owner
            .merge_enum_authority(validate_enum_authority(&dto, None).unwrap().data)
            .await
            .unwrap();
        let mut wrong_binding = dto.clone();
        let mut changed: serde_json::Value = serde_json::from_str(&publication).unwrap();
        changed["chosenOutcome"] = serde_json::json!("NO");
        wrong_binding.publication_record_json = Some(changed.to_string());
        assert!(validate_enum_authority(&wrong_binding, None).is_err());
        let mut conflicting_stage = dto.clone();
        let mut changed: serde_json::Value = serde_json::from_str(&publication).unwrap();
        changed["relayPublished"] = serde_json::json!(true);
        conflicting_stage.publication_record_json = Some(changed.to_string());
        assert!(owner
            .merge_enum_authority(
                validate_enum_authority(&conflicting_stage, None)
                    .unwrap()
                    .data
            )
            .await
            .is_err());
        assert!(owner
            .acknowledge_enum_publication("private-event".into(), "{}")
            .await
            .is_err());
        let retained = owner
            .storage
            .get_event("private-event".into())
            .await
            .unwrap()
            .unwrap();
        assert!(
            retained
                .private_authority
                .staged_publication_json
                .as_deref()
                == Some(publication.as_str())
        );
        owner
            .acknowledge_enum_publication("private-event".into(), &publication)
            .await
            .unwrap();
        assert!(owner
            .storage
            .get_event("private-event".into())
            .await
            .unwrap()
            .unwrap()
            .private_authority
            .staged_publication_json
            .is_none());
    }
}
