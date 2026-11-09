//! Validated private enum authority transfer. No secret data implements Debug.
use crate::{
    error::Error,
    storage::{EnumNonceAuthority, EnumPrivateAuthority, OracleEventData},
    EventDescriptor, OracleAnnouncement, OracleAttestation, Readable, Writeable,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use nostr::{Event, JsonUtil, Kind};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Bounded serialized authority accepted at the external backup/helper boundary.
pub const MAX_PRIVATE_AUTHORITY_BYTES: usize = 65_535;
/// Expanded local publication views duplicate artifacts. They are never a wire format.
pub const MAX_AUTHORITY_MODEL_BYTES: usize = 4 * MAX_PRIVATE_AUTHORITY_BYTES;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactPrivateEnumAuthority {
    pub schema_version: u32,
    pub announcement_tlv_hex: String,
    pub announcement_event_json: String,
    pub nonce_scalar_hex: Option<String>,
    pub signed_outcome: Option<String>,
    pub attestation_hex: Option<String>,
    pub attestation_event_json: Option<String>,
    pub publication: Option<CompactPublication>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactPublication {
    pub relay_published: bool,
    pub engine_evidence: Option<PublicationEvidence>,
    pub explanation_event_json: Option<String>,
    pub explanation_relay_published: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationEvidence {
    pub condition_id: String,
    pub oracle_event_id: String,
    pub oracle_pubkey: String,
    pub outcome: String,
    pub announcement_event_id: String,
    pub attestation_event_id: String,
}

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

/// Decode a wire version into the shared semantic model, preserving exact signed strings.
pub fn decode_enum_authority_json(
    json: &str,
    expected_oracle_pubkey: Option<&str>,
) -> Result<PrivateEnumAuthority, Error> {
    if json.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    let raw: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
    let version = raw["schemaVersion"]
        .as_u64()
        .ok_or(Error::InvalidAnnouncement)?;
    match version {
        1 => {
            require_keys(&raw, &AUTHORITY_V1_FIELDS)?;
            let dto: PrivateEnumAuthority =
                serde_json::from_value(raw).map_err(|_| Error::InvalidAnnouncement)?;
            validate_enum_authority(&dto, expected_oracle_pubkey)?;
            Ok(dto)
        }
        2 => {
            require_keys(&raw, &AUTHORITY_V2_FIELDS)?;
            check_compact_publication_shape(&raw["publication"])?;
            // Deserialize the original bytes as well: Value would hide duplicate keys.
            let compact: CompactPrivateEnumAuthority =
                serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
            expand_compact_authority(compact, expected_oracle_pubkey)
        }
        _ => Err(Error::InvalidAnnouncement),
    }
}

pub fn validate_enum_authority_json(
    json: &str,
    expected_oracle_pubkey: Option<&str>,
) -> Result<ValidatedEnumAuthority, Error> {
    let dto = decode_enum_authority_json(json, expected_oracle_pubkey)?;
    validate_authority_model(&dto, expected_oracle_pubkey)
}

/// The deployed v1 entry point retains its exact wire bound.
pub fn validate_enum_authority(
    dto: &PrivateEnumAuthority,
    expected_oracle_pubkey: Option<&str>,
) -> Result<ValidatedEnumAuthority, Error> {
    if serde_json::to_vec(dto).map_err(|_| Error::Internal)?.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    validate_authority_model(dto, expected_oracle_pubkey)
}

/// Explicit output-version selection; callers keep v1 as the release default.
pub fn encode_enum_authority_json(
    dto: &PrivateEnumAuthority,
    expected_oracle_pubkey: Option<&str>,
    version: u32,
) -> Result<String, Error> {
    let validated = validate_authority_model(dto, expected_oracle_pubkey)?;
    let json = match version {
        1 => serde_json::to_string(dto).map_err(|_| Error::Internal)?,
        2 => {
            let compact = compact_authority(dto, &validated.summary)?;
            // Validate the same semantics that external v2 readers will enforce.
            expand_compact_authority(compact.clone(), expected_oracle_pubkey)?;
            serde_json::to_string(&compact).map_err(|_| Error::Internal)?
        }
        _ => return Err(Error::InvalidAnnouncement),
    };
    if json.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    Ok(json)
}

/// Semantic validation of the bounded expanded local model, independent of wire encoding.
fn validate_authority_model(
    dto: &PrivateEnumAuthority,
    expected_oracle_pubkey: Option<&str>,
) -> Result<ValidatedEnumAuthority, Error> {
    if dto.schema_version != 1
        || serde_json::to_vec(dto).map_err(|_| Error::Internal)?.len() > MAX_AUTHORITY_MODEL_BYTES
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
    if json.len() > MAX_AUTHORITY_MODEL_BYTES {
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

const AUTHORITY_V1_FIELDS: [&str; 8] = [
    "schemaVersion",
    "announcementTlvHex",
    "announcementEventJson",
    "nonceScalarHex",
    "signedOutcome",
    "attestationHex",
    "attestationEventJson",
    "publicationRecordJson",
];
const AUTHORITY_V2_FIELDS: [&str; 8] = [
    "schemaVersion",
    "announcementTlvHex",
    "announcementEventJson",
    "nonceScalarHex",
    "signedOutcome",
    "attestationHex",
    "attestationEventJson",
    "publication",
];
const PROGRESS_FIELDS: [&str; 4] = [
    "relayPublished",
    "engineEvidence",
    "explanationEventJson",
    "explanationRelayPublished",
];
const EVIDENCE_FIELDS: [&str; 6] = [
    "conditionId",
    "oracleEventId",
    "oraclePubkey",
    "outcome",
    "announcementEventId",
    "attestationEventId",
];

fn require_keys(value: &serde_json::Value, fields: &[&str]) -> Result<(), Error> {
    let object = value.as_object().ok_or(Error::InvalidAnnouncement)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(Error::InvalidAnnouncement);
    }
    Ok(())
}

fn check_compact_publication_shape(value: &serde_json::Value) -> Result<(), Error> {
    if value.is_null() {
        return Ok(());
    }
    require_keys(value, &PROGRESS_FIELDS)?;
    if !value["engineEvidence"].is_null() {
        require_keys(&value["engineEvidence"], &EVIDENCE_FIELDS)?;
    }
    Ok(())
}

/// The condition identifier is the single-oracle NUT-CTF tagged hash.
fn condition_id(summary: &EnumAuthoritySummary) -> Result<String, Error> {
    if !(2..=8).contains(&summary.outcomes.len())
        || summary.event_id.is_empty()
        || summary.event_id.len() > 512
    {
        return Err(Error::InvalidAnnouncement);
    }
    let tag = sha256::Hash::hash(b"Cashu_condition_id");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(&hex::decode(&summary.oracle_pubkey).map_err(|_| Error::InvalidAnnouncement)?);
    engine.input(summary.event_id.as_bytes());
    engine.input(&[summary.outcomes.len() as u8]);
    Ok(sha256::Hash::from_engine(engine).to_string())
}

fn compact_authority(
    dto: &PrivateEnumAuthority,
    summary: &EnumAuthoritySummary,
) -> Result<CompactPrivateEnumAuthority, Error> {
    let publication = match &dto.publication_record_json {
        None => None,
        Some(json) => {
            let value: serde_json::Value =
                serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
            require_keys(
                &value,
                &[
                    "binding",
                    "chosenOutcome",
                    "attestation",
                    "relayPublished",
                    "engineEvidence",
                    "explanationEventJson",
                    "explanationRelayPublished",
                ],
            )?;
            require_keys(
                &value["binding"],
                &[
                    "conditionId",
                    "oracleEventId",
                    "oraclePubkey",
                    "outcomes",
                    "announcementEventJson",
                ],
            )?;
            if value["binding"]["conditionId"].as_str() != Some(&condition_id(summary)?) {
                return Err(Error::InvalidAnnouncement);
            }
            if !value["attestation"].is_null() {
                require_keys(&value["attestation"], &["attestationHex", "eventJson"])?;
            }
            let progress = serde_json::json!({
                "relayPublished": value["relayPublished"],
                "engineEvidence": value["engineEvidence"],
                "explanationEventJson": value["explanationEventJson"],
                "explanationRelayPublished": value["explanationRelayPublished"]
            });
            check_compact_publication_shape(&progress)?;
            Some(serde_json::from_value(progress).map_err(|_| Error::InvalidAnnouncement)?)
        }
    };
    Ok(CompactPrivateEnumAuthority {
        schema_version: 2,
        announcement_tlv_hex: dto.announcement_tlv_hex.clone(),
        announcement_event_json: dto.announcement_event_json.clone(),
        nonce_scalar_hex: dto.nonce_scalar_hex.clone(),
        signed_outcome: dto.signed_outcome.clone(),
        attestation_hex: dto.attestation_hex.clone(),
        attestation_event_json: dto.attestation_event_json.clone(),
        publication,
    })
}

fn expand_compact_authority(
    compact: CompactPrivateEnumAuthority,
    expected_oracle_pubkey: Option<&str>,
) -> Result<PrivateEnumAuthority, Error> {
    if compact.schema_version != 2 {
        return Err(Error::InvalidAnnouncement);
    }
    let mut dto = PrivateEnumAuthority {
        schema_version: 1,
        announcement_tlv_hex: compact.announcement_tlv_hex,
        announcement_event_json: compact.announcement_event_json,
        nonce_scalar_hex: compact.nonce_scalar_hex,
        signed_outcome: compact.signed_outcome,
        attestation_hex: compact.attestation_hex,
        attestation_event_json: compact.attestation_event_json,
        publication_record_json: None,
    };
    let validated = validate_authority_model(&dto, expected_oracle_pubkey)?;
    let condition = condition_id(&validated.summary)?;
    if let Some(progress) = compact.publication {
        validate_compact_progress(&progress, &dto, &validated, &condition)?;
        dto.publication_record_json = Some(
            serde_json::json!({
                "binding": {
                    "conditionId": condition,
                    "oracleEventId": validated.summary.event_id,
                    "oraclePubkey": validated.summary.oracle_pubkey,
                    "outcomes": validated.summary.outcomes,
                    "announcementEventJson": dto.announcement_event_json,
                },
                "chosenOutcome": dto.signed_outcome,
                "attestation": dto.attestation_hex.as_ref().map(|artifact| serde_json::json!({
                    "attestationHex": artifact, "eventJson": dto.attestation_event_json,
                })),
                "relayPublished": progress.relay_published,
                "engineEvidence": progress.engine_evidence,
                "explanationEventJson": progress.explanation_event_json,
                "explanationRelayPublished": progress.explanation_relay_published,
            })
            .to_string(),
        );
    } else if dto.nonce_scalar_hex.is_none() {
        return Err(Error::InvalidAnnouncement);
    }
    validate_authority_model(&dto, expected_oracle_pubkey)?;
    Ok(dto)
}

fn validate_compact_progress(
    progress: &CompactPublication,
    dto: &PrivateEnumAuthority,
    validated: &ValidatedEnumAuthority,
    condition: &str,
) -> Result<(), Error> {
    let outcome = dto.signed_outcome.as_deref().ok_or(Error::InvalidOutcome)?;
    let summary = &validated.summary;
    let parent = validated
        .data
        .announcement_event_id
        .as_deref()
        .ok_or(Error::InvalidAnnouncement)?;
    let attestation = validated.data.attestation_event_id.as_deref();
    if attestation.is_none()
        && (progress.relay_published
            || progress.engine_evidence.is_some()
            || progress.explanation_event_json.is_some()
            || progress.explanation_relay_published)
    {
        return Err(Error::InvalidAnnouncement);
    }
    if let Some(evidence) = &progress.engine_evidence {
        if evidence.condition_id != condition
            || evidence.oracle_event_id != summary.event_id
            || evidence.oracle_pubkey != summary.oracle_pubkey
            || evidence.outcome != outcome
            || evidence.announcement_event_id != parent
            || Some(evidence.attestation_event_id.as_str()) != attestation
        {
            return Err(Error::InvalidAnnouncement);
        }
    }
    if let Some(explanation) = &progress.explanation_event_json {
        validate_explanation(
            explanation,
            &summary.oracle_pubkey,
            parent,
            attestation.ok_or(Error::InvalidAnnouncement)?,
        )?;
    } else if progress.explanation_relay_published {
        return Err(Error::InvalidAnnouncement);
    }
    if dto.nonce_scalar_hex.is_none()
        && !(attestation.is_some()
            && (progress.relay_published || progress.engine_evidence.is_some()))
    {
        return Err(Error::InvalidNonces);
    }
    Ok(())
}

fn validate_explanation(
    json: &str,
    author: &str,
    parent: &str,
    attestation: &str,
) -> Result<(), Error> {
    if json.len() > MAX_PRIVATE_AUTHORITY_BYTES {
        return Err(Error::InvalidAnnouncement);
    }
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| Error::InvalidAnnouncement)?;
    require_keys(
        &value,
        &[
            "id",
            "pubkey",
            "created_at",
            "kind",
            "tags",
            "content",
            "sig",
        ],
    )?;
    let event = Event::from_json(json).map_err(|_| Error::InvalidAnnouncement)?;
    event.verify().map_err(|_| Error::InvalidAnnouncement)?;
    if event.kind.as_u16() != 1111
        || event.pubkey.to_hex() != author
        || event.content.len() > 4096
        || event.content.trim().is_empty()
        || event.tags.len() > 128
    {
        return Err(Error::InvalidAnnouncement);
    }
    for tag in event.tags.iter() {
        let values = tag.as_slice();
        if values.is_empty()
            || values.len() > 16
            || values.iter().any(|v| v.len() > 1024)
            || ["A", "a", "I", "i"].contains(&values[0].as_str())
        {
            return Err(Error::InvalidAnnouncement);
        }
    }
    for (name, reference) in [("E", parent), ("e", attestation)] {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.as_slice()[0] == name)
            .collect();
        if tags.len() != 1
            || tags[0].as_slice().len() != 4
            || tags[0].as_slice()[1] != reference
            || tags[0].as_slice()[3] != author
        {
            return Err(Error::InvalidAnnouncement);
        }
    }
    for (name, expected) in [("K", "88"), ("k", "89"), ("P", author), ("p", author)] {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.as_slice()[0] == name)
            .collect();
        if tags.len() != 1 || tags[0].as_slice().len() != 2 || tags[0].as_slice()[1] != expected {
            return Err(Error::InvalidAnnouncement);
        }
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

    fn publication(
        progress: &PrivateEnumAuthority,
        summary: &EnumAuthoritySummary,
        explanation: Option<String>,
        relay: bool,
    ) -> String {
        serde_json::json!({
            "binding": { "conditionId":condition_id(summary).unwrap(), "oracleEventId":summary.event_id, "oraclePubkey":summary.oracle_pubkey, "outcomes":summary.outcomes, "announcementEventJson":progress.announcement_event_json },
            "chosenOutcome": progress.signed_outcome,
            "attestation": progress.attestation_hex.as_ref().map(|hex| serde_json::json!({"attestationHex":hex,"eventJson":progress.attestation_event_json})),
            "relayPublished":relay,"engineEvidence":null,"explanationEventJson":explanation,"explanationRelayPublished":false
        }).to_string()
    }

    fn explanation(
        owner: &Oracle<MemoryStorage>,
        dto: &PrivateEnumAuthority,
        content: String,
    ) -> String {
        let parent = Event::from_json(&dto.announcement_event_json).unwrap();
        let attestation = Event::from_json(dto.attestation_event_json.as_ref().unwrap()).unwrap();
        let key = owner.public_key().to_string();
        EventBuilder::new(Kind::Custom(1111), content)
            .allow_self_tagging()
            .tags([
                Tag::parse(["E", &parent.id.to_hex(), "", &key]).unwrap(),
                Tag::parse(["K", "88"]).unwrap(),
                Tag::parse(["P", &key]).unwrap(),
                Tag::parse(["e", &attestation.id.to_hex(), "", &key]).unwrap(),
                Tag::parse(["k", "89"]).unwrap(),
                Tag::parse(["p", &key]).unwrap(),
            ])
            .sign_with_keys(&owner.nostr_keys())
            .unwrap()
            .as_json()
    }

    #[tokio::test]
    async fn compact_round_trip_preserves_exact_artifacts_through_each_lifecycle_state() {
        let (owner, mut unsigned) = fixture(false).await;
        // Whitespace is deliberately retained rather than reserializing the signed event.
        unsigned.announcement_event_json = format!(" {}\n", unsigned.announcement_event_json);
        let summary = validate_enum_authority(&unsigned, None).unwrap().summary;
        let mut choice = unsigned.clone();
        choice.signed_outcome = Some("YES".into());
        choice.publication_record_json = Some(publication(&choice, &summary, None, false));
        let (_, mut signed) = fixture(true).await;
        signed.publication_record_json = Some(publication(&signed, &summary, None, false));
        let mut explained = signed.clone();
        let signed_explanation = explanation(&owner, &signed, "A multilingual 判定理由 🗳️".into());
        explained.publication_record_json = Some(publication(
            &explained,
            &summary,
            Some(signed_explanation),
            false,
        ));
        let mut engine_confirmed = explained.clone();
        let mut evidence_stage: serde_json::Value =
            serde_json::from_str(engine_confirmed.publication_record_json.as_ref().unwrap())
                .unwrap();
        evidence_stage["engineEvidence"] = serde_json::json!({
            "conditionId":condition_id(&summary).unwrap(),"oracleEventId":summary.event_id,
            "oraclePubkey":summary.oracle_pubkey,"outcome":"YES",
            "announcementEventId":Event::from_json(&engine_confirmed.announcement_event_json).unwrap().id.to_hex(),
            "attestationEventId":Event::from_json(engine_confirmed.attestation_event_json.as_ref().unwrap()).unwrap().id.to_hex()
        });
        evidence_stage["explanationRelayPublished"] = serde_json::json!(true);
        engine_confirmed.publication_record_json = Some(evidence_stage.to_string());
        let mut terminal = explained.clone();
        terminal.nonce_scalar_hex = None;
        let mut progress: serde_json::Value =
            serde_json::from_str(terminal.publication_record_json.as_ref().unwrap()).unwrap();
        progress["relayPublished"] = serde_json::json!(true);
        terminal.publication_record_json = Some(progress.to_string());
        for state in [
            unsigned,
            choice,
            signed,
            explained,
            engine_confirmed,
            terminal,
        ] {
            let v1 = encode_enum_authority_json(&state, None, 1).unwrap();
            assert_eq!(
                decode_enum_authority_json(&v1, None)
                    .unwrap()
                    .announcement_event_json,
                state.announcement_event_json
            );
            let v2 = encode_enum_authority_json(&state, None, 2).unwrap();
            let raw: serde_json::Value = serde_json::from_str(&v2).unwrap();
            assert_eq!(raw["schemaVersion"], 2);
            assert!(raw.get("publicationRecordJson").is_none());
            let restored = decode_enum_authority_json(&v2, None).unwrap();
            assert_eq!(
                restored.announcement_event_json,
                state.announcement_event_json
            );
            assert_eq!(
                restored.attestation_event_json,
                state.attestation_event_json
            );
            assert_eq!(restored.attestation_hex, state.attestation_hex);
            assert_eq!(restored.nonce_scalar_hex, state.nonce_scalar_hex);
            assert_eq!(restored.signed_outcome, state.signed_outcome);
            let before: Option<serde_json::Value> = state
                .publication_record_json
                .as_ref()
                .map(|json| serde_json::from_str(json).unwrap());
            let after: Option<serde_json::Value> = restored
                .publication_record_json
                .as_ref()
                .map(|json| serde_json::from_str(json).unwrap());
            assert_eq!(after, before);
            validate_enum_authority_json(&v2, None).unwrap();
        }
    }

    #[tokio::test]
    async fn compact_rejects_unknown_missing_conflicting_and_impossible_progress() {
        let (owner, mut dto) = fixture(true).await;
        let summary = validate_enum_authority(&dto, None).unwrap().summary;
        dto.publication_record_json = Some(publication(
            &dto,
            &summary,
            Some(explanation(&owner, &dto, "reason".into())),
            false,
        ));
        let encoded = encode_enum_authority_json(&dto, None, 2).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        for size in [MAX_PRIVATE_AUTHORITY_BYTES - 1, MAX_PRIVATE_AUTHORITY_BYTES] {
            let padded = format!("{}{}", encoded, " ".repeat(size - encoded.len()));
            validate_enum_authority_json(&padded, None).unwrap();
        }
        let oversized = format!(
            "{}{}",
            encoded,
            " ".repeat(MAX_PRIVATE_AUTHORITY_BYTES + 1 - encoded.len())
        );
        assert!(validate_enum_authority_json(&oversized, None).is_err());
        let mut mutations = Vec::new();
        let mut bad = value.clone();
        bad["schemaVersion"] = serde_json::json!(3);
        mutations.push(bad);
        let mut bad = value.clone();
        bad["extra"] = serde_json::json!(null);
        mutations.push(bad);
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove("nonceScalarHex");
        mutations.push(bad);
        let mut bad = value.clone();
        bad["publication"]
            .as_object_mut()
            .unwrap()
            .remove("engineEvidence");
        mutations.push(bad);
        let mut bad = value.clone();
        bad["publication"]["extra"] = serde_json::json!(true);
        mutations.push(bad);
        let mut bad = value.clone();
        bad["signedOutcome"] = serde_json::json!("NO");
        mutations.push(bad);
        let mut bad = value.clone();
        bad["nonceScalarHex"] = serde_json::json!(null);
        mutations.push(bad);
        let mut bad = value.clone();
        bad["publication"]["explanationEventJson"] = serde_json::json!(null);
        bad["publication"]["explanationRelayPublished"] = serde_json::json!(true);
        mutations.push(bad);
        let mut bad = value.clone();
        bad["publication"]["engineEvidence"] = serde_json::json!({"conditionId":"00".repeat(32),"oracleEventId":summary.event_id,"oraclePubkey":summary.oracle_pubkey,"outcome":"YES","announcementEventId":"00".repeat(32),"attestationEventId":"00".repeat(32)});
        mutations.push(bad);
        let mut bad = value.clone();
        bad["publication"]["explanationEventJson"] = serde_json::json!(dto.attestation_event_json);
        mutations.push(bad);
        for bad in mutations {
            assert!(validate_enum_authority_json(&bad.to_string(), None).is_err());
        }
        assert!(validate_enum_authority_json(&encoded.replace("reason", "\\ud800"), None).is_err());
        let duplicated = encoded.replacen(
            "\"schemaVersion\":2",
            "\"schemaVersion\":2,\"schemaVersion\":2",
            1,
        );
        assert!(validate_enum_authority_json(&duplicated, None).is_err());
        assert!(
            validate_enum_authority_json(&" ".repeat(MAX_PRIVATE_AUTHORITY_BYTES + 1), None)
                .is_err()
        );
    }

    #[tokio::test]
    async fn maximum_escaped_text_and_explanation_fit_compact_without_expanded_v1_admission() {
        let owner = oracle(MemoryStorage::new());
        let outcomes: Vec<String> = (0..8).map(|n| format!("{n}{}", "x".repeat(190))).collect();
        let ann = owner
            .create_enum_event_with_nonce(
                "capacity".into(),
                outcomes.clone(),
                1,
                SecretKey::from_slice(&[2; 32]).unwrap(),
            )
            .await
            .unwrap();
        let parent = EventBuilder::new(Kind::Custom(88), BASE64.encode(ann.encode()))
            .tags([
                Tag::parse(["title", &"\u{0001}".repeat(200)]).unwrap(),
                Tag::parse(["description", &"\u{0001}".repeat(2000)]).unwrap(),
            ])
            .sign_with_keys(&owner.nostr_keys())
            .unwrap();
        let att = owner
            .sign_enum_event("capacity".into(), outcomes[0].clone())
            .await
            .unwrap();
        let att_event = EventBuilder::new(Kind::Custom(89), BASE64.encode(att.encode()))
            .tag(Tag::event(parent.id))
            .sign_with_keys(&owner.nostr_keys())
            .unwrap();
        let mut tlv = Vec::new();
        ddk_messages::ser_impls::write_as_tlv(&ann, &mut tlv).unwrap();
        let mut dto = PrivateEnumAuthority {
            schema_version: 1,
            announcement_tlv_hex: hex::encode(tlv),
            announcement_event_json: parent.as_json(),
            nonce_scalar_hex: Some("02".repeat(32)),
            signed_outcome: Some(outcomes[0].clone()),
            attestation_hex: Some(hex::encode(att.encode())),
            attestation_event_json: Some(att_event.as_json()),
            publication_record_json: None,
        };
        let summary = validate_authority_model(&dto, None).unwrap().summary;
        dto.publication_record_json = Some(publication(
            &dto,
            &summary,
            Some(explanation(&owner, &dto, "\u{0001}".repeat(4096))),
            false,
        ));
        assert!(serde_json::to_vec(&dto).unwrap().len() > MAX_PRIVATE_AUTHORITY_BYTES);
        assert!(encode_enum_authority_json(&dto, None, 1).is_err());
        let compact = encode_enum_authority_json(&dto, None, 2).unwrap();
        assert!(compact.len() < MAX_PRIVATE_AUTHORITY_BYTES);
        let decoded = decode_enum_authority_json(&compact, None).unwrap();
        assert_eq!(decoded.announcement_event_json, dto.announcement_event_json);
        assert_eq!(decoded.attestation_event_json, dto.attestation_event_json);
        assert!(serde_json::to_vec(&decoded).unwrap().len() > MAX_PRIVATE_AUTHORITY_BYTES);
        let validated =
            validate_enum_authority_json(&compact, Some(&owner.public_key().to_string())).unwrap();
        let restored = oracle(MemoryStorage::new());
        restored.merge_enum_authority(validated.data).await.unwrap();
        assert!(restored
            .sign_enum_event("capacity".into(), outcomes[1].clone())
            .await
            .is_err());
        assert_eq!(
            restored
                .storage
                .get_event("capacity".into())
                .await
                .unwrap()
                .unwrap()
                .attestation()
                .unwrap()
                .encode(),
            att.encode()
        );
    }

    #[tokio::test]
    async fn compact_import_preserves_existing_journal_bytes_but_rejects_changed_artifacts() {
        let (_, mut dto) = fixture(true).await;
        let summary = validate_enum_authority(&dto, None).unwrap().summary;
        let progress = publication(&dto, &summary, None, false);
        let value: serde_json::Value = serde_json::from_str(&progress).unwrap();
        let original = serde_json::to_string_pretty(&value).unwrap();
        dto.publication_record_json = Some(original.clone());
        let restored = oracle(MemoryStorage::new());
        restored
            .merge_enum_authority(validate_enum_authority(&dto, None).unwrap().data)
            .await
            .unwrap();
        let compact = encode_enum_authority_json(&dto, None, 2).unwrap();
        let incoming = validate_enum_authority_json(&compact, None).unwrap();
        assert_ne!(
            incoming
                .data
                .private_authority
                .staged_publication_json
                .as_ref()
                .unwrap(),
            &original
        );
        let merged = restored.merge_enum_authority(incoming.data).await.unwrap();
        assert_eq!(
            merged
                .private_authority
                .staged_publication_json
                .as_ref()
                .unwrap(),
            &original
        );
        let mut changed = decode_enum_authority_json(&compact, None).unwrap();
        changed.attestation_event_json =
            Some(format!(" {}", changed.attestation_event_json.unwrap()));
        let mut stage: serde_json::Value =
            serde_json::from_str(changed.publication_record_json.as_ref().unwrap()).unwrap();
        stage["attestation"]["eventJson"] = serde_json::json!(changed.attestation_event_json);
        changed.publication_record_json = Some(stage.to_string());
        let changed = encode_enum_authority_json(&changed, None, 2).unwrap();
        assert!(restored
            .merge_enum_authority(validate_enum_authority_json(&changed, None).unwrap().data)
            .await
            .is_err());
        assert!(restored
            .acknowledge_enum_publication("private-event".into(), &progress)
            .await
            .is_err());
        restored
            .acknowledge_enum_publication("private-event".into(), &original)
            .await
            .unwrap();
    }
}
