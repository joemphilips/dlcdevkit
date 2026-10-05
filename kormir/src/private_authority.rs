//! Per-event private authority. This module does not allocate imported nonces.
use crate::{
    error::Error,
    storage::{EnumNonceAuthority, OracleEventData, Storage},
    EventDescriptor, Oracle, OracleAnnouncement, OracleAttestation, Writeable,
};
use bitcoin::secp256k1::SecretKey;
use std::str::FromStr;

impl<S: Storage> Oracle<S> {
    pub fn validate_enum_authority(&self, data: &OracleEventData) -> Result<(), Error> {
        let ann = &data.announcement;
        ann.validate(&self.secp)
            .map_err(|_| Error::InvalidAnnouncement)?;
        if ann.oracle_public_key != self.public_key()
            || data.event_id != ann.oracle_event.event_id
            || ann.oracle_event.oracle_nonces.len() != 1
        {
            return Err(Error::InvalidAnnouncement);
        }
        let EventDescriptor::EnumEvent(descriptor) = &ann.oracle_event.event_descriptor else {
            return Err(Error::InvalidEventDescriptor);
        };
        if let Some(choice) = &data.private_authority.choice {
            if !descriptor.outcomes.contains(choice) {
                return Err(Error::InvalidOutcome);
            }
        }
        match self.enum_nonce(data)? {
            Some(nonce)
                if nonce.x_only_public_key(&self.secp).0 != ann.oracle_event.oracle_nonces[0] =>
            {
                return Err(Error::InvalidNonces)
            }
            None if data.signatures.is_empty() => return Err(Error::InvalidNonces),
            _ => {}
        }
        if let Some(attestation) = data.attestation() {
            attestation
                .validate(&self.secp, ann)
                .map_err(|_| Error::InvalidAnnouncement)?;
            if data.signatures.len() != 1
                || data
                    .private_authority
                    .choice
                    .as_ref()
                    .is_some_and(|choice| choice != &data.signatures[0].0)
            {
                return Err(Error::EventAlreadySigned);
            }
        }
        Ok(())
    }

    fn enum_nonce(&self, data: &OracleEventData) -> Result<Option<SecretKey>, Error> {
        match &data.private_authority.nonce {
            EnumNonceAuthority::Legacy => {
                if data.indexes.len() != 1 || data.indexes[0] >= (1 << 31) {
                    return Err(Error::InvalidNonces);
                }
                Ok(Some(self.get_nonce_key(data.indexes[0])))
            }
            EnumNonceAuthority::Explicit { scalar } => {
                if !data.indexes.is_empty() {
                    return Err(Error::InvalidNonces);
                }
                Ok(Some(
                    SecretKey::from_str(scalar).map_err(|_| Error::InvalidNonces)?,
                ))
            }
            EnumNonceAuthority::Terminal => {
                if !data.indexes.is_empty() {
                    return Err(Error::InvalidNonces);
                }
                Ok(None)
            }
        }
    }

    /// Export an existing legacy index directly; never scan or export allocator state.
    pub async fn export_enum_nonce(&self, event_id: String) -> Result<Option<SecretKey>, Error> {
        let data = self
            .storage
            .get_event(event_id)
            .await?
            .ok_or(Error::NotFound)?;
        self.validate_enum_authority(&data)?;
        self.enum_nonce(&data)
    }

    /// Insert explicit authority, or merge it with identical retained authority.
    pub async fn merge_enum_authority(
        &self,
        incoming: OracleEventData,
    ) -> Result<OracleEventData, Error> {
        self.validate_enum_authority(&incoming)?;
        for _ in 0..16 {
            let current = self.storage.get_event(incoming.event_id.clone()).await?;
            let mut next = incoming.clone();
            if let Some(old) = &current {
                self.validate_enum_authority(old)?;
                if old.announcement.encode() != incoming.announcement.encode() {
                    return Err(Error::InvalidAnnouncement);
                }
                if matches!(old.private_authority.nonce, EnumNonceAuthority::Terminal)
                    && !matches!(
                        incoming.private_authority.nonce,
                        EnumNonceAuthority::Terminal
                    )
                {
                    return Err(Error::InvalidNonces);
                }
                if let (Some(a), Some(b)) = (self.enum_nonce(old)?, self.enum_nonce(&incoming)?) {
                    if a != b {
                        return Err(Error::InvalidNonces);
                    }
                }
                if !old.signatures.is_empty() {
                    if !incoming.signatures.is_empty() && old.signatures != incoming.signatures {
                        return Err(Error::EventAlreadySigned);
                    }
                    next.signatures = old.signatures.clone();
                }
                merge_option(
                    &mut next.private_authority.choice,
                    &old.private_authority.choice,
                )?;
                #[cfg(feature = "nostr")]
                {
                    merge_option(&mut next.announcement_event_id, &old.announcement_event_id)?;
                    merge_option(&mut next.attestation_event_id, &old.attestation_event_id)?;
                }
                merge_option(
                    &mut next.private_authority.announcement_event_json,
                    &old.private_authority.announcement_event_json,
                )?;
                merge_option(
                    &mut next.private_authority.attestation_event_json,
                    &old.private_authority.attestation_event_json,
                )?;
                merge_option(
                    &mut next.private_authority.staged_publication_json,
                    &old.private_authority.staged_publication_json,
                )?;
            }
            if let Some((choice, _)) = next.signatures.first() {
                merge_option(&mut next.private_authority.choice, &Some(choice.clone()))?;
            }
            self.validate_enum_authority(&next)?;
            if self
                .storage
                .compare_exchange_event(current, next.clone())
                .await?
            {
                return Ok(next);
            }
        }
        Err(Error::StorageFailure)
    }

    pub async fn create_enum_event_with_nonce(
        &self,
        event_id: String,
        outcomes: Vec<String>,
        maturity: u32,
        nonce: SecretKey,
    ) -> Result<OracleAnnouncement, Error> {
        let announcement = crate::create_enum_event(
            &self.secp,
            &self.key_pair,
            &event_id,
            &outcomes,
            maturity,
            &nonce.x_only_public_key(&self.secp).0,
        )?;
        let data = OracleEventData {
            event_id,
            announcement: announcement.clone(),
            indexes: vec![],
            signatures: vec![],
            private_authority: crate::storage::EnumPrivateAuthority {
                nonce: EnumNonceAuthority::Explicit {
                    scalar: hex::encode(nonce.secret_bytes()),
                },
                ..Default::default()
            },
            #[cfg(feature = "nostr")]
            announcement_event_id: None,
            #[cfg(feature = "nostr")]
            attestation_event_id: None,
        };
        self.merge_enum_authority(data).await?;
        Ok(announcement)
    }

    pub(crate) async fn sign_retained_enum(
        &self,
        event_id: String,
        outcome: String,
    ) -> Result<OracleAttestation, Error> {
        let mut data = self
            .storage
            .get_event(event_id)
            .await?
            .ok_or(Error::NotFound)?;
        if !data.signatures.is_empty() {
            return Err(Error::EventAlreadySigned);
        }
        self.validate_enum_authority(&data)?;
        if matches!(data.private_authority.nonce, EnumNonceAuthority::Terminal) {
            return Err(Error::InvalidNonces);
        }
        merge_option(&mut data.private_authority.choice, &Some(outcome.clone()))?;
        let reserved = self.merge_enum_authority(data).await?;
        if !reserved.signatures.is_empty() {
            return Err(Error::EventAlreadySigned);
        }
        let nonce = self.enum_nonce(&reserved)?.ok_or(Error::InvalidNonces)?;
        let attestation = crate::sign_enum_event(
            &self.secp,
            &self.key_pair,
            &reserved.announcement,
            &outcome,
            &nonce,
        )?;
        let mut signed = reserved;
        signed.signatures = vec![(outcome, attestation.signatures[0])];
        self.merge_enum_authority(signed).await?;
        Ok(attestation)
    }

    pub async fn acknowledge_enum_publication(
        &self,
        event_id: String,
        exact: &str,
    ) -> Result<(), Error> {
        for _ in 0..16 {
            let old = self
                .storage
                .get_event(event_id.clone())
                .await?
                .ok_or(Error::NotFound)?;
            match old.private_authority.staged_publication_json.as_deref() {
                None => return Ok(()),
                Some(value) if value == exact => {}
                Some(_) => return Err(Error::InvalidAnnouncement),
            }
            let mut next = old.clone();
            next.private_authority.staged_publication_json = None;
            if self.storage.compare_exchange_event(Some(old), next).await? {
                return Ok(());
            }
        }
        Err(Error::StorageFailure)
    }
}

fn merge_option<T: Clone + PartialEq>(
    incoming: &mut Option<T>,
    old: &Option<T>,
) -> Result<(), Error> {
    match (&incoming, old) {
        (Some(a), Some(b)) if a != b => Err(Error::EventAlreadySigned),
        (None, Some(value)) => {
            *incoming = Some(value.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}
