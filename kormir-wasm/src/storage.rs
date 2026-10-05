use crate::error::JsError;
use gloo_utils::format::JsValueSerdeExt;
use kormir::error::Error;
use kormir::storage::{OracleEventData, Storage};
use kormir::{OracleAnnouncement, Signature};
use rexie::{ObjectStore, Rexie, TransactionMode};
use serde::Serialize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use wasm_bindgen::JsValue;

const DATABASE_NAME: &str = "kormir";
const OBJECT_STORE_NAME: &str = "oracle";
pub const NSEC_KEY: &str = "nsec";
const NONCE_INDEX_KEY: &str = "nonce_index";
const ORACLE_DATA_PREFIX: &str = "oracle_data/";

fn get_oracle_data_key(event_id: String) -> String {
    format!("{ORACLE_DATA_PREFIX}{event_id}")
}

#[derive(Debug, Clone)]
pub struct IndexedDb {
    current_index: Arc<AtomicU32>,
    rexie: Rexie,
}

impl IndexedDb {
    async fn build_indexed_db() -> Result<Rexie, JsError> {
        Ok(Rexie::builder(DATABASE_NAME)
            .version(1)
            .add_object_store(ObjectStore::new(OBJECT_STORE_NAME))
            .build()
            .await?)
    }

    pub async fn new() -> Result<Self, JsError> {
        let rexie = Self::build_indexed_db().await?;
        let tx = rexie.transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;
        let store = tx.store(OBJECT_STORE_NAME)?;
        let js = store.get(&JsValue::from_serde(NONCE_INDEX_KEY)?).await?;
        let index: Option<u32> = js.into_serde()?;
        tx.done().await?;

        Ok(Self {
            current_index: Arc::new(AtomicU32::new(index.unwrap_or(0))),
            rexie,
        })
    }

    pub async fn save_to_indexed_db<K: Serialize, V: Serialize>(
        &self,
        key: K,
        value: V,
    ) -> Result<(), JsError> {
        let tx = self
            .rexie
            .transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;
        let store = tx.store(OBJECT_STORE_NAME)?;
        store
            .put(
                &JsValue::from_serde(&value)?,
                Some(&JsValue::from_serde(&key)?),
            )
            .await?;
        tx.done().await?;
        Ok(())
    }

    pub async fn get_from_indexed_db<K: Serialize, V>(&self, key: K) -> Result<Option<V>, JsError>
    where
        V: for<'a> serde::de::Deserialize<'a>,
    {
        let tx = self
            .rexie
            .transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;
        let store = tx.store(OBJECT_STORE_NAME)?;
        let js = store.get(&JsValue::from_serde(&key)?).await?;
        tx.done().await?;
        Ok(js.into_serde()?)
    }

    pub async fn list_events(&self) -> Result<Vec<(String, OracleEventData)>, JsError> {
        let tx = self
            .rexie
            .transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadOnly)?;
        let store = tx.store(OBJECT_STORE_NAME)?;
        let all = store.get_all(None, None, None, None).await?;
        tx.done().await?;

        let mut vec = Vec::with_capacity(all.len());
        for (key, value) in all {
            let key: String = key.into_serde()?;
            if key.starts_with(ORACLE_DATA_PREFIX) {
                let data: OracleEventData = value.into_serde()?;
                let id = key
                    .strip_prefix(ORACLE_DATA_PREFIX)
                    .expect("prefix checked")
                    .to_string();
                vec.push((id, data));
            }
        }
        Ok(vec)
    }

    /// Reinstalling the same key must not erase retained nonce or signing authority.
    pub async fn restore_signing_key(secret_hex: &str) -> Result<(), JsError> {
        let rexie = Self::build_indexed_db().await?;
        let tx = rexie.transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;
        let store = tx.store(OBJECT_STORE_NAME)?;
        let key = JsValue::from_serde(NSEC_KEY)?;
        let existing: Option<String> = store.get(&key).await?.into_serde()?;
        if !existing
            .as_deref()
            .is_some_and(|current| current.eq_ignore_ascii_case(secret_hex))
        {
            store.clear().await?;
            store
                .put(&JsValue::from_serde(secret_hex)?, Some(&key))
                .await?;
        }
        tx.done().await?;
        Ok(())
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    pub async fn clear() -> Result<(), JsError> {
        let rexie = Self::build_indexed_db().await?;
        let tx = rexie.transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadWrite)?;
        let store = tx.store(OBJECT_STORE_NAME)?;
        store.clear().await?;
        tx.done().await?;
        Ok(())
    }
}

impl Storage for IndexedDb {
    async fn compare_exchange_event(
        &self,
        expected: Option<OracleEventData>,
        next: OracleEventData,
    ) -> Result<bool, Error> {
        let tx = self
            .rexie
            .transaction(&[OBJECT_STORE_NAME], TransactionMode::ReadWrite)
            .map_err(JsError::from)?;
        let store = tx.store(OBJECT_STORE_NAME).map_err(JsError::from)?;
        let key = JsValue::from_serde(&get_oracle_data_key(next.event_id.clone()))
            .map_err(JsError::from)?;
        let current: Option<OracleEventData> = store
            .get(&key)
            .await
            .map_err(JsError::from)?
            .into_serde()
            .map_err(JsError::from)?;
        let matches = match (current.as_ref(), expected.as_ref()) {
            (None, None) => true,
            (Some(current), Some(expected)) => kormir::storage::same_event(current, expected)?,
            _ => false,
        };
        if matches {
            store
                .put(
                    &JsValue::from_serde(&next).map_err(JsError::from)?,
                    Some(&key),
                )
                .await
                .map_err(JsError::from)?;
        }
        tx.done().await.map_err(JsError::from)?;
        Ok(matches)
    }

    async fn get_next_nonce_indexes(&self, num: usize) -> Result<Vec<u32>, Error> {
        let mut current_index = self.current_index.fetch_add(num as u32, Ordering::SeqCst);
        let mut indexes = Vec::with_capacity(num);
        for _ in 0..num {
            indexes.push(current_index);
            current_index += 1;
        }
        self.save_to_indexed_db(NONCE_INDEX_KEY, current_index)
            .await?;
        Ok(indexes)
    }

    async fn save_announcement(
        &self,
        announcement: OracleAnnouncement,
        indexes: Vec<u32>,
    ) -> Result<String, Error> {
        let event = OracleEventData {
            event_id: announcement.oracle_event.event_id.clone(),
            announcement: announcement.clone(),
            indexes,
            private_authority: Default::default(),
            signatures: Default::default(),
            announcement_event_id: None,
            attestation_event_id: None,
        };

        if !self.compare_exchange_event(None, event).await? {
            return Err(Error::InvalidAnnouncement);
        }
        Ok(announcement.oracle_event.event_id.clone())
    }

    async fn save_signatures(
        &self,
        event_id: String,
        sigs: Vec<(String, Signature)>,
    ) -> Result<OracleEventData, Error> {
        let mut event = self
            .get_event(event_id.clone())
            .await?
            .ok_or(Error::NotFound)?;
        if !event.signatures.is_empty() {
            return Err(Error::EventAlreadySigned);
        }

        let previous = event.clone();
        event.signatures = sigs;
        if !self
            .compare_exchange_event(Some(previous), event.clone())
            .await?
        {
            return Err(Error::EventAlreadySigned);
        }
        Ok(event)
    }

    async fn get_event(&self, event_id: String) -> Result<Option<OracleEventData>, Error> {
        Ok(self
            .get_from_indexed_db(get_oracle_data_key(event_id))
            .await?)
    }
}
