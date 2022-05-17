use super::{ffi::OneTimeKey, Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature, Session};

pub struct OlmMessage(pub(crate) vodozemac::olm::OlmMessage);

pub struct Account(vodozemac::olm::Account);

pub fn new_account() -> Box<Account> {
    Account(vodozemac::olm::Account::new()).into()
}

pub struct InboundCreationResult {
    pub session: Session,
    pub plaintext: String,
}

impl From<vodozemac::olm::InboundCreationResult> for InboundCreationResult {
    fn from(v: vodozemac::olm::InboundCreationResult) -> Self {
        Self {
            session: Session { inner: v.session },
            plaintext: v.plaintext,
        }
    }
}

impl Account {
    pub fn ed25519_key(&self) -> Box<Ed25519PublicKey> {
        Ed25519PublicKey(self.0.ed25519_key()).into()
    }

    pub fn curve25519_key(&self) -> Box<Curve25519PublicKey> {
        Curve25519PublicKey(*self.0.curve25519_key()).into()
    }

    pub fn sign(&self, message: &str) -> Box<Ed25519Signature> {
        Ed25519Signature(self.0.sign(message)).into()
    }

    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.0.generate_one_time_keys(count)
    }

    pub fn one_time_keys(&self) -> Vec<OneTimeKey> {
        self.0
            .one_time_keys()
            .into_iter()
            .map(|(key_id, key)| OneTimeKey {
                key_id: key_id.to_base64(),
                key: Box::new(Curve25519PublicKey(key)),
            })
            .collect()
    }

    pub fn generate_fallback_key(&mut self) {
        self.0.generate_fallback_key()
    }

    pub fn fallback_key(&self) -> Vec<OneTimeKey> {
        self.0
            .fallback_key()
            .into_iter()
            .map(|(key_id, key)| OneTimeKey {
                key_id: key_id.to_base64(),
                key: Box::new(Curve25519PublicKey(key)),
            })
            .collect()
    }

    pub fn mark_keys_as_published(&mut self) {
        self.0.mark_keys_as_published()
    }

    pub fn create_outbound_session(
        &self,
        identity_key: &Curve25519PublicKey,
        one_time_key: &Curve25519PublicKey,
    ) -> Result<Box<Session>, vodozemac::KeyError> {
        let session = self
            .0
            .create_outbound_session(identity_key.0, one_time_key.0);

        Ok(Box::new(Session { inner: session }))
    }

    pub fn create_inbound_session(
        &mut self,
        identity_key: &Curve25519PublicKey,
        message: &OlmMessage,
    ) -> Result<Box<InboundCreationResult>, anyhow::Error> {
        if let vodozemac::olm::OlmMessage::PreKey(m) = &message.0 {
            let result = self.0.create_inbound_session(&identity_key.0, &m)?;

            Ok(Box::new(result.into()))
        } else {
            anyhow::bail!("Invalid message type, a pre-key message is required")
        }
    }
}
