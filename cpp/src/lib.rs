mod account;
mod sas;
mod session;
mod types;

use account::{new_account, Account, InboundCreationResult, OlmMessage};
use sas::{new_sas, EstablishedSas, Mac, Sas, SasBytes};
use session::Session;
use types::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

#[cxx::bridge]
mod ffi {
    #[namespace = "olm"]
    struct OlmMessageParts {
        message_type: usize,
        ciphertext: String,
    }

    #[namespace = "olm"]
    struct OneTimeKey {
        key_id: String,
        key: Box<Curve25519PublicKey>,
    }

    #[namespace = "olm"]
    struct SessionKeys {
        identity_key: Box<Curve25519PublicKey>,
        base_key: Box<Curve25519PublicKey>,
        one_time_key: Box<Curve25519PublicKey>,
    }

    #[namespace = "types"]
    extern "Rust" {
        type Curve25519PublicKey;
        type Ed25519PublicKey;
        type Ed25519Signature;
    }

    #[namespace = "olm"]
    extern "Rust" {
        type Account;
        type InboundCreationResult;
        fn new_account() -> Box<Account>;
        fn ed25519_key(self: &Account) -> Box<Ed25519PublicKey>;
        fn curve25519_key(self: &Account) -> Box<Curve25519PublicKey>;
        fn sign(self: &Account, message: &str) -> Box<Ed25519Signature>;
        fn generate_one_time_keys(self: &mut Account, count: usize);
        fn one_time_keys(self: &Account) -> Vec<OneTimeKey>;
        fn generate_fallback_key(self: &mut Account);
        fn fallback_key(self: &Account) -> Vec<OneTimeKey>;
        fn mark_keys_as_published(self: &mut Account);
        fn create_outbound_session(
            self: &Account,
            identity_key: &Curve25519PublicKey,
            one_time_key: &Curve25519PublicKey,
        ) -> Result<Box<Session>>;
        fn create_inbound_session(
            self: &mut Account,
            identity_key: &Curve25519PublicKey,
            message: &OlmMessage,
        ) -> Result<Box<InboundCreationResult>>;

        type Session;
        fn session_id(self: &Session) -> String;
        fn encrypt(self: &mut Session, plaintext: &str) -> Box<OlmMessage>;
        fn decrypt(self: &mut Session, message: &OlmMessage) -> Result<String>;

        type OlmMessage;
    }

    #[namespace = "sas"]
    extern "Rust" {
        type Mac;
        type Sas;
        fn new_sas() -> Box<Sas>;
        fn public_key(self: &Sas) -> Box<Curve25519PublicKey>;
        fn diffie_hellman(
            self: &mut Sas,
            other_public_key: &Curve25519PublicKey,
        ) -> Result<Box<EstablishedSas>>;

        type EstablishedSas;
        fn bytes(self: &EstablishedSas, info: &str) -> Box<SasBytes>;
        fn calculate_mac(self: &EstablishedSas, input: &str, info: &str) -> Box<Mac>;
        fn verify_mac(self: &EstablishedSas, input: &str, info: &str, mac: &Mac) -> Result<()>;

        type SasBytes;
        fn emoji_indices(self: &SasBytes) -> [u8; 7];
        fn decimals(self: &SasBytes) -> [u16; 3];
    }
}
