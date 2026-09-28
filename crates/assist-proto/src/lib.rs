//! Wire types shared by the broker, the agent and the viewer.
//!
//! - [`Signal`]: messages over the broker's WebSocket — WebRTC offer/answer
//!   exchange plus the events the agent reports for the audit log.
//! - [`Control`]: messages over the WebRTC data channel, peer to peer, between
//!   the technician's browser and the agent.
//! - [`Grant`]: what the broker allows a technician to do in one session,
//!   Ed25519-signed by the broker so the agent can check it without trusting
//!   the signaling path.

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Messages relayed by the broker. JSON, tagged by `type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Signal {
    /// Viewer → broker → agent. The viewer sends the SDP; the broker attaches
    /// the grant it minted for this viewer before relaying.
    Offer {
        sdp: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<String>,
    },
    /// Agent → broker → viewer.
    Answer { sdp: String },
    /// Agent → broker → viewer: the person at the computer said no, or the
    /// grant did not verify. Broker → viewer: no agent is connected.
    Rejected { reason: String },
    /// Agent → broker: something the audit log should record.
    Event { name: String, detail: String },
    /// Broker → either side: the other side went away.
    PeerLeft,
}

/// Messages over the data channel. JSON, tagged by `type`.
///
/// Coordinates are normalised to `0.0..=1.0` of the shared screen, so the
/// viewer never needs to know the agent's resolution or scaling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// Viewer → agent: ask to move from viewing to controlling (step-up).
    RequestControl,
    /// Agent → viewer: the person at the computer approved control.
    ControlGranted,
    /// Agent → viewer: the person declined, or the grant does not allow it.
    ControlDenied {
        reason: String,
    },
    /// Agent → viewer: control was withdrawn at the computer.
    ControlRevoked,
    MouseMove {
        x: f64,
        y: f64,
    },
    MouseButton {
        button: MouseButton,
        down: bool,
        x: f64,
        y: f64,
    },
    Wheel {
        dx: f64,
        dy: f64,
    },
    /// `key` is a DOM `KeyboardEvent.key` value ("a", "Enter", "ArrowUp", …).
    Key {
        key: String,
        down: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

/// The most a technician may do in a session. The person at the computer can
/// always allow less than this, never more.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    View,
    Control,
}

/// A session grant: signed by the broker, checked by the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub session_id: String,
    /// The support code the agent registered with; binds the grant to it.
    pub code: String,
    /// Who is connecting, as the broker authenticated them.
    pub technician: String,
    pub max_scope: Scope,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Domain separation: these signed bytes are a CyberDoc Assist grant and
/// nothing else, so a signature can never be replayed as another message type.
const GRANT_DOMAIN: &[u8] = b"cyberdoc.assist.grant.v1\0";

/// The signature scheme's `alg` label carried in [`PublicKey`].
pub const GRANT_ALG: &str = "Ed25519";

#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("grant is malformed")]
    Malformed,
    #[error("grant signature does not verify")]
    BadSignature,
    #[error("grant was issued for another session")]
    WrongSession,
    #[error("grant has expired")]
    Expired,
}

fn signed_bytes(payload: &[u8]) -> Vec<u8> {
    [GRANT_DOMAIN, payload].concat()
}

/// `base64url(json) "." base64url(Ed25519 signature)`.
pub fn sign_grant(grant: &Grant, key: &SigningKey) -> Result<String, GrantError> {
    let payload = serde_json::to_vec(grant).map_err(|_| GrantError::Malformed)?;
    let signature: Signature = key.sign(&signed_bytes(&payload));
    Ok(format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(&payload),
        Base64UrlUnpadded::encode_string(&signature.to_bytes())
    ))
}

/// Checks the signature, that the grant is for `code`, and that it is current.
pub fn verify_grant(
    token: &str,
    key: &VerifyingKey,
    code: &str,
    now: u64,
) -> Result<Grant, GrantError> {
    let (payload, signature) = token.split_once('.').ok_or(GrantError::Malformed)?;
    let payload = Base64UrlUnpadded::decode_vec(payload).map_err(|_| GrantError::Malformed)?;
    let sig_bytes = Base64UrlUnpadded::decode_vec(signature).map_err(|_| GrantError::Malformed)?;
    let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| GrantError::Malformed)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&signed_bytes(&payload), &signature)
        .map_err(|_| GrantError::BadSignature)?;
    let grant: Grant = serde_json::from_slice(&payload).map_err(|_| GrantError::Malformed)?;
    if grant.code != code {
        return Err(GrantError::WrongSession);
    }
    if now >= grant.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(grant)
}

/// The broker's public key as served at `GET /api/key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Signature algorithm label; always [`GRANT_ALG`].
    pub alg: String,
    /// base64url of the 32-byte Ed25519 public key.
    pub key: String,
}

impl PublicKey {
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self {
            alg: GRANT_ALG.to_owned(),
            key: Base64UrlUnpadded::encode_string(key.as_bytes()),
        }
    }

    pub fn to_verifying_key(&self) -> Option<VerifyingKey> {
        if self.alg != GRANT_ALG {
            return None;
        }
        let bytes = Base64UrlUnpadded::decode_vec(&self.key).ok()?;
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        VerifyingKey::from_bytes(&bytes).ok()
    }
}

/// Returned by `POST /api/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSession {
    pub session_id: String,
    /// The 9-digit code the person reads to the technician.
    pub code: String,
    /// Proves to the broker that a WebSocket is this session's agent.
    pub agent_secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        // Deterministic key so tests need no RNG.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn grant(expires_at: u64) -> Grant {
        Grant {
            session_id: "s1".into(),
            code: "123456789".into(),
            technician: "tech@cintelis.ai".into(),
            max_scope: Scope::Control,
            issued_at: 100,
            expires_at,
        }
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let token = sign_grant(&grant(200), &key).unwrap();
        let back = verify_grant(&token, &key.verifying_key(), "123456789", 150).unwrap();
        assert_eq!(back, grant(200));
    }

    #[test]
    fn refuses_other_code_expiry_and_tampering() {
        let key = test_key();
        let token = sign_grant(&grant(200), &key).unwrap();
        let vk = key.verifying_key();
        assert!(matches!(
            verify_grant(&token, &vk, "999999999", 150),
            Err(GrantError::WrongSession)
        ));
        assert!(matches!(
            verify_grant(&token, &vk, "123456789", 200),
            Err(GrantError::Expired)
        ));

        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            verify_grant(&token, &other.verifying_key(), "123456789", 150),
            Err(GrantError::BadSignature)
        ));

        // Widen the scope in the payload, keep the old signature.
        let mut widened = grant(200);
        widened.technician = "someone-else".into();
        let forged = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(&widened).unwrap()),
            token.split_once('.').unwrap().1
        );
        assert!(matches!(
            verify_grant(&forged, &vk, "123456789", 150),
            Err(GrantError::BadSignature)
        ));
    }

    #[test]
    fn public_key_round_trip() {
        let key = test_key();
        let wire = PublicKey::from_verifying_key(&key.verifying_key());
        assert_eq!(wire.alg, GRANT_ALG);
        let back = wire.to_verifying_key().unwrap();
        assert_eq!(back.as_bytes(), key.verifying_key().as_bytes());
    }

    #[test]
    fn signal_json_shape() {
        let json = serde_json::to_string(&Signal::Answer { sdp: "v=0".into() }).unwrap();
        assert_eq!(json, r#"{"type":"answer","sdp":"v=0"}"#);
        let c: Control =
            serde_json::from_str(r#"{"type":"key","key":"Enter","down":true}"#).unwrap();
        assert_eq!(
            c,
            Control::Key {
                key: "Enter".into(),
                down: true
            }
        );
    }
}
