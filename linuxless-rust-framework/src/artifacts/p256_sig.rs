use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use super::envelope::{ArtifactVerifyError, Envelope, ENVELOPE_FORMAT, SIG_ALG_P256};

/// Verifies at least one **ECDSA P-256 SHA-256** DER signature over the canonical payload JSON.
pub fn verify_envelope_pem(
    envelope_json: &str,
    public_key_pem: &str,
) -> Result<(), ArtifactVerifyError> {
    let env: Envelope = serde_json::from_str(envelope_json)?;
    if env.format != ENVELOPE_FORMAT {
        return Err(ArtifactVerifyError::UnsupportedFormat(env.format));
    }

    let vk = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| ArtifactVerifyError::Crypto(e.to_string()))?;

    let msg = env.payload.signing_bytes()?;

    for sig in &env.signatures {
        if sig.algorithm != SIG_ALG_P256 {
            continue;
        }
        let der = B64
            .decode(sig.signature_der_base64.trim())
            .map_err(|e| ArtifactVerifyError::Crypto(e.to_string()))?;
        let signature =
            Signature::from_der(&der).map_err(|e| ArtifactVerifyError::Crypto(e.to_string()))?;
        if vk.verify(&msg, &signature).is_ok() {
            return Ok(());
        }
    }

    Err(ArtifactVerifyError::NoValidSignature)
}

use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

/// Signs canonical payload bytes with a PKCS#8 PEM **EC private key** (P-256).
pub fn sign_payload_pem_pkcs8(
    mut payload: super::envelope::ArtifactPayload,
    secret_key_pem: &str,
    public_key_id: Option<String>,
) -> Result<Envelope, ArtifactVerifyError> {
    payload.sort_artifacts();
    let msg = payload.signing_bytes()?;

    let sk = SigningKey::from_pkcs8_pem(secret_key_pem)
        .map_err(|e| ArtifactVerifyError::Crypto(e.to_string()))?;
    let sig: Signature = sk.sign(&msg);
    let der = sig.to_der();
    let b64 = B64.encode(der.as_bytes());

    Ok(Envelope {
        format: ENVELOPE_FORMAT.to_string(),
        payload,
        signatures: vec![super::envelope::SignatureRecord {
            algorithm: SIG_ALG_P256.to_string(),
            public_key_id,
            signature_der_base64: b64,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rand_core::OsRng;

    use super::super::envelope::{ArtifactEntry, ArtifactKind, ArtifactPayload};

    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let sk = SigningKey::random(&mut OsRng);
        let sk_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let vk = *sk.verifying_key();
        let vk_pem = vk.to_public_key_pem(LineEnding::LF).unwrap().to_string();

        let payload = ArtifactPayload {
            manifest_version: 1,
            artifacts: vec![ArtifactEntry {
                name: "demo.wasm".into(),
                kind: ArtifactKind::Wasm,
                sha256: "0".repeat(64),
                path: None,
            }],
            image_trust: None,
        };

        let env = sign_payload_pem_pkcs8(payload, &sk_pem, Some("test-key".into())).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        verify_envelope_pem(&json, &vk_pem).unwrap();
    }
}
