//! **rustic-tool** — image-trust CLI: ECDSA `sign`/`verify`, [KWT](https://github.com/TheMapleseed/KWT) `kwt-sign`, `sha256`, `keygen`.
//! `cargo build --release --features rustic-tool --bin rustic-tool`

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kwt::crypto::MasterKey;
use kwt::token::KwtToken;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use rustic::artifacts::{
    ArtifactPayload, KWT_ATTESTATION_WELL_KNOWN_FORMAT, KwtAttestationWellKnown,
    sign_payload_pem_pkcs8, verify_envelope_pem,
};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "rustic-tool")]
#[command(about = "Rustic image-trust: ECDSA envelopes, KWT attestations, sha256, keygen")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed `ArtifactPayload` JSON in a [KWT](https://github.com/TheMapleseed/KWT) v1 token (XChaCha20-Poly1305 + HKDF).
    KwtSign {
        #[arg(long)]
        payload: PathBuf,
        /// 64 hex chars (32-byte master key); must match `IMAGE_TRUST_KWT_MASTER_KEY` at runtime.
        #[arg(long)]
        master_key_hex: String,
        #[arg(long, default_value = "rustic-manifest")]
        subject: String,
        #[arg(long, default_value = "rustic")]
        audience: String,
        /// Token lifetime in seconds (attestations often use a long TTL).
        #[arg(long, default_value_t = 86400 * 365)]
        ttl_seconds: u32,
        #[arg(long)]
        output: PathBuf,
        /// Write only the `v1....` token (else JSON for `IMAGE_TRUST_ENVELOPE` / well-known shape).
        #[arg(long, default_value_t = false)]
        raw_token_only: bool,
    },
    /// Create a signed envelope JSON from payload JSON + PKCS#8 EC private key PEM.
    Sign {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        public_key_id: Option<String>,
    },
    /// Verify an envelope with a SPKI public key PEM (`BEGIN PUBLIC KEY`).
    Verify {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Print lowercase hex SHA-256 of a file.
    Sha256 {
        #[arg(long)]
        file: PathBuf,
    },
    /// Generate a random P-256 PKCS#8 PEM private key and matching public key PEM.
    Keygen {
        #[arg(long)]
        private_out: PathBuf,
        #[arg(long)]
        public_out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::KwtSign {
            payload,
            master_key_hex,
            subject,
            audience,
            ttl_seconds,
            output,
            raw_token_only,
        } => {
            let body = fs::read_to_string(&payload)?;
            let mut p: ArtifactPayload = serde_json::from_str(&body)?;
            p.sort_artifacts();
            let manifest_json = serde_json::to_string(&p)?;
            let raw = hex::decode(master_key_hex.trim())?;
            let key = MasterKey::from_bytes(&raw)?;
            let mut claims = kwt::codec::new_claims(&subject, &audience, ttl_seconds);
            claims.artifact_manifest_json = Some(manifest_json);
            let token = KwtToken::issue(&claims, &key)?;
            if raw_token_only {
                fs::write(&output, format!("{token}\n"))?;
            } else {
                let well = KwtAttestationWellKnown {
                    format: KWT_ATTESTATION_WELL_KNOWN_FORMAT.to_string(),
                    kwt: token,
                };
                fs::write(&output, serde_json::to_string_pretty(&well)?)?;
            }
            eprintln!("wrote {}", output.display());
        }
        Commands::Sign {
            payload,
            secret_key,
            output,
            public_key_id,
        } => {
            let body = fs::read_to_string(&payload)?;
            let mut p: ArtifactPayload = serde_json::from_str(&body)?;
            p.sort_artifacts();
            let sk_pem = fs::read_to_string(&secret_key)?;
            let env = sign_payload_pem_pkcs8(p, &sk_pem, public_key_id)?;
            fs::write(&output, serde_json::to_string_pretty(&env)?)?;
            eprintln!("wrote {}", output.display());
        }
        Commands::Verify {
            envelope,
            public_key,
        } => {
            let json = fs::read_to_string(&envelope)?;
            let pem = fs::read_to_string(&public_key)?;
            verify_envelope_pem(&json, &pem)?;
            eprintln!("OK: ECDSA P-256 signature verifies");
        }
        Commands::Sha256 { file } => {
            let bytes = fs::read(&file)?;
            println!("{}", hex::encode(Sha256::digest(&bytes)));
        }
        Commands::Keygen {
            private_out,
            public_out,
        } => {
            let sk = SigningKey::random(&mut OsRng);
            let priv_pem = sk.to_pkcs8_pem(LineEnding::LF)?;
            fs::write(&private_out, priv_pem.as_str())?;
            let vk = *sk.verifying_key();
            let pub_pem = vk.to_public_key_pem(LineEnding::LF)?;
            fs::write(&public_out, pub_pem.as_str())?;
            eprintln!(
                "wrote {} and {}",
                private_out.display(),
                public_out.display()
            );
        }
    }
    Ok(())
}
