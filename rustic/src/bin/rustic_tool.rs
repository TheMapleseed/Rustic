//! **rustic-tool** — ECDSA image-trust CLI: `sign`, `verify`, `sha256`, `keygen`.
//! `cargo build --release --features rustic-tool --bin rustic-tool`

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use rustic::artifacts::{ArtifactPayload, sign_payload_pem_pkcs8, verify_envelope_pem};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "rustic-tool")]
#[command(about = "Rustic ECDSA P-256 image-trust envelopes: sign, verify, sha256, keygen")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
