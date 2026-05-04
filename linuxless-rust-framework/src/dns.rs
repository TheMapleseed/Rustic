use hickory_resolver::TokioResolver;
use tracing::{info, warn};

/// Pure-Rust DNS path (reads `/etc/resolv.conf` when present; in scratch Docker usually injects it).
pub async fn log_sample_resolution() {
    #[cfg(any(unix, target_os = "windows"))]
    {
        match TokioResolver::builder_tokio() {
            Ok(builder) => {
                let resolver = builder.build();
                match resolver.lookup_ip("example.com.").await {
                    Ok(ips) => info!(?ips, "hickory-resolver lookup example.com"),
                    Err(e) => warn!(%e, "hickory lookup failed (non-fatal)"),
                }
            }
            Err(e) => warn!(
                %e,
                "hickory system config failed; in scratch use explicit ResolverConfig / nameservers"
            ),
        }
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        warn!("hickory system resolver skipped on this target");
    }
}
