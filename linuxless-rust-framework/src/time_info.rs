use chrono::Utc;
use chrono_tz::Tz;
use tracing::info;

/// Demonstrates `chrono-tz` so scheduling does not depend on `/usr/share/zoneinfo` in scratch.
pub fn log_sample_timezone() {
    let utc = Utc::now();
    let tz: Tz = "America/Chicago".parse().unwrap_or(chrono_tz::UTC);
    let local = utc.with_timezone(&tz);
    info!(%utc, %local, "sample time (chrono + chrono-tz)");
}
