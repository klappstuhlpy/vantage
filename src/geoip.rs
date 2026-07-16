//! IP → geolocation lookups via the MaxMind GeoLite2-City database.
//!
//! The database is optional: if the file is missing or fails to parse, the
//! `GeoIp` wrapper returns `None` for every lookup and the rest of the app
//! carries on without errors. Drop a GeoLite2-City.mmdb file at the path
//! configured by `geoip_path` and the security dashboard will start populating
//! country/city fields.
//!
//! The reader is cheap to clone — it's an `Arc<Reader<Vec<u8>>>` internally,
//! and lookups happen synchronously off the parsed database.

use serde::Serialize;
use std::{net::IpAddr, path::Path, sync::Arc};

/// One geolocated IP record, kept as just enough for the dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoRecord {
    /// Two-letter ISO country code (e.g. "DE", "US"). Empty if unknown.
    pub country_code: String,
    /// Localised country name in English ("Germany").
    pub country: String,
    /// City name ("Berlin"). May be empty even when country is known.
    pub city: String,
}

impl GeoRecord {
    /// True if the lookup returned something meaningful at all.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.country_code.is_empty() && self.city.is_empty()
    }
}

#[derive(Clone, Default)]
pub struct GeoIp {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoIp {
    /// Tries to open the mmdb file. Returns a working `GeoIp` either way:
    /// if the file is missing or invalid, lookups will just return `None`.
    pub fn open(path: Option<&Path>) -> Self {
        let reader = path.and_then(|p| match maxminddb::Reader::open_readfile(p) {
            Ok(r) => {
                tracing::info!(path = %p.display(), "loaded GeoIP database");
                Some(Arc::new(r))
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %p.display(), "could not open GeoIP database; lookups disabled");
                None
            }
        });
        Self { reader }
    }

    pub fn is_enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// Looks up an IP; returns `None` if the DB is missing or the IP isn't in it.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoRecord> {
        let reader = self.reader.as_ref()?;
        let city: maxminddb::geoip2::City = reader.lookup(ip).ok()?;

        let country_code = city.country.as_ref().and_then(|c| c.iso_code).unwrap_or("").to_string();
        let country = city
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .copied()
            .unwrap_or("")
            .to_string();
        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .copied()
            .unwrap_or("")
            .to_string();

        if country_code.is_empty() && city_name.is_empty() {
            return None;
        }

        Some(GeoRecord {
            country_code,
            country,
            city: city_name,
        })
    }

    /// Parses a string IP and looks it up. Convenience for "raw row from DB".
    pub fn lookup_str(&self, ip_str: &str) -> Option<GeoRecord> {
        let ip: IpAddr = ip_str.parse().ok()?;
        self.lookup(ip)
    }
}
