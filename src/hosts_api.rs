// Shared mail-hosts database on the EPP server.
// Autoconfig cache (IMAP/POP3/SMTP hostnames per domain) is authoritative on
// the server; this module reads it and pushes local discoveries back so every
// client benefits. Fully off when the setting is disabled in RunCfg.

use crate::{epp_api, Hosts};
use serde::Deserialize;
use std::time::Duration;

fn client(timeout: Duration) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_default()
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    imap: Vec<String>,
    #[serde(default)]
    pop3: Vec<String>,
    #[serde(default)]
    smtp: Vec<String>,
}

/// Blocking lookup for a domain. Returns `None` on any failure or empty match.
pub fn fetch(domain: &str, timeout: Duration) -> Option<Hosts> {
    let url = format!("{}/api/v1/mail-hosts/{}", epp_api::base_url(), domain);
    let resp = client(timeout).get(url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let p: Payload = resp.json().ok()?;
    if p.imap.is_empty() && p.pop3.is_empty() && p.smtp.is_empty() {
        return None;
    }
    Some(Hosts {
        imap: p.imap,
        pop3: p.pop3,
        smtp: p.smtp,
    })
}

/// Fire-and-forget submit of newly-learned hosts. No-op without a saved
/// EPP token. Server merges into the existing entry.
pub fn submit(domain: String, hosts: Hosts) {
    if hosts.imap.is_empty() && hosts.pop3.is_empty() && hosts.smtp.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let Some(tok) = epp_api::load_token() else {
            return;
        };
        let url = format!("{}/api/v1/mail-hosts", epp_api::base_url());
        let _ = client(Duration::from_secs(4))
            .post(url)
            .bearer_auth(&tok.token)
            .json(&serde_json::json!({
                "domain": domain,
                "imap": hosts.imap,
                "pop3": hosts.pop3,
                "smtp": hosts.smtp,
            }))
            .send();
    });
}
