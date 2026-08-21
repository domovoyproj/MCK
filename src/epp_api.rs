use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

pub const PRODUCT_SLUG: &str = "mailcheck";

pub fn base_url() -> String {
    std::env::var("EPP_BASE").unwrap_or_else(|_| "https://domovoy1337.online".into())
}

pub fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default()
}

fn epp_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "epp", "epp")
}

fn launcher_token_path() -> Option<PathBuf> {
    let d = epp_dirs()?;
    Some(d.config_dir().join("token.json"))
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct SavedToken {
    pub token: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LicenseStatus {
    pub active: bool,
    pub email: String,
    pub hwid: String,
    pub error: Option<String>,
}

static CURRENT_STATUS: RwLock<Option<LicenseStatus>> = RwLock::new(None);

pub fn hwid() -> String {
    let raw = machine_uid::get().unwrap_or_else(|_| "unknown-machine".into());
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

pub fn load_token() -> Option<SavedToken> {
    if let Ok(tok) = std::env::var("EPP_TOKEN") {
        if !tok.trim().is_empty() {
            return Some(SavedToken {
                token: tok.trim().to_string(),
                email: "EPP User".into(),
            });
        }
    }
    if let Some(path) = launcher_token_path() {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(st) = serde_json::from_str::<SavedToken>(&s) {
                if !st.token.is_empty() {
                    return Some(st);
                }
            }
        }
    }
    None
}

pub fn save_token(st: &SavedToken) {
    if let Some(dirs) = epp_dirs() {
        let _ = std::fs::create_dir_all(dirs.config_dir());
        if let Ok(js) = serde_json::to_string(st) {
            let _ = std::fs::write(dirs.config_dir().join("token.json"), js);
        }
    }
}

pub fn clear_token() {
    if let Some(path) = launcher_token_path() {
        let _ = std::fs::remove_file(path);
    }
}

pub fn verify_license() -> LicenseStatus {
    let machine_hwid = hwid();
    let Some(saved) = load_token() else {
        let st = LicenseStatus {
            active: false,
            email: String::new(),
            hwid: machine_hwid,
            error: Some("Требуется авторизация в аккаунте EPP".into()),
        };
        if let Ok(mut g) = CURRENT_STATUS.write() {
            *g = Some(st.clone());
        }
        return st;
    };

    let c = client();
    let url = format!("{}/api/v1/license/verify", base_url());
    let res = c.post(&url)
        .bearer_auth(&saved.token)
        .json(&serde_json::json!({
            "product_slug": PRODUCT_SLUG,
            "hwid": machine_hwid,
        }))
        .send();

    match res {
        Ok(resp) => {
            if resp.status().as_u16() == 401 {
                let st = LicenseStatus {
                    active: false,
                    email: saved.email,
                    hwid: machine_hwid,
                    error: Some("Сессия истекла. Войдите в аккаунт снова.".into()),
                };
                if let Ok(mut g) = CURRENT_STATUS.write() {
                    *g = Some(st.clone());
                }
                return st;
            }
            if !resp.status().is_success() {
                let st = LicenseStatus {
                    active: false,
                    email: saved.email,
                    hwid: machine_hwid,
                    error: Some(format!("Ошибка сервера лицензий: {}", resp.status())),
                };
                if let Ok(mut g) = CURRENT_STATUS.write() {
                    *g = Some(st.clone());
                }
                return st;
            }
            if let Ok(v) = resp.json::<serde_json::Value>() {
                if v.get("allowed").and_then(|a| a.as_bool()).unwrap_or(false) {
                    let st = LicenseStatus {
                        active: true,
                        email: saved.email,
                        hwid: machine_hwid,
                        error: None,
                    };
                    if let Ok(mut g) = CURRENT_STATUS.write() {
                        *g = Some(st.clone());
                    }
                    return st;
                } else {
                    let reason = v.get("reason").and_then(|r| r.as_str()).unwrap_or("denied");
                    let msg = match reason {
                        "no_subscription" => "Нет активной подписки на Mail Checker на сайте epp.",
                        "expired" => "Срок действия вашей подписки на Mail Checker истек.",
                        "device_limit" => "Лимит устройств исчерпан. Сбросьте HWID в личном кабинете.",
                        "unknown_product" => "Продукт не зарегистрирован в системе EPP.",
                        other => other,
                    };
                    let st = LicenseStatus {
                        active: false,
                        email: saved.email,
                        hwid: machine_hwid,
                        error: Some(msg.to_string()),
                    };
                    if let Ok(mut g) = CURRENT_STATUS.write() {
                        *g = Some(st.clone());
                    }
                    return st;
                }
            }
            let st = LicenseStatus {
                active: false,
                email: saved.email,
                hwid: machine_hwid,
                error: Some("Некорректный ответ сервера лицензирования".into()),
            };
            if let Ok(mut g) = CURRENT_STATUS.write() {
                *g = Some(st.clone());
            }
            st
        }
        Err(e) => {
            let st = LicenseStatus {
                active: false,
                email: saved.email,
                hwid: machine_hwid,
                error: Some(format!("Не удалось подключиться к серверу EPP: {e}")),
            };
            if let Ok(mut g) = CURRENT_STATUS.write() {
                *g = Some(st.clone());
            }
            st
        }
    }
}

pub fn login(email: &str, password: &str) -> Result<LicenseStatus, String> {
    let c = client();
    let url = format!("{}/api/v1/auth/login", base_url());
    let resp = c.post(&url)
        .json(&serde_json::json!({
            "email": email.trim(),
            "password": password,
        }))
        .send()
        .map_err(|e| format!("Ошибка сети: {e}"))?;

    if !resp.status().is_success() {
        return Err("Неверный email или пароль.".into());
    }

    let val: serde_json::Value = resp.json().map_err(|e| format!("Ошибка ответа: {e}"))?;
    let token = val.get("token").and_then(|t| t.as_str()).ok_or("Токен не получен")?;
    let saved = SavedToken {
        token: token.to_string(),
        email: email.trim().to_string(),
    };
    save_token(&saved);
    Ok(verify_license())
}

/// Auto-delete executable and containing app directory if subscription ended or missing, then exit.
pub fn self_destruct() -> ! {
    if let Ok(exe_path) = std::env::current_exe() {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;

            let exe_str = exe_path.to_string_lossy().to_string();
            let parent = exe_path.parent();
            let parent_is_app_dir = parent.map_or(false, |p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                name.eq_ignore_ascii_case("chronos")
                    || name.eq_ignore_ascii_case("xenos")
                    || name.eq_ignore_ascii_case("mailcheck")
                    || p.to_string_lossy().to_lowercase().contains("epp\\data\\apps")
                    || p.to_string_lossy().to_lowercase().contains("epp/data/apps")
            });

            let cmd_line = if parent_is_app_dir {
                if let Some(p) = parent {
                    let parent_str = p.to_string_lossy().to_string();
                    format!(
                        "ping 127.0.0.1 -n 2 > nul & del /f /q \"{}\" & timeout /t 1 /nobreak > nul & rmdir /s /q \"{}\"",
                        exe_str, parent_str
                    )
                } else {
                    format!("ping 127.0.0.1 -n 2 > nul & del /f /q \"{}\"", exe_str)
                }
            } else {
                format!("ping 127.0.0.1 -n 2 > nul & del /f /q \"{}\"", exe_str)
            };

            let _ = std::process::Command::new("cmd.exe")
                .args(["/C", &cmd_line])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
        #[cfg(not(windows))]
        {
            let _ = std::fs::remove_file(&exe_path);
        }
    }
    std::process::exit(1);
}

pub fn get_cached_status() -> LicenseStatus {
    if let Ok(g) = CURRENT_STATUS.read() {
        if let Some(st) = &*g {
            return st.clone();
        }
    }
    verify_license()
}
