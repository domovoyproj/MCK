// Кладёт WebView2Loader.dll рядом с exe (нужна на windows-gnu, где она не линкуется статически).
use std::{env, fs, path::PathBuf};

fn main() {
    let dll = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("WebView2Loader.dll");
    if dll.exists() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        // OUT_DIR = target/<profile>/build/<pkg>/out  →  target/<profile> это 3 уровня вверх
        if let Some(target_dir) = out.ancestors().nth(3) {
            let _ = fs::copy(&dll, target_dir.join("WebView2Loader.dll"));
        }
    }
    println!("cargo:rerun-if-changed=WebView2Loader.dll");
}
