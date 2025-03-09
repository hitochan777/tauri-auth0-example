mod auth_service;
use tauri::{command, Emitter, Window};

#[command]
async fn authenticate(window: Window) -> Result<(), String> {
    auth_service::authenticate()
        .await
        .and_then(|token| {
            window.emit("token", token.secret()).unwrap();
            Ok(())
        })
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_oauth::init())
        .invoke_handler(tauri::generate_handler![authenticate])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
