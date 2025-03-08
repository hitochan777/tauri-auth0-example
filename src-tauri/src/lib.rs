mod auth_service;
use tauri::{command, Emitter, Window};
use tauri_plugin_oauth::start;

#[command]
async fn authenticate(window: Window) -> Result<(), String> {
    let redirect_url = "http://localhost:1420/callback".to_string();
    let oauth_service = auth_service::OAuthService::new(redirect_url.into());
    oauth_service
        .authenticate(window)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_oauth::init())
        .invoke_handler(tauri::generate_handler![start_server])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
