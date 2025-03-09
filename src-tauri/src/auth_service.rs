use oauth2::reqwest::async_http_client;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tauri::Window;
use tauri_plugin_oauth::start;
use url::Url;

struct OAuthState {
    csrf_token: CsrfToken,
    pkce: Arc<(PkceCodeChallenge, PkceCodeVerifier)>,
}

#[derive(Deserialize, Debug)]
struct CallbackQuery {
    code: AuthorizationCode,
    state: CsrfToken,
}

fn create_client(redirect_url: RedirectUrl) -> BasicClient {
    let client_id = ClientId::new(env::var("CLIENT_ID").expect("Missing CLIENT_ID"));
    let auth_url =
        AuthUrl::new(env::var("AUTH_URL").expect("Missing AUTH_URL")).expect("Invalid AUTH_URL");
    let token_url = TokenUrl::new(env::var("TOKEN_URL").expect("Missing TOKEN_URL"))
        .expect("Invalid TOKEN_URL");

    BasicClient::new(client_id, None, auth_url, Some(token_url)).set_redirect_uri(redirect_url)
}

pub async fn authenticate(window: Window) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let port = start(move |url| {
        let _ = tx.send(url);
    })?;
    let client = Arc::new(create_client(RedirectUrl::new(format!(
        "http://localhost:{port}"
    ))?));
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let auth_request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge.clone())
        .add_scope(Scope::new("openid".to_string()))
        .url();

    open::that(format!("{:?}", auth_request))?;
    let auth = OAuthState {
        csrf_token: auth_request.1,
        pkce: Arc::new((pkce_challenge, pkce_verifier)),
    };

    let url = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("No URL received"))?;
    let parsed_url = Url::parse(&url)?;
    let query = parsed_url
        .query()
        .ok_or_else(|| anyhow::anyhow!("Missing query string"))?;
    let callback_query: CallbackQuery =
        serde_urlencoded::from_str(query).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    if callback_query.state.secret() != auth.csrf_token.secret() {
        println!("Suspected Man in the Middle attack!");
        anyhow::bail!("CSRF token mismatch");
    }

    let cli = client
        .exchange_code(callback_query.code)
        .set_pkce_verifier(PkceCodeVerifier::new(auth.pkce.1.secret().clone()));
    let token = cli.request_async(async_http_client).await?;
    println!("Token: {:?}", token);
    // TODO: store token here

    Ok(())
}
