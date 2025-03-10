use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
};
use oauth2::{reqwest, AccessToken, TokenResponse};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tauri_plugin_oauth::start_with_config;
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

pub async fn authenticate() -> anyhow::Result<AccessToken> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let port = start_with_config(
        tauri_plugin_oauth::OauthConfig {
            ports: Some((45000..=45010).collect()),
            response: None,
        },
        move |url| {
            let _ = tx.send(url);
        },
    )?;

    fn create_oauth_client(port: u16) -> Result<BasicClient, anyhow::Error> {
        let client_id =
            ClientId::new(env::var("CLIENT_ID").map_err(|_| anyhow::anyhow!("Missing CLIENT_ID"))?);
        let auth_url =
            AuthUrl::new(env::var("AUTH_URL").map_err(|_| anyhow::anyhow!("Missing AUTH_URL"))?)
                .map_err(|_| anyhow::anyhow!("Invalid AUTH_URL"))?;
        let token_url =
            TokenUrl::new(env::var("TOKEN_URL").map_err(|_| anyhow::anyhow!("Missing TOKEN_URL"))?)
                .map_err(|_| anyhow::anyhow!("Invalid TOKEN_URL"))?;

        let client = BasicClient::new(client_id)
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(RedirectUrl::new(format!("http://localhost:{port}"))?);

        Ok(client)
    }

    let client = create_oauth_client(port)?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let auth_request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge.clone())
        .add_scope(Scope::new("openid".to_string()))
        .url();

    println!("Opening browser for authentication...{}", auth_request.0);
    open::that(auth_request.0.to_string())?;
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

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let cli = client
        .exchange_code(callback_query.code)
        .set_pkce_verifier(PkceCodeVerifier::new(auth.pkce.1.secret().clone()));
    let token = cli
        .request_async(&http_client)
        .await?
        .access_token()
        .clone();
    Ok(token)
}
