use oauth2::{
    basic::BasicClient, reqwest::http_client, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenUrl
};
use serde::Deserialize;
use std::sync::Arc;
use url::Url;
use std::env;
use tauri::Window;
use tauri_plugin_oauth::start;

struct OAuthService {
    client: Arc<BasicClient>,
}

struct OAuthState {
    csrf_token: CsrfToken,
    pkce: Arc<(PkceCodeChallenge, PkceCodeVerifier)>,
}

#[derive(Deserialize, Debug)]
struct CallbackQuery {
  code: AuthorizationCode,
  state: CsrfToken,
}

impl OAuthService {
    fn new(redirect_url: RedirectUrl) -> OAuthService {
        OAuthService {
            client: Arc::new(Self::create_client(redirect_url)),
        }
    }

    fn create_client(redirect_url: RedirectUrl) -> BasicClient {
        let client_id = ClientId::new(env::var("OAUTH2_CLIENT_ID").expect("Missing OAUTH2_CLIENT_ID"));
        let auth_url = AuthUrl::new(env::var("OAUTH2_AUTH_URL").expect("Missing OAUTH2_AUTH_URL")).expect("Invalid AUTH0_AUTH_URL");
        let token_url = TokenUrl::new(env::var("OAUTH2_TOKEN_URL").expect("Missing OAUTH2_TOKEN_URL")).expect("Invalid AUTH0_TOKEN_URL");

        BasicClient::new(client_id, None, auth_url, Some(token_url))
            .set_redirect_uri(redirect_url)
    }

    async fn authenticate(&self, window: Window) -> anyhow::Result<()> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let auth_request = self.client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scope(Scope::new("openid".to_string()))
            .url();


        let (tx, rx) = tokio::sync::oneshot::channel();

        // Start the local server using tauri-plugin-oauth
        start(move |url| {
            let _ = tx.send(url);
        });
        open::that(format!("{:?}", auth_request))?;
        let auth = OAuthState {
            csrf_token: auth_request.1,
            pkce: Arc::new((pkce_challenge, pkce_verifier)),
        };

        let url = rx.await?;
        let query = Url::parse(&url)?.query().ok_or_else(|| anyhow::anyhow!("Missing query string"))?;
        let callback_query: CallbackQuery = serde_urlencoded::from_str(query).map_err(|e| anyhow::anyhow!(e.to_string()))?;

        if callback_query.state.secret() != auth.csrf_token.secret() {
            println!("Suspected Man in the Middle attack!");
            anyhow::bail!("CSRF token mismatch");
        }

        let cli = self.client.exchange_code(callback_query.code).set_pkce_verifier(PkceCodeVerifier::new(auth.pkce.1.secret().clone()));
        let token = cli.request_async(http_client).await?;
        println!("Token: {:?}", token);
        // TODO: store token here

        Ok(())
    }
}