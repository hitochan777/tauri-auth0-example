# Example Tauri (v2) app with OIDC authentication

This repository demonstrates a Tauri application with OAuth2 authentication.   
It listens for a token event from the Rust backend and shows an alert on the frontend when the token is received.

## Getting started

1. **Install Dependencies**:
   ```bash
   pnpm install
   ```

2. Configure Auth server
   * Callback URL: http://localhost:{45000-45010}
     This example uses port from 450000-45010
   * Enable Authorization Code Grant
     At least Auth0 requires you to enable this otherwise it will show you an error on authentication.

3. **Set Environment Variables**:
   Set environment variables with tools you like (I use direnv)
   ```bash
   CLIENT_ID=your_client_id
   AUTH_URL=your_auth_url
   TOKEN_URL=your_token_url
   ```

4. **Run the Application**:
   ```bash
   pnpm tauri dev
   ```

5. **Authenticate**:
   Open the application and submit the authentication form. An alert will be shown with the token when it is received.
  