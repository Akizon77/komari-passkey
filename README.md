# Komari Passkey

Komari Passkey is a plugin-only WebAuthn login implementation. It does not
modify Komari itself and does not use HTTP hooks.

It stores credentials and short-lived challenges in two plugin tables in the
main Komari database. After a verified assertion it creates a native row in
the existing sessions table and sends the normal session_token cookie.

## Requirements

- Komari `>=1.4.3`.
- A Komari release exposing admin:dbQuery and admin:dbExec to plugins.
- Node.js 20 or newer on the Komari host. The plugin starts a loopback-only
  SimpleWebAuthn verifier process.
- HTTPS with a configured RP ID and allowed origin. HTTP is intentionally
  disabled by default and can be enabled explicitly for local development.

## Setup

After installing the plugin, open the Komari **Account** page and add a
Passkey. The Passkey login button appears after at least one credential has
been registered.

## Security Defaults

- Required user verification and resident credentials.
- Platform authenticator registration.
- Synced multi-device credentials are rejected.
- 120-second challenge lifetime.
- 12-hour HttpOnly, Secure, SameSite=Strict session cookie.

All of these policies are declared in the plugin configuration and can be
adjusted there before registering a passkey.

## Development

    npm install
    npm run typecheck
    npm test
    npm run pack

The development server and API key are stored in komari.local.json, which is
ignored by Git. Do not commit that file.
