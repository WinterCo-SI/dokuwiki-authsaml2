# DokuWiki SAML 2 authentication

This plugin adds SAML 2.0 single sign-on to DokuWiki using the bundled OneLogin PHP SAML toolkit. Install the complete plugin package, enable `authsaml2` as the DokuWiki authentication backend, and configure the IdP and SP values in Admin → Configuration Settings. Composer is not required on the DokuWiki host.

SAML endpoints use fixed URLs at the public wiki root, such as `/?saml_action=acs`, so they do not depend on the page that initiated authentication. DokuWiki's standard Login action starts the SAML flow. RelayState contains an opaque base64url token while the return URL remains in the server-side session. Configure the username, email, display-name, and groups SAML attributes separately with `username_attribute`, `mail_attribute`, `name_attribute`, and `groups_attribute`. Their defaults are `uid`, `mail`, `displayName`, and `groups`. Every value in the configured groups attribute becomes a DokuWiki group membership. Keep certificates and private keys out of version control.

The plugin validates the response Destination against the complete ACS URL, including `?saml_action=acs`. Set `acs_url_override` when the public ACS URL cannot be derived from DokuWiki's configured URL, such as behind a reverse proxy. The override is used in SP metadata and as the expected response Destination.

`session_cookie_lifetime` controls how long the authenticated PHP session cookie remains valid, in seconds. Its default is 28800 seconds (8 hours), measured from a successful SAML login. The plugin uses this cookie instead of DokuWiki's separate sticky-login cookie.

Rejected SAML responses are sent to DokuWiki's error logger with the toolkit's validation reason. When `debug` is enabled, the escaped reason is also included on the error page.

When the IdP has no SLO URL, logout clears the local DokuWiki and SAML session state and redirects to the wiki root. This avoids DokuWiki's normal post-logout redirect to the login action, which would immediately start another SSO login while the IdP session remains active.

Use HTTPS for the wiki and its ACS URL. The login round trip temporarily marks the PHP session cookie `SameSite=None; Secure` so the IdP's cross-site SAML POST retains the AuthnRequest and return state.

Initialize the pinned SDK submodules after cloning with `git submodule update --init --recursive`.
