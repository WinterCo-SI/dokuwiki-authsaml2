# DokuWiki SAML 2 authentication

This plugin adds SAML 2.0 single sign-on to DokuWiki using the bundled OneLogin PHP SAML toolkit. Install the complete plugin package, enable `authsaml2` as the DokuWiki authentication backend, and configure the IdP and SP values in Admin → Configuration Settings. Composer is not required on the DokuWiki host.

SAML endpoints use fixed URLs at the public wiki root, such as `/?saml_action=acs`, so they do not depend on the page that initiated authentication. DokuWiki's standard Login action starts the SAML flow, and RelayState returns the user to the page shown before login. Configure the username, email, display-name, and groups SAML attributes separately with `username_attribute`, `mail_attribute`, `name_attribute`, and `groups_attribute`. Their defaults are `uid`, `mail`, `displayName`, and `groups`. Every value in the configured groups attribute becomes a DokuWiki group membership. Keep certificates and private keys out of version control.

`session_cookie_lifetime` controls how long the authenticated PHP session cookie remains valid, in seconds. Its default is 28800 seconds (8 hours), measured from a successful SAML login. The plugin uses this cookie instead of DokuWiki's separate sticky-login cookie.

Rejected SAML responses are sent to DokuWiki's error logger with the toolkit's validation reason. When `debug` is enabled, the escaped reason is also included on the error page.

Use HTTPS for the wiki and its ACS URL. The login round trip temporarily marks the PHP session cookie `SameSite=None; Secure` so the IdP's cross-site SAML POST retains the AuthnRequest and return state.

Initialize the pinned SDK submodules after cloning with `git submodule update --init --recursive`.
