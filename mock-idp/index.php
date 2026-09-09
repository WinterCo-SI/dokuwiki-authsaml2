<?php
// Minimal development-only IdP: echoes a SAML response to the requested ACS.
$request = isset($_GET['SAMLRequest']) ? base64_decode((string)$_GET['SAMLRequest']) : '';
$id = '';
if (preg_match('/\bID="([^"]+)"/', $request, $m)) $id = $m[1];
$acs = isset($_GET['RelayState']) ? '' : '';
$acs = getenv('SAML_ACS_URL') ?: 'http://localhost:8088/?saml_action=acs';
$xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="'.htmlspecialchars($id, ENT_QUOTES, 'UTF-8').'" Destination="'.htmlspecialchars($acs, ENT_QUOTES, 'UTF-8').'">'
    . '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    . '<saml:Assertion><saml:Subject><saml:NameID>mock-user</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>mock-user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
?><form method="post" action="<?= htmlspecialchars($acs, ENT_QUOTES, 'UTF-8') ?>"><input type="hidden" name="SAMLResponse" value="<?= htmlspecialchars(base64_encode($xml), ENT_QUOTES, 'UTF-8') ?>"><button>Continue</button></form><script>document.forms[0].submit()</script>
