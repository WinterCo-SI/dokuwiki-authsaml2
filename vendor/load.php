<?php

$xmlsecDir = __DIR__ . '/robrichards/xmlseclibs/src/';
require_once $xmlsecDir . 'XMLSecurityKey.php';
require_once $xmlsecDir . 'XMLSecurityDSig.php';
require_once $xmlsecDir . 'XMLSecEnc.php';
require_once $xmlsecDir . 'Utils/XPath.php';

$samlDir = __DIR__ . '/onelogin/php-saml/src/Saml2/';
$samlClasses = array(
    'Auth.php',
    'AuthnRequest.php',
    'Constants.php',
    'Error.php',
    'LogoutRequest.php',
    'LogoutResponse.php',
    'Metadata.php',
    'Response.php',
    'Settings.php',
    'Utils.php',
    'ValidationError.php'
);
foreach ($samlClasses as $samlClass) require_once $samlDir . $samlClass;
