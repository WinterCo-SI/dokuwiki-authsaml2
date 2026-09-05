<?php

define('DOKU_URL', 'https://wiki.example.test/wiki/');
define('DOKU_BASE', '/wiki/');

eval('namespace dokuwiki; class Logger { public static $errors = array(); public static function error($message, $details = null, $file = "", $line = 0) { self::$errors[] = array($message, $details, $file, $line); return true; } }');

class RedirectSignal extends Exception {
    public $url;

    public function __construct($url) {
        parent::__construct($url);
        $this->url = $url;
    }
}

class DokuWiki_Auth_Plugin {
    public function __construct() {}

    public function getConf($name) {
        global $conf;
        return isset($conf['plugin']['authsaml2'][$name]) ? $conf['plugin']['authsaml2'][$name] : null;
    }

    public function getLang($name) {
        return $name;
    }
}

class DokuWiki_Action_Plugin {}

class Doku_Event_Handler {
    public $hooks = array();

    public function register_hook($event, $when, $object, $method) {
        $this->hooks[] = array($event, $when, $object, $method);
    }
}

class Doku_Event {
    public $data;
    public $prevented = false;
    public $stopped = false;

    public function __construct($data) {
        $this->data = $data;
    }

    public function preventDefault() {
        $this->prevented = true;
    }

    public function stopPropagation() {
        $this->stopped = true;
    }
}

class InputStub {
    public function bool($name) {
        return false;
    }
}

class SamlStub {
    public $processedRequestId;
    public $loginRelayState;
    public $logoutCalled = false;
    public $errors = array();
    public $lastErrorReason;
    public $lastResponseXml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://wiki.example.test/wiki/?saml_action=acs"/>';

    public function login($relayState, array $parameters, $forceAuthn, $isPassive, $stay) {
        if (!$stay) throw new Exception('Login URL must be requested without redirecting');
        $this->loginRelayState = $relayState;
        return 'https://idp.example.test/login';
    }

    public function getLastRequestID() {
        return 'request-123';
    }

    public function logout($returnTo, array $parameters, $nameId, $sessionIndex, $stay, $nameIdFormat, $nameIdNameQualifier, $nameIdSPNameQualifier) {
        $this->logoutCalled = true;
        return 'https://idp.example.test/logout?SAMLRequest=request';
    }

    public function processResponse($requestId) {
        $this->processedRequestId = $requestId;
    }

    public function getErrors() {
        return $this->errors;
    }

    public function getLastErrorReason() {
        return $this->lastErrorReason;
    }

    public function getLastResponseXML() {
        return $this->lastResponseXml;
    }
}

function wl($id = '', $more = '', $absolute = false, $separator = '&amp;') {
    $url = ($absolute ? DOKU_URL : DOKU_BASE) . ($id === '' ? 'start' : rawurlencode($id));
    if (is_array($more)) $more = http_build_query($more);
    return $more === '' ? $url : $url . '?' . str_replace('&', $separator, $more);
}

function hsc($value) {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function send_redirect($url) {
    throw new RedirectSignal($url);
}

function check($condition, $message) {
    if (!$condition) throw new Exception($message);
}

function signedSamlResponse($requestId, $destination, $spEntityId, $idpEntityId, $key, $certificate) {
    $issuedAt = gmdate('Y-m-d\TH:i:s\Z');
    $notBefore = gmdate('Y-m-d\TH:i:s\Z', time() - 60);
    $notAfter = gmdate('Y-m-d\TH:i:s\Z', time() + 3600);
    $assertionId = '_assertion_' . bin2hex(random_bytes(8));
    $responseId = '_response_' . bin2hex(random_bytes(8));
    $escape = function ($value) {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    };

    $assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="' . $assertionId . '" Version="2.0" IssueInstant="' . $issuedAt . '">' .
        '<saml:Issuer>' . $escape($idpEntityId) . '</saml:Issuer>' .
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.test</saml:NameID>' .
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="' . $escape($requestId) . '" NotOnOrAfter="' . $notAfter . '" Recipient="' . $escape($destination) . '"/></saml:SubjectConfirmation></saml:Subject>' .
        '<saml:Conditions NotBefore="' . $notBefore . '" NotOnOrAfter="' . $notAfter . '"><saml:AudienceRestriction><saml:Audience>' . $escape($spEntityId) . '</saml:Audience></saml:AudienceRestriction></saml:Conditions>' .
        '<saml:AuthnStatement AuthnInstant="' . $issuedAt . '" SessionNotOnOrAfter="' . $notAfter . '" SessionIndex="session-123"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>' .
        '<saml:AttributeStatement>' .
        '<saml:Attribute Name="uid"><saml:AttributeValue xsi:type="xs:string">alice</saml:AttributeValue></saml:Attribute>' .
        '<saml:Attribute Name="mail"><saml:AttributeValue xsi:type="xs:string">alice@example.test</saml:AttributeValue></saml:Attribute>' .
        '<saml:Attribute Name="displayName"><saml:AttributeValue xsi:type="xs:string">Alice Example</saml:AttributeValue></saml:Attribute>' .
        '<saml:Attribute Name="groups"><saml:AttributeValue xsi:type="xs:string">content editors</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">admins</saml:AttributeValue></saml:Attribute>' .
        '</saml:AttributeStatement></saml:Assertion>';

    $signedAssertion = OneLogin\Saml2\Utils::addSign($assertion, $key, $certificate);
    $signedAssertionDocument = new DOMDocument();
    $signedAssertionDocument->loadXML($signedAssertion);
    $signature = $signedAssertionDocument->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);
    $issuer = $signedAssertionDocument->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')->item(0);
    $issuer->parentNode->insertBefore($signature, $issuer->nextSibling);
    $signedAssertion = $signedAssertionDocument->saveXML($signedAssertionDocument->documentElement);
    $response = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . $responseId . '" Version="2.0" IssueInstant="' . $issuedAt . '" Destination="' . $escape($destination) . '" InResponseTo="' . $escape($requestId) . '">' .
        '<saml:Issuer>' . $escape($idpEntityId) . '</saml:Issuer>' .
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' .
        $signedAssertion . '</samlp:Response>';
    return base64_encode($response);
}

require dirname(__DIR__) . '/auth.php';
require dirname(__DIR__) . '/action.php';

$conf = array('plugin' => array('authsaml2' => array(
    'strict' => 1,
    'debug' => 0,
    'sp_entity_id' => 'https://wiki.example.test/saml',
    'acs_url_override' => '',
    'sp_x509cert' => '',
    'sp_private_key' => '',
    'idp_entity_id' => 'https://idp.example.test/',
    'idp_sso_url' => 'https://idp.example.test/login',
    'idp_slo_url' => 'https://idp.example.test/logout',
    'idp_x509cert' => 'certificate',
    'require_signed_assertions' => 1,
    'require_encrypted_assertions' => 1,
    'session_cookie_lifetime' => 28800,
    'username_attribute' => 'uid',
    'mail_attribute' => 'mail',
    'name_attribute' => 'displayName',
    'groups_attribute' => 'groups'
)));

session_start();
$configuredEntityId = $conf['plugin']['authsaml2']['sp_entity_id'];
$conf['plugin']['authsaml2']['sp_entity_id'] = '';
$incompleteBackend = new auth_plugin_authsaml2();
check($incompleteBackend->saml() === null, 'Incomplete configuration must not initialize the SAML toolkit');
$conf['plugin']['authsaml2']['sp_entity_id'] = $configuredEntityId;

$reflection = new ReflectionClass('auth_plugin_authsaml2');
$backend = $reflection->newInstanceWithoutConstructor();
$samlProperty = $reflection->getProperty('saml');
$samlProperty->setAccessible(true);
$samlProperty->setValue($backend, null);

$INPUT = new InputStub();
check($backend->trustExternal('', '') === null, 'Inactive external authentication must defer to DokuWiki');

$_SESSION['authsaml2_userinfo']['alice'] = array('user' => 'alice', 'grps' => array('editors'));
$_SESSION['authsaml2_expires_at']['alice'] = time() + 3600;
check($backend->checkPass('alice', '__authsaml2_session__'), 'Cached SAML session must validate');
check($backend->checkPass('alice', '__authsaml2_session__'), 'Cached SAML session must remain reusable');
$_SESSION['authsaml2_expires_at']['alice'] = time() - 1;
check(!$backend->checkPass('alice', '__authsaml2_session__'), 'Expired SAML session must be rejected');

$settings = $backend->settings();
check($settings['sp']['assertionConsumerService']['url'] === 'https://wiki.example.test/wiki/?saml_action=acs', 'ACS URL must use the fixed wiki root');
check($settings['baseurl'] === 'https://wiki.example.test/wiki/', 'SAML validation base URL must use the public ACS scheme, host, and path');
check($settings['sp']['singleLogoutService']['url'] === 'https://wiki.example.test/wiki/?saml_action=slo', 'SLO URL must use the fixed wiki root');
check($settings['security']['wantAssertionsEncrypted'] === true, 'Assertion encryption setting must be enabled');
check($settings['security']['relaxDestinationValidation'] === true, 'The toolkit destination check must defer to the plugin exact check');

$conf['plugin']['authsaml2']['acs_url_override'] = 'https://proxy.example.test/saml/acs?saml_action=acs';
$overriddenSettings = $backend->settings();
check($overriddenSettings['sp']['assertionConsumerService']['url'] === $conf['plugin']['authsaml2']['acs_url_override'], 'ACS URL override must be advertised');
check($overriddenSettings['baseurl'] === 'https://proxy.example.test/saml/acs', 'ACS URL override must control the validation base URL');
$conf['plugin']['authsaml2']['acs_url_override'] = '';

$saml = new SamlStub();
$samlProperty->setValue($backend, $saml);
$loginUrl = $backend->loginUrl('https://wiki.example.test/wiki/page');
check($loginUrl === 'https://wiki.example.test/wiki/?saml_action=login', 'Login URL must not expose the return URL');
check($_SESSION['authsaml2_return_to'] === 'https://wiki.example.test/wiki/page', 'Login return must be staged in the session');
$handleRequest = $reflection->getMethod('handleRequest');
$handleRequest->setAccessible(true);
$_REQUEST = array(
    'saml_action' => 'login',
    'return' => 'https://wiki.example.test/wiki/altered'
);
try {
    $handleRequest->invoke($backend);
    check(false, 'Login must redirect');
} catch (ReflectionException $e) {
    throw $e;
} catch (RedirectSignal $e) {
    check($e->url === 'https://idp.example.test/login', 'Login must redirect to the IdP');
}
check($_SESSION['authsaml2_return_to'] === 'https://wiki.example.test/wiki/page', 'Login endpoint must ignore an altered return parameter');
$_REQUEST = array();
check($_SESSION['authsaml2_request_id'] === 'request-123', 'AuthnRequest ID must be stored');
check($_SESSION['authsaml2_return_to'] === 'https://wiki.example.test/wiki/page', 'Current page must be stored for the login return');
$relayState = $_SESSION['authsaml2_relay_state'];
check($saml->loginRelayState === $relayState, 'Encoded RelayState must be sent to the IdP');
check((bool)preg_match('/^[A-Za-z0-9_-]{43}$/', $relayState), 'RelayState must be a 32-byte base64url token');
check(strpos($relayState, 'wiki.example.test') === false, 'RelayState must not expose the return URL');

$processResponse = $reflection->getMethod('processSamlResponse');
$processResponse->setAccessible(true);
check($processResponse->invoke($backend) === true, 'Correlated SAML response must validate');
check($saml->processedRequestId === 'request-123', 'AuthnRequest ID must be passed to the toolkit');
check(!isset($_SESSION['authsaml2_request_id']), 'AuthnRequest ID must be consumed once');
check($processResponse->invoke($backend) === false, 'Response without login state must be rejected');
check(end(\dokuwiki\Logger::$errors)[1] === 'Missing SAML AuthnRequest ID in the session', 'Missing login state must be logged');

$saml->errors = array('invalid_response');
$saml->lastErrorReason = '<invalid issuer>';
$_SESSION['authsaml2_request_id'] = 'request-456';
check($processResponse->invoke($backend) === false, 'Toolkit validation errors must be rejected');
check(end(\dokuwiki\Logger::$errors)[1] === '<invalid issuer>', 'Toolkit error reason must be logged');
$samlErrorResponse = $reflection->getMethod('samlErrorResponse');
$samlErrorResponse->setAccessible(true);
$conf['plugin']['authsaml2']['debug'] = 0;
check($samlErrorResponse->invoke($backend) === 'Invalid SAML response', 'Error details must be hidden when debug is disabled');
$conf['plugin']['authsaml2']['debug'] = 1;
check($samlErrorResponse->invoke($backend) === 'Invalid SAML response: &lt;invalid issuer&gt;', 'Escaped error details must be shown when debug is enabled');
$conf['plugin']['authsaml2']['debug'] = 0;
$saml->errors = array();
$saml->lastErrorReason = null;

$saml->lastResponseXml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://wiki.example.test/wiki/"/>';
$_SESSION['authsaml2_request_id'] = 'request-wrong-destination';
check($processResponse->invoke($backend) === false, 'Destination without saml_action=acs must be rejected');
check(strpos(end(\dokuwiki\Logger::$errors)[1], 'does not match the ACS URL') !== false, 'Exact destination mismatch must be logged');
$saml->lastResponseXml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://wiki.example.test/wiki/?saml_action=acs"/>';

$_REQUEST['RelayState'] = $relayState;
$consumeReturnUrl = $reflection->getMethod('consumeReturnUrl');
$consumeReturnUrl->setAccessible(true);
check($consumeReturnUrl->invoke($backend) === 'https://wiki.example.test/wiki/page', 'RelayState must restore the page shown before login');
check(!isset($_SESSION['authsaml2_relay_state']), 'RelayState must be consumed once');
unset($_REQUEST['RelayState']);

$handler = new Doku_Event_Handler();
$action = new action_plugin_authsaml2();
$action->register($handler);
check(count($handler->hooks) === 1 && $handler->hooks[0][0] === 'ACTION_ACT_PREPROCESS', 'Login action hook must be registered');

$auth = $backend;
$ID = 'namespace:page';
$event = new Doku_Event('login');
try {
    $action->handleLogin($event, null);
    check(false, 'Standard login action must redirect');
} catch (RedirectSignal $e) {
    check(parse_url($e->url, PHP_URL_PATH) === '/wiki/', 'Login redirect must use the fixed wiki root');
    check(strpos($e->url, 'saml_action=login') !== false, 'Login redirect must target the SAML login action');
    check(strpos($e->url, 'return=') === false, 'Login redirect must not expose the return URL');
}
check($event->prevented && $event->stopped, 'Standard login action must be intercepted');
check($_SESSION['authsaml2_return_to'] === 'https://wiki.example.test/wiki/namespace%3Apage', 'Login action must stage the current page in the session');

$_SESSION['authsaml2_saml_session'] = array(
    'nameId' => 'alice@example.test',
    'sessionIndex' => 'session-123',
    'nameIdFormat' => null,
    'nameIdNameQualifier' => null,
    'nameIdSPNameQualifier' => null
);
$_SESSION['authsaml2_userinfo'] = array('alice' => array('user' => 'alice'));
$_SESSION['authsaml2_expires_at'] = array('alice' => time() + 3600);
$conf['plugin']['authsaml2']['idp_slo_url'] = '';
try {
    $backend->logOff();
    check(false, 'Local-only logout must redirect away from the login action');
} catch (RedirectSignal $e) {
    check($e->url === wl(), 'Local-only logout must redirect to the wiki root');
}
check(!$saml->logoutCalled, 'IdP logout must not be attempted without an SLO URL');
check(!isset($_SESSION['authsaml2_saml_session']), 'Local-only logout must clear the SAML session');
check(!isset($_SESSION['authsaml2_userinfo']), 'Local-only logout must clear cached user data');
check(!isset($_SESSION['authsaml2_expires_at']), 'Local-only logout must clear cached expiry data');
check($backend->logOff() === true, 'Logout without a SAML session must not redirect');
$conf['plugin']['authsaml2']['idp_slo_url'] = 'https://idp.example.test/logout';

$conf['plugin']['authsaml2']['require_encrypted_assertions'] = 0;
$certificate = file_get_contents(dirname(__DIR__) . '/vendor/onelogin/php-saml/tests/data/customPath/certs/sp.crt');
$privateKey = file_get_contents(dirname(__DIR__) . '/vendor/onelogin/php-saml/tests/data/customPath/certs/sp.key');
$conf['plugin']['authsaml2']['idp_x509cert'] = $certificate;
$_SERVER['HTTPS'] = 'on';
$_SERVER['HTTP_HOST'] = 'wiki.example.test';
$_SERVER['SERVER_PORT'] = '443';
$_SERVER['REQUEST_URI'] = '/wiki/?saml_action=acs';
$_SERVER['QUERY_STRING'] = 'saml_action=acs';
$_SERVER['SCRIPT_NAME'] = '/wiki/index';

$realBackend = new auth_plugin_authsaml2();
check($realBackend->saml() instanceof OneLogin\Saml2\Auth, 'Real SAML toolkit must initialize');
$realReflection = new ReflectionClass($realBackend);
$realProcessResponse = $realReflection->getMethod('processSamlResponse');
$realProcessResponse->setAccessible(true);
$requestId = 'request-real-123';
$destination = $realBackend->settings()['sp']['assertionConsumerService']['url'];
$_SESSION['authsaml2_request_id'] = $requestId;
$_POST['SAMLResponse'] = signedSamlResponse(
    $requestId,
    $destination,
    $conf['plugin']['authsaml2']['sp_entity_id'],
    $conf['plugin']['authsaml2']['idp_entity_id'],
    $privateKey,
    $certificate
);
$schemaDocument = new DOMDocument();
$schemaDocument->loadXML(base64_decode($_POST['SAMLResponse']));
libxml_use_internal_errors(true);
if (!$schemaDocument->schemaValidate(dirname(__DIR__) . '/vendor/onelogin/php-saml/src/Saml2/schemas/saml-schema-protocol-2.0.xsd')) {
    $schemaErrors = array_map(function ($error) { return trim($error->message); }, libxml_get_errors());
    throw new Exception('Generated SAML schema errors: ' . implode('; ', $schemaErrors));
}
libxml_clear_errors();
$realResponseValid = $realProcessResponse->invoke($realBackend);
check($realResponseValid === true, 'Signed correlated SAML response must validate: ' . $realBackend->saml()->getLastErrorReason());
$samlUser = $realBackend->assertionUser();
check($samlUser['user'] === 'alice', 'Username must be read from the signed assertion');
check($samlUser['mail'] === 'alice@example.test', 'Email must be read from the signed assertion');
check($samlUser['name'] === 'Alice Example', 'Display name must be read from the signed assertion');
check($samlUser['grps'] === array('content_editors', 'admins'), 'Whitespace in signed group values must be replaced with underscores');
check($realBackend->saml()->getSessionIndex() === 'session-123', 'SAML session index must be available for logout');

$_SESSION['authsaml2_request_id'] = 'different-request';
check($realProcessResponse->invoke($realBackend) === false, 'Mismatched InResponseTo must be rejected');

$tamperedResponse = base64_decode($_POST['SAMLResponse']);
$_POST['SAMLResponse'] = base64_encode(str_replace('Alice Example', 'Mallory Example', $tamperedResponse));
$_SESSION['authsaml2_request_id'] = $requestId;
check($realProcessResponse->invoke($realBackend) === false, 'Modified signed assertion must be rejected');

echo "authsaml2 tests passed\n";
