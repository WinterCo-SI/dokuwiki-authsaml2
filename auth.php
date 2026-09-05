<?php

/** DokuWiki authentication backend for OneLogin SAML 2.0. */
class auth_plugin_authsaml2 extends DokuWiki_Auth_Plugin {
    /** @var OneLogin\\Saml2\\Auth|null */
    private $saml;

    public $cando = array(
        'external' => true,
        'logout' => true,
        'getUsers' => false,
        'getGroups' => false,
        'addUser' => false,
        'delUser' => false,
        'modName' => false,
        'modLogin' => false,
        'modPass' => false,
        'modGroups' => false
    );

    public function __construct() {
        parent::__construct();
        $this->saml = null;
        $this->loadSdk();
        $this->handleRequest();
    }

    public function getUserData($username, $requireGroups = false) {
        if (isset($_SESSION['authsaml2_userinfo'][$username])) return $_SESSION['authsaml2_userinfo'][$username];
        return array('user' => $username, 'name' => $username, 'mail' => '', 'grps' => array());
    }

    public function checkPass($user, $pass) {
        if ($pass === '__authsaml2_session__') {
            if (empty($_SESSION['authsaml2_expires_at'][$user]) || $_SESSION['authsaml2_expires_at'][$user] <= time()) return false;
            if (isset($_SESSION['authsaml2_userinfo'][$user])) return true;
            if (!isset($_SESSION['authsaml2_assertion']) || $_SESSION['authsaml2_assertion']['user'] !== $user) return false;
            $assertion = $_SESSION['authsaml2_assertion'];
            if (!isset($_SESSION['authsaml2_userinfo'])) $_SESSION['authsaml2_userinfo'] = array();
            $_SESSION['authsaml2_userinfo'][$user] = $assertion;
            return true;
        }
        return false;
    }

    public function trustExternal($user, $pass, $sticky = false) {
        global $INPUT;
        if ($INPUT->bool('saml_acs')) {
            return $this->consumeAssertion();
        }
        if ($INPUT->bool('saml_login')) {
            $this->redirectToLogin();
            return false;
        }
        return null;
    }

    public function logOff() {
        if (!$this->saml || empty($_SESSION['authsaml2_saml_session'])) return true;

        $session = $_SESSION['authsaml2_saml_session'];
        try {
            $url = $this->saml->logout(
                wl(),
                array(),
                $session['nameId'],
                $session['sessionIndex'],
                true,
                $session['nameIdFormat'],
                $session['nameIdNameQualifier'],
                $session['nameIdSPNameQualifier']
            );
            unset($_SESSION['authsaml2_saml_session']);
            $_SESSION['authsaml2_logout_request_id'] = $this->saml->getLastRequestID();
            send_redirect($url);
            exit;
        } catch (\Throwable $e) {
            unset($_SESSION['authsaml2_logout_request_id']);
        }
        return true;
    }

    public function getCapabilities() {
        return array('external' => true, 'logout' => true);
    }

    public function loginButton() {
        global $ID;
        $url = $this->endpointUrl('login', array('return' => wl($ID, '', true, '&')));
        return '<a class="button" href="' . hsc($url) . '">' . hsc($this->getLang('login')) . '</a>';
    }

    public function endpointUrl($action, array $parameters = array()) {
        $parameters = array_merge(array('saml_action' => $action), $parameters);
        return rtrim(DOKU_URL, '/') . '/?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    public function saml() {
        return $this->saml;
    }

    public function assertionUser() {
        if (!$this->saml) return null;
        $attrs = $this->saml->getAttributes();
        $map = $this->attributeMap();
        $username = $this->firstAttribute($attrs, $map['username']);
        if (!$username) return null;
        return array(
            'user' => $username,
            'name' => $this->firstAttribute($attrs, $map['name']),
            'mail' => $this->firstAttribute($attrs, $map['mail']),
            'grps' => $this->attributeValues($attrs, $map['groups'])
        );
    }

    private function loadSdk() {
        $loader = __DIR__ . '/vendor/load.php';
        if (is_file($loader)) require_once $loader;
        if (!class_exists('OneLogin\\Saml2\\Auth') || !$this->isConfigured()) return;
        try {
            $this->saml = new OneLogin\Saml2\Auth($this->settings());
        } catch (\Throwable $e) {
            $this->saml = null;
        }
    }

    private function isConfigured() {
        $required = array('sp_entity_id', 'idp_entity_id', 'idp_sso_url');
        foreach ($required as $name) {
            if (trim((string)$this->getConf($name)) === '') return false;
        }
        if ($this->getConf('require_signed_assertions') && trim((string)$this->getConf('idp_x509cert')) === '') return false;
        if ($this->getConf('require_encrypted_assertions')) {
            if (trim((string)$this->getConf('sp_x509cert')) === '') return false;
            if (trim((string)$this->getConf('sp_private_key')) === '') return false;
        }
        return true;
    }

    public function settings() {
        global $conf;
        return array(
            'strict' => (bool)$conf['plugin']['authsaml2']['strict'],
            'debug' => (bool)$conf['plugin']['authsaml2']['debug'],
            'sp' => array('entityId' => $conf['plugin']['authsaml2']['sp_entity_id'], 'assertionConsumerService' => array('url' => $this->endpointUrl('acs')), 'singleLogoutService' => array('url' => $this->endpointUrl('slo')), 'x509cert' => $conf['plugin']['authsaml2']['sp_x509cert'], 'privateKey' => $conf['plugin']['authsaml2']['sp_private_key']),
            'idp' => array('entityId' => $conf['plugin']['authsaml2']['idp_entity_id'], 'singleSignOnService' => array('url' => $conf['plugin']['authsaml2']['idp_sso_url']), 'singleLogoutService' => array('url' => $conf['plugin']['authsaml2']['idp_slo_url']), 'x509cert' => $conf['plugin']['authsaml2']['idp_x509cert']),
            'security' => array('wantAssertionsSigned' => (bool)$conf['plugin']['authsaml2']['require_signed_assertions'], 'wantAssertionsEncrypted' => (bool)$conf['plugin']['authsaml2']['require_encrypted_assertions'])
        );
    }

    private function redirectToLogin() {
        if (!$this->saml) return;
        global $ID;
        $this->startLogin(wl($ID, '', true, '&'));
    }

    private function startLogin($returnTo) {
        $url = $this->saml->login($returnTo, array(), false, false, true);
        $_SESSION['authsaml2_return_to'] = $returnTo;
        $_SESSION['authsaml2_request_id'] = $this->saml->getLastRequestID();
        $this->setCrossSiteSessionCookie();
        send_redirect($url);
        exit;
    }

    /** Handle SAML requests routed through DokuWiki's only public entrypoint. */
    private function handleRequest() {
        if (empty($_REQUEST['saml_action']) || !$this->saml) return;
        $action = (string)$_REQUEST['saml_action'];
        if ($action === 'login') {
            $returnTo = $this->localReturnUrl(isset($_REQUEST['return']) ? (string)$_REQUEST['return'] : '');
            $this->startLogin($returnTo);
        }
        if ($action === 'metadata') {
            header('Content-Type: application/xml');
            echo $this->saml->getSettings()->getSPMetadata();
            exit;
        }
        if ($action === 'acs') {
            if (!$this->processSamlResponse()) { http_status(401); exit('Invalid SAML response'); }
            $user = $this->assertionUser();
            if (!$user) { http_status(401); exit('SAML response did not contain a username'); }
            $samlSession = $this->samlSession();
            $returnTo = $this->consumeReturnUrl();
            $_SESSION['authsaml2_assertion'] = $user;
            if (!isset($_SESSION['authsaml2_expires_at'])) $_SESSION['authsaml2_expires_at'] = array();
            $_SESSION['authsaml2_expires_at'][$user['user']] = time() + $this->sessionCookieLifetime();
            unset($_SESSION['authsaml2_saml_session']);
            global $auth;
            $auth = $this;
            if (!auth_login($user['user'], '__authsaml2_session__', false)) {
                unset($_SESSION['authsaml2_assertion']);
                http_status(401);
                exit('Could not create the DokuWiki session');
            }
            $_SESSION['authsaml2_saml_session'] = $samlSession;
            $this->setSessionCookieExpiry();
            send_redirect($returnTo);
            exit;
        }
        if ($action === 'slo') {
            $requestId = isset($_SESSION['authsaml2_logout_request_id']) ? $_SESSION['authsaml2_logout_request_id'] : null;
            $this->saml->processSLO(false, $requestId);
            if ($this->saml->getErrors()) { http_status(401); exit('Invalid SAML logout message'); }
            send_redirect(wl());
            exit;
        }
    }

    private function samlSession() {
        return array(
            'nameId' => $this->saml->getNameId(),
            'sessionIndex' => $this->saml->getSessionIndex(),
            'nameIdFormat' => $this->saml->getNameIdFormat(),
            'nameIdNameQualifier' => $this->saml->getNameIdNameQualifier(),
            'nameIdSPNameQualifier' => $this->saml->getNameIdSPNameQualifier()
        );
    }

    private function processSamlResponse() {
        if (empty($_SESSION['authsaml2_request_id'])) return false;
        $requestId = (string)$_SESSION['authsaml2_request_id'];
        unset($_SESSION['authsaml2_request_id']);
        try {
            $this->saml->processResponse($requestId);
        } catch (\Throwable $e) {
            return false;
        }
        return !$this->saml->getErrors();
    }

    private function consumeReturnUrl() {
        $returnTo = isset($_SESSION['authsaml2_return_to']) ? (string)$_SESSION['authsaml2_return_to'] : '';
        unset($_SESSION['authsaml2_return_to']);
        $relayState = isset($_REQUEST['RelayState']) ? (string)$_REQUEST['RelayState'] : '';
        if ($returnTo !== '' && $relayState !== '' && hash_equals($returnTo, $relayState)) return $returnTo;
        return wl();
    }

    private function localReturnUrl($url) {
        $url = trim($url);
        if ($url === '') return wl();
        if (preg_match('/[\\x00-\\x1f\\x7f]/', $url) || strpos($url, '\\') !== false || substr($url, 0, 2) === '//') return wl();

        $target = parse_url($url);
        if ($target === false) return wl();
        if (!isset($target['scheme']) && !isset($target['host'])) return $url;

        $wiki = parse_url(DOKU_URL);
        if ($wiki === false || !isset($target['scheme'], $target['host'], $wiki['scheme'], $wiki['host'])) return wl();
        $targetPort = isset($target['port']) ? (int)$target['port'] : (strtolower($target['scheme']) === 'https' ? 443 : 80);
        $wikiPort = isset($wiki['port']) ? (int)$wiki['port'] : (strtolower($wiki['scheme']) === 'https' ? 443 : 80);
        if (strtolower($target['scheme']) !== strtolower($wiki['scheme'])) return wl();
        if (strtolower($target['host']) !== strtolower($wiki['host']) || $targetPort !== $wikiPort) return wl();
        return $url;
    }

    private function consumeAssertion() {
        if (!$this->saml) return false;
        if (!$this->processSamlResponse()) return false;
        global $USERINFO;
        $assertion = $this->assertionUser();
        if (!$assertion) return false;
        $username = $assertion['user'];
        $USERINFO = $assertion;
        $_SERVER['REMOTE_USER'] = $username;
        if (!isset($_SESSION['authsaml2_userinfo'])) $_SESSION['authsaml2_userinfo'] = array();
        if (!isset($_SESSION['authsaml2_expires_at'])) $_SESSION['authsaml2_expires_at'] = array();
        $_SESSION['authsaml2_userinfo'][$username] = $assertion;
        $_SESSION['authsaml2_expires_at'][$username] = time() + $this->sessionCookieLifetime();
        $_SESSION['authsaml2_saml_session'] = $this->samlSession();
        $this->setSessionCookieExpiry();
        return true;
    }

    /** Make the PHP session cookie persistent for the configured validity period. */
    private function setSessionCookieExpiry() {
        if (session_status() !== PHP_SESSION_ACTIVE) return;

        $params = session_get_cookie_params();
        $options = array(
            'expires' => time() + $this->sessionCookieLifetime(),
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly']
        );
        if (isset($params['samesite']) && $params['samesite'] !== '') {
            $options['samesite'] = $params['samesite'];
        }
        setcookie(session_name(), session_id(), $options);
    }

    private function setCrossSiteSessionCookie() {
        if (session_status() !== PHP_SESSION_ACTIVE) return;

        $params = session_get_cookie_params();
        setcookie(session_name(), session_id(), array(
            'expires' => 0,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => true,
            'httponly' => $params['httponly'],
            'samesite' => 'None'
        ));
    }

    private function sessionCookieLifetime() {
        return max(1, (int)$this->getConf('session_cookie_lifetime'));
    }

    private function attributeMap() {
        return array(
            'username' => trim((string)$this->getConf('username_attribute')),
            'mail' => trim((string)$this->getConf('mail_attribute')),
            'name' => trim((string)$this->getConf('name_attribute')),
            'groups' => trim((string)$this->getConf('groups_attribute'))
        );
    }

    private function firstAttribute($attrs, $name) { return !empty($attrs[$name]) ? (string)$attrs[$name][0] : ''; }

    private function attributeValues($attrs, $name) {
        if (empty($attrs[$name]) || !is_array($attrs[$name])) return array();
        return array_map('strval', $attrs[$name]);
    }
}
