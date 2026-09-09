<?php

/** Connect the SAML backend to DokuWiki's standard login action. */
class action_plugin_authsaml2 extends DokuWiki_Action_Plugin {
    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handleLogin');
    }

    public function handleLogin(Doku_Event $event, $param) {
        if ($event->data !== 'login') return;

        global $auth, $ID;
        if (!($auth instanceof auth_plugin_authsaml2) || !$auth->saml()) return;

        $event->preventDefault();
        $event->stopPropagation();
        $returnTo = isset($_SESSION['authsaml2_previous_page'])
            ? (string)$_SESSION['authsaml2_previous_page']
            : wl($ID, '', true, '&');
        send_redirect($auth->loginUrl($returnTo));
        exit;
    }
}
