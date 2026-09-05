<?php
$meta['sp_entity_id'] = array('string');
$meta['idp_entity_id'] = array('string');
$meta['idp_sso_url'] = array('string');
$meta['idp_slo_url'] = array('string');
$meta['idp_x509cert'] = array('');
$meta['sp_x509cert'] = array('');
$meta['sp_private_key'] = array('');
$meta['username_attribute'] = array('string');
$meta['mail_attribute'] = array('string');
$meta['name_attribute'] = array('string');
$meta['groups_attribute'] = array('string');
$meta['session_cookie_lifetime'] = array('numeric', '_min' => 1);
$meta['require_signed_assertions'] = array('onoff');
$meta['require_encrypted_assertions'] = array('onoff');
$meta['strict'] = array('onoff');
$meta['debug'] = array('onoff');
