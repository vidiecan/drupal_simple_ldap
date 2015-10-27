<?php
/**
 * @file
 * Functions for Simple LDAP admin interface.
 */

/**
 * LDAP server configuration form.
 */
function simple_ldap_admin() {
  $form = array();

  $form['server'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Server Connection Information'),
    '#collapsible' => FALSE,
  );

  $form['server']['simple_ldap_host'] = array(
    '#type' => 'textfield',
    '#title' => t('Host'),
    '#required' => TRUE,
    '#default_value' => variable_get('simple_ldap_host', ''),
    '#description' => t('To use SSL, prepend the host with "ldaps://".'),
  );

  $form['server']['simple_ldap_port'] = array(
    '#type' => 'textfield',
    '#title' => t('Port'),
    '#default_value' => variable_get('simple_ldap_port', '389'),
    '#required' => TRUE,
  );

  $form['server']['simple_ldap_starttls'] = array(
    '#type' => 'checkbox',
    '#title' => t('Use startTLS'),
    '#default_value' => variable_get('simple_ldap_starttls', FALSE),
  );

  $form['server']['simple_ldap_readonly'] = array(
    '#type' => 'checkbox',
    '#title' => t('Read-only'),
    '#default_value' => variable_get('simple_ldap_readonly', FALSE),
  );

  $form['directory'] = array(
    '#type' => 'fieldset',
    '#title' => t('Directory Information'),
    '#collapsible' => FALSE,
  );

  $form['directory']['simple_ldap_binddn'] = array(
    '#type' => 'textfield',
    '#title' => t('Bind DN'),
    '#default_value' => variable_get('simple_ldap_binddn', ''),
    '#description' => t('Leave this blank to bind anonymously'),
  );

  $form['directory']['simple_ldap_bindpw'] = array(
    '#type' => 'password',
    '#title' => t('Bind password'),
    '#description' => t('Leave this blank to bind anonymously'),
    '#attributes' => array('value' => array(variable_get('simple_ldap_bindpw', ''))),
  );

  $form['directory']['simple_ldap_basedn'] = array(
    '#type' => 'textfield',
    '#title' => t('Base DN'),
    '#default_value' => variable_get('simple_ldap_basedn', ''),
    '#description' => t('Leave this blank to attempt to detect the base DN.'),
  );

  $form['directory']['simple_ldap_pagesize'] = array(
    '#type' => 'textfield',
    '#title' => t('Search result page size'),
    '#default_value' => variable_get('simple_ldap_pagesize', ''),
    '#description' => t('Leave this blank to disable paged queries.'),
  );

  // Disable the option if paged queries are not supported.
  if (!function_exists('ldap_control_paged_result_response') && !function_exists('ldap_control_paged_result')) {
    $form['directory']['simple_ldap_pagesize']['#disabled'] = TRUE;
    $form['directory']['simple_ldap_pagesize']['#default_value'] = '';
    $form['directory']['simple_ldap_pagesize']['#description'] = t('Paged queries are not supported by this PHP installation.') . ' ' . t('Support was added in PHP version 5.4.');
  }

  $form['ldap_down'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Server Failure'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );
  $form['ldap_down']['simple_ldap_ldap_down_maintenance_mode'] = array(
    '#type' => 'checkbox',
    '#title' => t('Maintenance Mode on LDAP Failure'),
    '#description' => t('Check this to force the site into maintenance mode if no LDAP servers can be reached.'),
    '#default_value' => variable_get('simple_ldap_ldap_down_maintenance_mode', TRUE),
  );
  $form['ldap_down']['simple_ldap_ldap_down_message'] = array(
    '#type' => 'textfield',
    '#title' => t('Maintenance Mode Message on LDAP Failure'),
    '#description' => t('The message to show everyone when LDAP goes down.'),
    '#default_value' => variable_get('simple_ldap_ldap_down_message', t('The site is experiencing technical difficulties.')),
  );
  $form['ldap_down']['simple_ldap_ldap_down_notify_list'] = array(
    '#type' => 'textarea',
    '#title' => t('Notification List'),
    '#description' => t('Specify the list of email addresses to be notified when the LDAP server goes down, one per line.'),
    '#default_value' => variable_get('simple_ldap_ldap_down_notify_list', ''),
  );
  $form['ldap_down']['simple_ldap_ldap_down_notify_frequency'] = array(
    '#type' => 'textfield',
    '#title' => t('Notification Frequency'),
    '#description' => t('How often, in minutes, should the notify list be realerted?  Set to 0 for notify once per outage.'),
    '#default_value' => variable_get('simple_ldap_ldap_down_notify_frequency', '30'),
    '#size' => 4,
  );


  // Advanced settings.
  $form['advanced'] = array(
    '#type' => 'fieldset',
    '#title' => t('Advanced'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );

  $form['advanced']['simple_ldap_opt_referrals'] = array(
    '#type' => 'checkbox',
    '#title' => t('Follow LDAP referrals'),
    '#default_value' => variable_get('simple_ldap_opt_referrals', TRUE),
  );

  $form['advanced']['simple_ldap_debug'] = array(
    '#type' => 'checkbox',
    '#title' => t('Enable watchdog debug logging.'),
    '#default_value' => variable_get('simple_ldap_debug', FALSE),
  );

  return system_settings_form($form);
}

/**
 * Run some basic tests to make debugging LDAP connections easier.
 */
function simple_ldap_server_check() {
  $ldap_host = variable_get('simple_ldap_host', '');
  $matches = array();
  $results = array();

  if (empty($ldap_host)) {
    $error = t('No host speciifed.  Set a host in !ldap_settings and try again.', 
      array('!ldap_settings' => l(t('LDAP Settings'), 'admin/config/people/simple_ldap/server/settings'))
    );
    return "<p>$error</p>";
  }

  // Strip it apart.
  preg_match('/(ldap[si]?):\/\/([^:\/]*)(:(\d*))?(\/)?(.*)/', $ldap_host, $matches);

  if (empty($matches)) {
    $error = t('Could not parse host %host.  Check !ldap_settings and try again.', 
      array(
        '!ldap_settings' => l(t('LDAP Settings'), 'admin/config/people/simple_ldap/server/settings'),
        '%host' => $ldap_host,
      )
    );
    return "<p>$error</p>";
  }

  $proto = $matches[1];
  $host = $matches[2];
  $port = $matches[4];
  $extra = $matches[5];


  //
  // Test 1 - Report the connection type.
  //
  switch ($proto) {
    case 'ldap':
      $connection = t('Unencrypted LDAP connection');
      break;
    case 'ldaps':
      $connection = t('Encrypted LDAP connection');
      break;
    case 'ldapi':
      $connection = t('Connection over UNIX socket');
      break;
    default:
      $connection = t('Unknown connection type');
  }

  $results[] = array(
    'class' => array('ldap-test-information'),
    'data' => array(
      t('Connection Type'),
      $connection,
    ),
  );

  //
  // Test 2 - If it's not socket-based, lookup the host / IP in DNS.
  //
  if (!empty($host)) {
    $php_ipv6 = defined('AF_INET6');
    $is_ipaddr = @inet_pton($host);
    $status = 'ldap-test-ok';

    if ($is_ipaddr) {
      $hostname = gethostbyaddr($host);
      $ip_list = array($host);
    }
    else {
      $ip_list = gethostbynamel($host);
      $hostname = $host;
    }

    if (($ip_list === FALSE) || ($hostname === FALSE)) {
      $dns_result = t('Could not fetch DNS information abotu @address', array('@address' => $host));
      $status = 'ldap-test-warning';
    }
    else {
      $dns_result = "$host resolves as $hostname (" . implode(', ', $ip_list) . ')';
    }

    $results[] = array(
      'class' => array($status),
      'data' => array(
        t('DNS Checks'),
        $dns_result,
      ),
    );
  }


  //
  // Test 3 - Make a simple TCP connection to the server and port.
  // 
  // If this test fails, then it's probably a connectivity issue.
  //
  if (!empty($host)) {
    if (empty($port)) {
      $port = variable_get('simple_ldap_port', '389');
    }
    if (empty($port)) {
      $port = ($proto == 'ldaps') ? '636' : '389';
    }
    $waitTimeoutInSeconds = 5;
    $starttime = microtime(true);
    $fp = @fsockopen($host,(int)$port,$errCode,$errStr,$waitTimeoutInSeconds);
    $stoptime = microtime(true);

    $connect_test = ($fp) ? 'Connected in @time ms to %host:%port.' : 'Failed to establish connection to %host:%port in @time ms: @error.';

    $results[] = array(
      'class' => ($fp) ? array('ldap-test-ok') : array('ldap-test-error'),
      'data' => array(
        t('TCP Connection Check'),
        t($connect_test, array(
          '%host' => $host, 
          '%port' => $port, 
          '@time' => (int)(($stoptime - $starttime) * 1000),
          '@error' => $errStr,
        )),
      ),
    );

    if ($fp) {
      fclose($fp);
    }

    if (($proto == 'ldaps') && ($port == '389')) {
      $results[] = array(
        'class' => array('ldap-test-warning'),
        'data' => array(
          t('PROTOCOL MISMATCH'),
          t('Attempting to connect with SSL/TLS to default unencrypted port.'),
        ),
      );
    }
    if (($proto == 'ldap') && ($port == '636')) {
      $results[] = array(
        'class' => array('ldap-test-warning'),
        'data' => array(
          t('PROTOCOL MISMATCH'),
          t('Attempting to connect without encryption to default LDAP SSL port.'),
        ),
      );
    }
  }

  //
  // Test 4 - Try to bind to the server
  //
  $error = '';
  try{
    $server = SimpleLdapServer::singleton();
  }
  catch (SimpleLdapException $e) {
    $error = $e->getMessage();
    dpm($e);
  }

  if ($server->bound) {
    $results[] = array(
      'class' => array('ldap-test-ok'),
      'data' => array(
        t('Bind to Server'),
        t('Success'),
      ),
    );
  } 
  else {
    $results[] = array(
      'class' => array('ldap-test-error'),
      'data' => array(
        t('Bind to Server'),
        t('Failed with error: @error', array('@error' => $error)),
      ),
    );
  }

  //
  // Test 6 - Load the RootDSE to share some basic data about the server
  //
  try {
    $rootdse = $server->__get('rootdse');
  }
  catch (SimpleLdapException $e) {
    $rootdse = array();
  }

  if ($rootdse) {
    $results[] = array(
      'class' => array('ldap-test-ok'),
      'data' => array(
        t('Base DNs'),
        theme('item_list', array('items' => $rootdse['namingcontexts'])),
      ),
    );
  }
  else {
    $results[] = array(
      'class' => array('ldap-test-error'),
      'data' => array(
        t('Base DNs'),
        t('Could not fetch server information.'),
      ),
    );
  }

  //
  // Test 7 - Pull the list of supported ObjectClasses.
  //
  $error = '';  
  try {
    $objectclasses = $server->schema->get('objectclasses');
  }
  catch (SimpleLdapException $e) {
    $error = $e->getMessage();
  }
  if (empty($objectclasses)) {
    $results[] = array(
      'class' => array('ldap-test-warning'),
      'data' => array(
        t('Object Classes'),
        t('No object classes found. ' . $error),
      ),
    );
  }
  else {
    $results[] = array(
      'class' => array('ldap-test-ok'),
      'data' => array(
        t('Object Classes'),
        theme('item_list', array('items' => array_map('_simple_ldap_objectclass_map', $objectclasses))),
      ),
    );
  }


  // 
  // Generate the report
  //
  $header = array(
    'Test', 'Result',
  );

  $table = array(
    'header' => $header,
    'rows' => $results,
    'attributes' => array(
      'class' => array('ldap-report'),
      'id' => 'simple-ldap-debug-report',
    ),

  );

  drupal_add_css(drupal_get_path('module', 'simple_ldap') . '/simple_ldap.css');
  return theme('table', $table);
}

function _simple_ldap_objectclass_map($value) {
  $result =  $value['name'] . ": (" . $value['oid'] . ')';
  if (array_key_exists('desc', $value)) {
    $result .= ': ' . $value['desc'];
  }
  return $result;
}
