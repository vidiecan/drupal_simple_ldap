<?php
// From http://stackoverflow.com/a/2510540
function _formatBytes($size, $precision = 2)
{
    $base = log($size) / log(1024);
    $suffixes = array('', 'k', 'M', 'G', 'T');   

    return round(pow(1024, $base - floor($base)), $precision) . $suffixes[floor($base)];
}

/**
 * Implementation of hook_drush_command()
 */
function simple_ldap_user_drush_command() {
  $items = array();
  
  $items['ldap-export-all'] = array(
    'description' => 'Export all users in Drupal that are not in LDAP',
    'callback' => 'simple_ldap_user_drush_export_all',
    'options' => array(
      'found-count' => 'Stop the run after aa certain number of users are found in LDAP.  (Useful to prevent memory exhustion.)', 
      'missing-count' => 'Stop the run after aa certain number of users are not found in LDAP.  (Useful to prevent memory exhustion.)', 
    ),
  );
  $items['ldap-check-all'] = array(
    'description' => 'Check all users in Drupal are in LDAP',
    'callback' => 'simple_ldap_user_drush_check_all',
    'options' => array(
      'found-count' => 'Stop the run after aa certain number of users are found in LDAP.  (Useful to prevent memory exhustion.)', 
      'missing-count' => 'Stop the run after aa certain number of users are not found in LDAP.  (Useful to prevent memory exhustion.)', 
    ),
  );
  $items['ldap-mail-collison-check'] = array(
    'description' => 'Check for two users who have the same email address',
    'callback' => '_simple_ldap_user_check_existing_by_mail',
  );
  $items['ldap-update-all-puids'] = array(
    'description' => 'For all users in Drupal, update the authmap with the PUID from LDAP.',
    'callback' => 'simple_ldap_user_drush_update_all_puids',
  );
  return $items;
}

function simple_ldap_user_drush_check_all() {
  return simple_ldap_user_drush_scan_all();
}

function simple_ldap_user_drush_export_all() {
  return simple_ldap_user_drush_scan_all('_simple_ldap_user_drush_found', '_simple_ldap_user_drush_missing');
}

function simple_ldap_user_drush_update_all_puids() {
  // Check there is something to map.
  $puid_attr = strtolower(variable_get('simple_ldap_user_unique_attribute', ''));
  $attribute_name = strtolower(simple_ldap_user_variable_get('simple_ldap_user_attribute_name'));
  $attribute_mail = strtolower(simple_ldap_user_variable_get('simple_ldap_user_attribute_mail'));

  $found_count = $missing_count = $warning_count = 0;

  if (!$puid_attr) {
    drush_log(dt('No PUID attribute set.'), 'warning');
    return;
  }

  // For each user, fetch the LDAP record and update the authmap
  $result = db_query("SELECT uid,name,mail FROM {users}");
  while ($account = $result->fetchAssoc()) {
    $ldap_user = SimpleLdapUser::singleton($account['name']);
    if (!$ldap_user->exists) {
      $missing_count++;
      continue;
    }
    if (strcasecmp($ldap_user->{$attribute_name}[0], $account['name'])) {
      drush_log(dt('User "@username" found, but not by name.  Skipping.', array('@username' => $account['name'])), 'warning');
      $warning_count++;
      continue;
    }
    if (strcasecmp($ldap_user->{$attribute_mail}[0], $account['mail'])) {
      drush_log(dt('Mail attribute for user "@username" does not match: @drupal_mail != @ldap_mail', 
        array(
          '@username' => $account['name'],
          '@drupal_mail' => $account['mail'],
          '@ldap_mail' => $ldap_user->{$attribute_mail}[0],
        ), 'warning')
      );
      $warning_count++;
      continue;
    }

    // If no issues, write to the authmap
    db_merge('authmap')->key(array(
      'uid' => $account['uid'],
      'module' => 'simple_ldap',
    ))->fields(array('authname' => $ldap_user->{$puid_attr}[0]))->execute();
    $found_count++;

  }

  if ($found_count) {
    drush_log(dt('Updated @found PUIDs from LDAP records.', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'notice');
  } 
  if ($missing_count) {
    drush_log(dt('Could not find @missing users in LDAP.', array('@missing' => format_plural($missing_count, '1 user', '@count users'))), 'notice');
  } 
  if ($warning_count) {
    drush_log(dt('Detected @warning with anomalous entries.', array('@warning' => format_plural($warning_count, '1 user', '@count users'))), 'warning');
  } 
}

function _simple_ldap_user_check_existing_by_mail() {
  $name_attr = variable_get('simple_ldap_user_attribute_name', 'uid');
  $scope = variable_get('simple_ldap_user_scope', 'sub');
  $base_dn = variable_get('simple_ldap_user_basedn', NULL);
  if (!$base_dn) {
    drush_log(dt('No base DN set.'), 'error');
    return;
  }

  $server = SimpleLdapServer::singleton();
  if (!$server) {
    drush_log(dt('Could not connect to server.'), 'error');
    return;
  }

  $user_total_count = db_query("SELECT COUNT(*) AS count FROM {users}")->fetchAssoc();
  $user_total_count = $user_total_count['count'];
  $user_count = $collisions = 0;

  $attrs = array($name_attr);
  $result = db_query("SELECT uid,name,mail FROM {users}");
  while($row = $result->fetchAssoc()) {

    $user_count++;
    if (($user_count % 1024) == 0) {
      gc_collect_cycles();
      printf("  %d%% complete (%s u: %d, c: %d)...\r", (int)(100 * $user_count / $user_total_count), _formatBytes(memory_get_usage()), $user_count, $collisions);
    }

    $filter = 'mail=' . $row['mail'];
    $ldap_records = $server->search($base_dn, $filter, $scope, $attrs);

    if ($ldap_records['count'] > 1) {
      $count = $ldap_records['count'];
      unset($ldap_records['count']);
      $names = array();
      foreach($ldap_records as $n) {
        $names[] = $n[$name_attr][0];
      }
      $data = array(
        '@email' => $row['mail'],
        '@count' => $count,
        '@users' => implode(', ', $names),
      );
      drush_log(dt('Email address @email used by @count users: @users', $data), 'error');
      $collisions++;
      continue;
    }

    if ($ldap_records['count'] && strtolower($ldap_records[0][$name_attr][0]) !== strtolower($row['name'])) {
      $data = array(
        '@email' => $row['mail'],
        '@drupal_name' => $row['name'],
        '@ldap_name' => $ldap_records[0][$name_attr][0],
      );
      drush_log(dt('Username for email address @email does not match LDAP.  Drupal: @drupal_name LDAP: @ldap_name', $data), 'error');
      $collisions++;
      continue;
    }
  }
  printf("100%% complete (%s / %s)...\nDone\n", _formatBytes(memory_get_usage()), _formatBytes(memory_get_peak_usage()));
  if ($collisions) {
    drush_log(dt('Found @bad collisions among @count users.', array('@bad' => $collisions, '@count' => $user_count)), 'error');
  }
  else {
    drush_log(dt('No collisions found among all @count users.', array('@count' => $user_count)), 'ok');
  }
}

function _simple_ldap_user_drush_found($authname, $user, $ldap_user) {
  if (empty($authname)) {
    $puid_attr = strtolower(variable_get('simple_ldap_user_unique_attribute', ''));
    $account = user_load($user['uid'], TRUE);
    $authname = ($puid_attr) ? $ldap_user->{$puid_attr}[0] : $ldap_user->dn;
    user_set_authmaps($account, array('authname_simple_ldap' => $authname));
  }
}

function _simple_ldap_user_drush_missing($authname, $user) {
  $dummy_context = array();

  // Make sure we don't have an authmap collision.
  $am_entry = db_query("SELECT uid,authname FROM {authmap} WHERE authname=:puid AND module='simple_ldap'", 
    array(':puid' => $user['authname'])
  )->fetchAssoc();
  if (!empty($am_entry['uid']) && ($am_entry['uid'] != $user['uid'])) {
    drush_log(dt('    PUID COLLISION: Authname @authname used by both UIDs @this and @that.  Skipping @user.', 
      array(
        '@this' => $user['uid'],
        '@that' => $am_entry['uid'],
        '@authname' => $user['authname'],
        '@user' => $user['name'],
      )), 
      'error'
    );
    return;
  }

  drush_log(dt('Provisioning @user', array('@user' => $user['name'])), 'notice');
  simple_ldap_user_export_user($user['uid'], $dummy_context);
}

function simple_ldap_user_drush_scan_all($found_callback = NULL, $not_found_callback = NULL) {
  // Get the default search params.
  $name_attr = variable_get('simple_ldap_user_attribute_name', 'uid');
  $scope = variable_get('simple_ldap_user_scope', 'sub');
  $base_dn = variable_get('simple_ldap_user_basedn', NULL);
  if (!$base_dn) {
    drush_log(dt('No base DN set.'), 'error');
    return;
  }
  $attrs = array($name_attr);

  $server = SimpleLdapServer::singleton();
  if (!$server) {
    drush_log(dt('Could not connect to server.'), 'error');
    return;
  }

  // Get ready for the run.
  $found_limit = drush_get_option('found-count');
  $missing_limit = drush_get_option('missing-count');

  if ($found_limit) {
    drush_log(dt('Will exit after @count records are found.', array('@count' => $found_limit)), 'notice');
  }

  if ($missing_limit) {
    drush_log(dt('Will exit after @count records are not found.', array('@count' => $missing_limit)), 'notice');
  }

  $user_total_count = db_query("SELECT COUNT(*) AS count FROM {users}")->fetchAssoc();
  $user_total_count = $user_total_count['count'];
  $puid_attr = strtolower(variable_get('simple_ldap_user_unique_attribute', ''));
  drush_log(dt('Using PUID Attr: @puid', array('@puid' => empty($puid_attr) ? '(none)' : $puid_attr)), 'notice');
  $sql = "SELECT u.*,a.authname FROM {users} u LEFT JOIN {authmap} a ON a.uid=u.uid AND a.module='simple_ldap'";

  $result = db_query($sql);
  if (!$result) {
    drush_log(dt('Failed to fetch list of users from Drupal database.'), 'error');
    return;
  }

  $bad_count = $user_count = $found_count = $missing_count = 0;

  while($user = $result->fetchAssoc()) {
    if ($user['uid'] < 2) {
      continue;
    }

    $user_count++;
    if (($user_count % 1024) == 0) {
      // Clear caches we won't need.
      entity_get_controller('file')->resetCache();
      entity_get_controller('user')->resetCache();
      // Clean up memory.
      gc_collect_cycles();
      printf("  %d%% complete (%s m: %d, f: %d)...\r", (int)(100 * $user_count / $user_total_count), _formatBytes(memory_get_usage()), $missing_count, $found_count);
    }

    if (strpos($user['name'], ',') !== FALSE) {
      drush_log(dt('User %username contains illegal characters.  Skipping.', array('%username' => $user['name'])), 'error');
      $bad_count++;
      continue;
    }

    $ldap_user = SimpleLdapUser::singleton($user['name']);
    $filter = 'mail=' . $user['mail'];
    $ldap_users_by_mail = $server->search($base_dn, $filter, $scope, $attrs);
    if ($ldap_users_by_mail['count'] > 1) {
      drush_log(dt('Multiple LDAP users have the email address @email.  Skipping.', array('@email' => $user['mail'])), 'error');
      continue;
    }

    if ($ldap_users_by_mail['count'] && strtolower($ldap_users_by_mail[0][$name_attr][0]) !== strtolower($user['name'])) {
      drush_log(dt('Drupal User @drupal_user and LDAP record @ldap_name use the same email @email. Skipping.',
        array(
          '@drupal_user' => $user['name'],
          '@ldap_name' => $ldap_users_by_mail[0][$name_attr][0],
          '@email' => $user['mail'],
        )
      ), 'error');
      continue;
    }

    if (($ldap_user->exists)) {
      drush_log(dt("Found @user (@dn)", array('@user' => $user['name'], '@dn' => $ldap_user->dn)), 'debug');

      if (!empty($puid_attr) && ($user['authname'] != $ldap_user->{$puid_attr}[0])) {
        drush_log(dt("    User @user: Authmap entry does not match PUID: Authmap: @authname LDAP: @puid", 
          array(
            '@authname' => empty($user['authname']) ? "(empty)" : $user['authname'], 
            '@puid' => empty($ldap_user->{$puid_attr}[0]) ? "(empty)" : $ldap_user->{$puid_attr}[0],
            '@user' => $user['name'],
          )
        ), 'warning');
      }

      if (!empty($ldap_user->mail[0]) && strtolower($ldap_user->mail[0]) !== strtolower($user['mail'])) {
        drush_log(dt('    User @user has Drupal email @drupal_mail and LDAP email @ldap_mail.  Skipping.',
          array(
            '@user' => $user['name'],
            '@drupal_mail' => $user['mail'],
            '@ldap_mail' => $ldap_user->mail[0],
          )
        ), 'warning');
        continue;
      }

      if (!empty($found_callback)) {
        $found_callback($user['authname'], $user, $ldap_user);
      }
      $found_count++;
      if (($found_limit) && ($found_count >= $found_limit)) {
        drush_log(dt('Exiting after finding @found records.', array('@found' => $found_limit)), 'warning');
        break;
      }
    }
    else {
      if (!empty($not_found_callback)) {
        $not_found_callback($user['authname'], $user);
      }
      else {
         drush_log(dt("Missing @user (@dn)", array('@user' => $user['name'], '@dn' => $user['authname'])), 'notice');
      }
      $missing_count++;
      if (($missing_limit) && ($missing_count >= $missing_limit)) {
        drush_log(dt('Exiting after not finding @missing records.', array('@missing' => $missing_limit)), 'warning');
        break;
      }
    }
    SimpleLdapUser::reset();
    unset($user);
    unset($ldap_user);
  }
  printf("100%% complete (%s / %s)...\nDone\n", _formatBytes(memory_get_usage()), _formatBytes(memory_get_peak_usage()));

  if ($missing_count > 0) {
    drush_log(dt('Found @found with LDAP records.', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'warning');
    drush_log(dt('Missing @missing.', array('@missing' => format_plural($missing_count, '1 user', '@count users'))), 'warning');
    drush_log(dt('Found @bad with unusable usernames.', array('@bad' => format_plural($bad_count, '1 user', '@count users'))), 'warning');
    drush_log(dt("Run with --verbose to see the list of missing users."), 'warning');
  } else {
    drush_log(dt('Found all @found', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'ok');
  }
}
