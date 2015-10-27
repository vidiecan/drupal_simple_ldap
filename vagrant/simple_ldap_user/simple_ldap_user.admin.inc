<?php
/**
 * @file
 * Functions for Simple LDAP User admin interface.
 */

/**
 * Simple LDAP User configuration form.
 */
function simple_ldap_user_admin($form, &$form_state) {
  // If we're the one's doing password management, we have a hook_form_FORM_ID_alter() to include. 
  require_once DRUPAL_ROOT . '/' . variable_get('password_inc', 'includes/password.inc');

  $form = array();

  // Get an LDAP server object.
  $server = SimpleLdapServer::singleton();

  // Verify LDAP server connectivity.
  if (!$server->bind()) {
    drupal_set_message(t('Unable to bind to the LDAP server.') . ' ' . l(t('Check the server configuration.'), 'admin/config/people/simple_ldap'), 'warning');
    return $form;
  }

  // String to append to items disabled by $server->readonly.
  $disabled_note = $server->readonly ? ' (' . t('Disabled by LDAP Server configuration.') . ')' : '';

  // Generate a list of object classes supported by the server.
  $objectclasses = $server->schema->get('objectclasses');
  foreach ($objectclasses as $key => $objectclass) {
    $objectclasses[$key] = $objectclass['name'];
  }
  asort($objectclasses);

  // Derive directory-specific values to use in the form.
  switch ($server->type) {
    case 'Active Directory':
      $readonly = TRUE;
      $objectclass_selected = simple_ldap_user_variable_get('simple_ldap_user_objectclass', NULL, TRUE);
      $attribute_name_selected = simple_ldap_user_variable_get('simple_ldap_user_attribute_name', NULL, TRUE);
      $attribute_mail_selected = simple_ldap_user_variable_get('simple_ldap_user_attribute_mail', NULL, TRUE);
      $attribute_pass_selected = simple_ldap_user_variable_get('simple_ldap_user_attribute_pass', NULL, TRUE);
      $password_hash_selected = simple_ldap_user_variable_get('simple_ldap_user_password_hash', NULL, TRUE);
      $attribute_rdn_selected = simple_ldap_user_variable_get('simple_ldap_user_attribute_rdn', NULL, TRUE);

      // Generate a list of attributes for the selected objectclass.
      $attributes = array(
        $attribute_name_selected => $attribute_name_selected,
        $attribute_mail_selected => $attribute_mail_selected,
        $attribute_pass_selected => $attribute_pass_selected,
        $attribute_rdn_selected => $attribute_rdn_selected,
      );
      break;

    case 'OpenLDAP':
    default:
      $readonly = FALSE;
      $objectclass_selected = isset($form_state['values']['simple_ldap_user_objectclass']) ? $form_state['values']['simple_ldap_user_objectclass'] : simple_ldap_user_variable_get('simple_ldap_user_objectclass');
      $attribute_name_selected = isset($form_state['values']['simple_ldap_user_attribute_name']) ? $form_state['values']['simple_ldap_user_attribute_name'] : simple_ldap_user_variable_get('simple_ldap_user_attribute_name');
      $attribute_mail_selected = isset($form_state['values']['simple_ldap_user_attribute_mail']) ? $form_state['values']['simple_ldap_user_attribute_mail'] : simple_ldap_user_variable_get('simple_ldap_user_attribute_mail');
      $attribute_pass_selected = isset($form_state['values']['simple_ldap_user_attribute_pass']) ? $form_state['values']['simple_ldap_user_attribute_pass'] : simple_ldap_user_variable_get('simple_ldap_user_attribute_pass');
      $password_hash_selected = simple_ldap_user_variable_get('simple_ldap_user_password_hash');
      $attribute_rdn_selected = simple_ldap_user_variable_get('simple_ldap_user_attribute_rdn');

      // Generate a list of attributes for the selected objectclass.
      $attributes = array();
      foreach ($objectclass_selected as $objectclass) {
        try {
          $result = $server->schema->attributes($objectclass, TRUE);
          foreach ($result as $attribute) {
            $attributes[strtolower($attribute)] = $attribute;
          }
        } catch (SimpleLdapException $e) {
          // Just absorb the exception. This means that an objectclass was
          // specified that does not exist on the server. Just don't add any
          // attributes to the list in this case.
        }
      }
      asort($attributes);
  }

  $form['user'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Users'),
  );

  $form['user']['simple_ldap_user_basedn'] = array(
    '#type' => 'textfield',
    '#title' => t('Base DN'),
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_basedn'),
    '#required' => TRUE,
    '#description' => t('The Base DN that will be searched for user accounts.'),
  );

  $form['user']['simple_ldap_user_scope'] = array(
    '#type' => 'radios',
    '#title' => t('Search scope'),
    '#options' => array(
      'sub' => t('Subtree') . ' - ' . t('Search the base DN and all of its children for user accounts.'),
      'one' => t('One-level') . ' - ' . t('Do not include children of the base DN while searching for user accounts.'),
    ),
    '#required' => TRUE,
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_scope'),
  );

  $form['user']['simple_ldap_user_objectclass'] = array(
    '#type' => 'select',
    '#title' => t('User objectClass'),
    '#options' => $objectclasses,
    '#default_value' => $objectclass_selected,
    '#required' => TRUE,
    '#multiple' => TRUE,
    '#size' => 10,
    '#description' => t('Which LDAP objectClass should be used when searching for, or creating, a user.'),
    '#disabled' => $readonly,
    '#ajax' => array(
      'callback' => 'simple_ldap_user_objectclass_ajax',
      'wrapper' => 'simple-ldap-user-attributes',
    ),
  );

  $form['user']['simple_ldap_user_attribute_name'] = array(
    '#type' => 'select',
    '#title' => t('Username attribute'),
    '#prefix' => '<div id="simple-ldap-user-attributes">',
    '#options' => $attributes,
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute should be mapped to a Drupal username.') . ' ' . t('This is commonly "cn" or "uid".'),
    '#disabled' => $readonly,
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_name_selected, $attributes)) {
    $form['user']['simple_ldap_user_attribute_name']['#default_value'] = $attribute_name_selected;
  }

  $form['user']['simple_ldap_user_attribute_mail'] = array(
    '#type' => 'select',
    '#title' => t('Email attribute'),
    '#options' => $attributes,
    '#required' => TRUE,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's email address.") . ' ' . t('This is commonly "mail".'),
    '#disabled' => $readonly,
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_mail_selected, $attributes)) {
    $form['user']['simple_ldap_user_attribute_mail']['#default_value'] = $attribute_mail_selected;
  }

  $form['user']['simple_ldap_user_attribute_pass'] = array(
    '#type' => 'select',
    '#title' => t('Password attribute') . $disabled_note,
    '#suffix' => '</div>',
    '#options' => $attributes,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's password.") . ' ' . t('This is only used for password resets, not for authentication, and is commonly "userPassword".'),
    '#disabled' => $readonly || $server->readonly,
    '#empty_value' => FALSE,
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_pass_selected, $attributes)) {
    $form['user']['simple_ldap_user_attribute_pass']['#default_value'] = $attribute_pass_selected;
  }

  $form['user']['simple_ldap_user_password_hash'] = array(
    '#type' => 'select',
    '#title' => t('Password hashing algorithm') . $disabled_note,
    '#options' => SimpleLdap::hashes(),
    '#description' => t('Which encryption algorithm should be used to encrypt passwords when writing to LDAP.'),
    '#disabled' => $readonly || $server->readonly,
    '#default_value' => $password_hash_selected,
    '#empty_value' => 'none',
  );

  // LDAP user admin advanced form.
  $form['advanced'] = array(
    '#type' => 'fieldset',
    '#title' => t('Advanced'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );

  $form['advanced']['simple_ldap_user_filter'] = array(
    '#type' => 'textfield',
    '#title' => t('Search filter'),
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_filter'),
    '#description' => t('This filter will be combined with the normal search filter to find users.') . ' ' . t('This can be used to require a certain attribute be present, for example.'),
  );

  $form['advanced']['simple_ldap_user_source'] = array(
    '#type' => 'radios',
    '#title' => t('Authoritative data source') . $disabled_note,
    '#options' => array(
      'ldap' => t('LDAP'),
      'drupal' => t('Drupal'),
    ),
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_source'),
    '#disabled' => $server->readonly,
    '#description' => t('This determines the behavior of the data sync in the event of a conflict between LDAP and Drupal.'),
  );

  $form['advanced']['simple_ldap_user_sync'] = array(
    '#type' => 'radios',
    '#title' => t('Synchronization trigger'),
    '#options' => array(
      'hook_user_load' => t('Every time a user object is loaded from the database.') . ' (' . t('More real-time, best if there are frequent changes.') . ')',
      'hook_user_login' => t('Every time a user logs in.') . ' (' . t('Less LDAP traffic, best if changes are rare.') . ')',
    ),
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_sync'),
  );

  $form['advanced']['simple_ldap_user_delete_from_ldap'] = array(
    '#type' => 'radios',
    '#title' => t('Delete from LDAP on user delete?'),
    '#options' => array(
      '0' => t('Never'),
      '1' => t('Always'),
    ),
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_delete_from_ldap'),
  );

  // Generate a table to display the attribute map if one is configured.
  $table = '';
  $attribute_map = simple_ldap_user_variable_get('simple_ldap_user_attribute_map');
  if (!empty($attribute_map)) {
    $table = '<table>';
    $table .= '<thead><tr><th>' . t('LDAP attribute') . '</th><th>' . t('Drupal attribute') . '</th></tr></thead>';
    $table .= '<tbody>';
    $class = 'odd';
    foreach ($attribute_map as $ldap_item => $item) {
      $table .= '<tr class="' . $class . '">';
      $table .= '<td>' . $ldap_item . '</td>';
      $table .= '<td>' . implode(' ', $item) . '</td>';
      $table .= '</tr>';
      $class = $class == 'odd' ? 'even' : 'odd';
    }
    $table .= '</tbody></table>';
  }

  $form['advanced']['simple_ldap_user_attribute_map'] = array(
    '#type' => 'item',
    '#title' => t('Attribute map'),
    '#weight' => 10,
    '#description' => $table . t('Additional attribute maps can be specified in @file using @variable.', array('@file' => 'settings.php', '@variable' => '$conf[\'simple_ldap_user_attribute_map\']')) . ' ' . t('See @readme for more details', array('@readme' => 'README.txt')),
  );

  $attribute_map = simple_ldap_user_variable_get('simple_ldap_user_attribute_map');
  if (!empty($attribute_map)) {

    // Generate a list of attribute names from the attribute map. This pulls
    // from the schema to make the human-readable version have the right case.
    $options = array();
    foreach ($attribute_map as $ldap_attr => $drupal_field) {
      $attribute_type = $server->schema->get('attributeTypes', $ldap_attr);
      $options[$ldap_attr] = $attribute_type['name'];
    }
    asort($options);

    $form['advanced']['simple_ldap_user_attribute_rdn'] = array(
      '#type' => 'select',
      '#title' => t('Relative Distinguished Name (RDN) attribute'),
      '#options' => $options,
      '#empty_value' => '',
      '#default_value' => $attribute_rdn_selected,
      '#description' => t('Any of the mapped attributes can be used as the RDN value when provisioning a new LDAP user entry.') . ' ' . t('If set to "None", the Username attribute specified above will be used.'),
      '#disabled' => $readonly,
    );

    $form['advanced']['simple_ldap_user_unique_attribute'] = array(
      '#type' => 'textfield',
      '#title' => t('UUID Attribute (PUID)'),
      '#description' => t('Enter the name of the attribute that remains persistant even through name changes.  Active Directory uses "objectGUID".  OpenLDAP, Apache DS and most others use "entryUUID".'),
      '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_unique_attribute'),
    );
  }

  return system_settings_form($form);
}

/**
 * Handle simple_ldap_user_objectclass ajax calls.
 */
function simple_ldap_user_objectclass_ajax($form, $form_state) {
  return array(
    $form['user']['simple_ldap_user_attribute_name'],
    $form['user']['simple_ldap_user_attribute_mail'],
    $form['user']['simple_ldap_user_attribute_pass'],
  );
}

/**
 * Admin form for mapping Drupal user attributes to LDAP attributes
 */
function simple_ldap_user_profile_map_form($form, $form_state) {
  $form = array();

  // Get an LDAP server object.
  $server = SimpleLdapServer::singleton();

  // Verify LDAP server connectivity.
  if (!$server->bind()) {
    drupal_set_message(t('Unable to bind to the LDAP server.') . ' ' . l(t('Check the server configuration.'), 'admin/config/people/simple_ldap'), 'warning');
    return $form;
  }

  // Pull the available LDAP schemas from the server
  $schema = $server->schema;

  // Pull the LDAP objectClasses selected for users, plus any parent classes.
  $classes = simple_ldap_user_variable_get('simple_ldap_user_objectclass');
  $classes = simple_ldap_user_parent_objectclasses($classes);

  // Pull the fields defined for user profiles
  // ToDo: Support user profile modules
  $user_fields = simple_ldap_user_user_fields();

  $unmapped_required = array();

  // Build a list of available LDAP attributes, grouped by Object Class
  $options[''] = ' - None - ';
  foreach ($classes as $class) { 
    if ($class == 'top') {
      continue;
    }

    // Add a * to must attributes, to indiciate it must be set.
    $ldap_must_attrs = $schema->must($class);
    foreach($ldap_must_attrs as $attribute) {
      $options[$class][strtolower($attribute)] = $attribute . '*';
    }

    if (!empty($ldap_must_attrs)) {
      $unmapped_required += array_combine(array_map('strtolower', $ldap_must_attrs), $ldap_must_attrs); 
    }

    // Add the may attributes later.
    foreach($schema->may($class) as $attribute) {
      $options[$class][strtolower($attribute)] = $attribute;
    }
  }

  // Finally, build the form 
  $form['header'] = array(
    '#type' => 'markup',
    '#markup' => t('<p>Select LDAP attributes to map to the Drupal user fields below.  LDAP attributes marked with an askterisk (*) are required by the LDAP schema and must be assigned to a Drupal fields.  LDAP attributes should be mapped to at most one Drupal fields.</p><p>Username, Email and Password mappings are also done on the User tab.</p>'),
  );
  $form['attributes'] = array(
    '#type' => 'fieldset',
    '#title' => t('Drupal Fields to LDAP Attributes'),
    '#collapsible' => TRUE,
    '#collapsed' => FALSE,
  );

  foreach($user_fields as $key => $field) {
    // Removed mapped fields from the list of MUST attributes.
    $mapped_attribute = simple_ldap_user_variable_get('simple_ldap_user_attribute_' . $key);
    unset($unmapped_required[$mapped_attribute]);
    // Add a form field.
    $form['attributes']['simple_ldap_user_attribute_' . $key] = array(
      '#type' => 'select',
      '#title' => $field['label'],
      '#description' => $field['description'],
      '#options' => $options,
      '#required' => $field['required'],
      '#default_value' => $mapped_attribute,
    );
  }

  // Give a warning about unmapped attributes.
  if (!empty($unmapped_required)) {
    drupal_set_message(t('The following attributes are required by the selected user object class(es), but are not mapped. They should be mapped here or given default values in !hook.  If they are not set, writes to LDAP may fail with an %violation. !list', array(
        '!hook' => '<code>hook_simple_ldap_user_to_ldap_alter()</code>',
        '!list' => theme('item_list', array('items' => $unmapped_required)),
        '%violation' => t('object class violation'),
      )), 'warning'
    );
  }

  $attribute_map = simple_ldap_user_variable_get('simple_ldap_user_attribute_map');
  $delimiter_options = array(
    'array' => t('Multivalue field (array)'),
    'cr' => t('Multiline field (\\r)'),
    'dollar' => t('Dollar sign ($)'),
  );

  foreach ($attribute_map as $key => $value) {
    if (is_array($value) && count($value) > 1) {
      $form['delimiters']['simple_ldap_user_delimiter_' . $key] = array(
        '#type' => 'select',
        '#title' => $key,
        '#options' => $delimiter_options,
        '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_delimiter_' . $key),
      );
    }
  }
  if (!empty($form['delimiters'])) {
    $form['delimiters'] += array(
      '#type' => 'fieldset',
      '#title' => t('Multiple Value Field Delimiters'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );
  }

  $form['extra_attrs_fieldset'] = array(
    '#type' => 'fieldset',
    '#title' => t('Load Additional Attributes'),
    '#collapsible' => TRUE,
    '#collapsed' => FALSE,
  );
  $form['extra_attrs_fieldset']['simple_ldap_user_extra_attrs'] = array(
    '#type' => 'select',
    '#title' => t('Extra Attributes'),
    '#description' => t('Select additional unmapped attributes to load.'),
    '#options' => $options,
    '#default_value' => simple_ldap_user_variable_get('simple_ldap_user_extra_attrs'),
    '#multiple' => TRUE,
    '#attached' => array( 
      'css' => array(
        drupal_get_path('module', 'simple_ldap_user') . '/simple_ldap_user_admin.css',
      ),
    ),
  );

  $form = system_settings_form($form);
  $form['#submit'][] = 'simple_ldap_user_profile_map_form_submit';

  return $form;
}

function simple_ldap_user_profile_map_form_submit($form, &$form_state) {
  $user_fields = array_keys(simple_ldap_user_user_fields());
  $attribute_map = array();
  foreach ($form_state['values'] as $key => $value) {
    if ((strpos($key, 'simple_ldap_user_attribute_') !== FALSE) && !empty($value)) {
      $field = substr($key, 27);
      $attribute_map[$value][] = $field;
    }
    if ((strpos($key, 'simple_ldap_user_delimiter_') !== FALSE) && !empty($value)) {
      $attr = substr($key, 27);
      if ($value == 'array') {
        unset($attribute_map[$attr]['#delimiter']);
      } 
      else {
        $attribute_map[$attr]["#delimiter"] = ($value == 'cr') ? "\r" : '$';
      }
    }
  }

  // Remove #delimiter from singleton values    
  foreach($attribute_map as $key => &$values) {
    if (array_key_exists('#delimiter', $values)) {
      if (count($values) == 2) {
        unset($values['#delimiter']);
        variable_del('simple_ldap_user_delimiter_' . $key);
      }
    }
  }

  variable_set('simple_ldap_user_attribute_map', $attribute_map);
}

/**
 * Form to handle mass user import.
 */
function simple_ldap_user_import($form, &$form_state) {
  $form = array();

  // Get LDAP Configuration.
  $server = SimpleLdapServer::singleton();
  $basedn = simple_ldap_user_variable_get('simple_ldap_user_basedn');
  $scope = simple_ldap_user_variable_get('simple_ldap_user_scope');
  $attribute_name = strtolower(simple_ldap_user_variable_get('simple_ldap_user_attribute_name'));
  $filter = '(&(' . $attribute_name . '=*)' . SimpleLdapUser::filter() . ')';

  // Get a list of users that would be imported.
  $ldap_users = SimpleLdap::clean($server->search($basedn, $filter, $scope, array('dn', $attribute_name)));

  // Reformat the LDAP array.
  $users = array();
  foreach ($ldap_users as $dn => $entry) {
    $users[$entry[$attribute_name][0]] = $entry[$attribute_name][0];
  }
  asort($users);

  $form['users'] = array(
    '#type' => 'checkboxes',
    '#title' => t('Import these users') . ' (' . count($users) . ')',
    '#options' => $users,
    '#default_value' => array_keys($users),
    '#checkall' => TRUE,
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Import'),
  );

  return $form;
}

/**
 * Submit handler for mass user import.
 */
function simple_ldap_user_import_submit($form, &$form_state) {
  $operations = array();
  foreach ($form_state['input']['users'] as $user) {
    if (!empty($user)) {
      $operations[] = array('simple_ldap_user_import_user', array($user));
    }
  }

  $form_state['redirect'] = 'admin/people';

  $batch = array(
    'operations' => $operations,
    'finished' => 'simple_ldap_user_import_finished',
    'file' => drupal_get_path('module', 'simple_ldap_user') . '/simple_ldap_user.admin.inc',
  );

  batch_set($batch);
}

/**
 * Batch process function for mass user import.
 */
function simple_ldap_user_import_user($name, &$context) {
  $drupal_user = simple_ldap_user_load_or_create_by_name($name);
  $context['message'] = 'Importing ' . $name;
  $context['results'][$name] = !empty($drupal_user);
}

/**
 * Called when the mass user import batch is finished.
 */
function simple_ldap_user_import_finished($success, $results, $operations) {
  if ($success) {
    drupal_set_message(t('Imported @count users from LDAP.', array('@count' => count($results))));
  }
  else {
    drupal_set_message(t('A problem occurred while importing the users from LDAP.'));
  }
}
