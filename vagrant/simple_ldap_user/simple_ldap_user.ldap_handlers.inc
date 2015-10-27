<?php

function simple_ldap_user_default_import_handler(&$edit, $info, $items, $ldap_attr, $language) {
  watchdog('SimpleLDAP', 'Cannot import: Unsupported field of type %type.', array('%type', $info['type']), WATCHDOG_NOTICE);
}

function simple_ldap_user_default_export_handler(&$value, $field_info, $items) {
  watchdog('SimpleLDAP', 'Cannot export: Unsupported field of type %type.', array('%type', $info['type']), WATCHDOG_NOTICE);
}
/**
 * Converts "basic" data types.  That is, anything that can be loaded and saved with a simple
 * string keyed to 'value' without format translation.  This would include most textfields and 
 * number fields, but not timestamps, which need to be translated to/from LDAP's time format,
 * or Taxonomy Terms that need to be mapped to a TID in Drupal.
 *
 * @param array &$edit 
 *   The $edit array to modify if the field needs to be saved.  Will be passed to user_save().
 *
 * @param array $info 
 *   Drupal field description as returned by field_info_field().
 * 
 * @param array $items
 *   The current value of the Drupal field.
 * 
 * @param array $ldap_attr
 *   The values in the LDAP attribute.  Includes $ldap_attr['count'].
 * 
 * @param string $language
 */
function simple_ldap_user_translate_basic_ldap_to_drupal(&$edit, $info, $items, $ldap_attr, $language) {
  // Synchronize types that go in ['value'] and are strings
  $dirty = FALSE;
  for ($i = 0; $i < $ldap_attr['count']; $i++) {
    if ($i < $info['cardinality'] || $info['cardinality'] == FIELD_CARDINALITY_UNLIMITED) {
      $edit[$info['field_name']][$language][$i]['value'] = $ldap_attr[$i];
      if ($items[$i]['value'] != $ldap_attr[$i]) {
        $dirty = TRUE;
      }
    }
  }

  // Check if any changes were actually made.
  if (!$dirty) {
    unset($edit[$info['field_name']]);
  }
}

function simple_ldap_user_translate_basic_drupal_to_ldap(&$value, $field_info, $items) {
  if (is_array($items)) {
    foreach ($items as $item) {
      if (isset($item['value'])) {
        $value[] = $item['value'];
      }
    }
  }  
}

function simple_ldap_user_translate_datetime_ldap_to_drupal(&$edit, $info, $items, $ldap_attr, $language) {
  // Synchronize types that go in ['value'] and are strings
  $dirty = FALSE;
  for ($i = 0; $i < $ldap_attr['count']; $i++) {
    if ($i < $info['cardinality'] || $info['cardinality'] == FIELD_CARDINALITY_UNLIMITED) {
      $formatted_time = date('Y-m-d H:i:s', strtotime($ldap_attr[$i]));
      $edit[$info['field_name']][$language][$i] = array(
        'value' => $formatted_time,
        'timezone' => 'UTC',
        'timezone_db' => 'UTC',
      );

      if ($items[$i]['value'] != $formatted_time) {
        $dirty = TRUE;
      }
    }
  }

  // Check if any changes were actually made.
  if (!$dirty) {
    unset($edit[$info['field_name']]);
  }
}

function simple_ldap_user_translate_datetime_drupal_to_ldap(&$value, $field_info, $items) {
  if (is_array($items)) {
    foreach ($items as $item) {
      if (isset($item['value'])) {
        $value[] = date('YmdHis', $item['value']) . 'Z';
      }
    }
  }  
}

function simple_ldap_user_translate_file_ldap_to_drupal(&$edit, $info, $items, $ldap_attr, $language) {
  $dirty = FALSE;
  $instance_info = field_info_instance('user', $info['field_name'], 'user');

  for ($i = 0; $i < $ldap_attr['count']; $i++) {
    if (empty($items[$i]) && empty($ldap_attr[$i])) {
      // Both empty, continue
      continue;
    }
    if (
      ($items[$i]['filesize'] == strlen($ldap_attr[$i])) && 
      md5($ldap_attr[$i]) == md5(file_get_contents($items[$i]['uri']))
    ) {
      // Files are identical, skip.
      continue;
    }

    $filename = file_default_scheme() . '://' . $instance_info['settings']['file_directory'] . '/' . $info['field_name'] . '.jpg';
    $edit[$info['field_name']][$language][$i] = (array)file_save_data($ldap_attr[$i], $filename, FILE_EXISTS_RENAME);
  }
}

function simple_ldap_user_translate_file_drupal_to_ldap(&$value, $field_info, $items) {
  if (is_array($items)) {
    foreach ($items as $item) {
      foreach ($items as $item) {
        $file = file_load($item['fid']);
        $value[] = file_get_contents($file->uri);
      }
    }
  }  
}

/**
 * Map the value(s) in the LDAP attr to one or more TIDs.  This will *NOT* create new Terms if they
 * are not present, and this funciton does not understand the term's heirarchy.  If the term's name 
 * is ambiguous, the one selected depends on the order the database returns them.
 */ 
function simple_ldap_user_translate_term_ldap_to_drupal(&$edit, $info, $items, $ldap_attr, $language) {
	$tids = array();

  $count = $ldap_attr['count'];
  unset($ldap_attr['count']);

  // Collect the TIDs that match the terms in the LDAP field
  // Limit the search to valid vocabularies this field may use.
	for ($i = 0; $i < $count; $i++) {
		$tids = simple_ldap_user_find_tids_by_terms($info, $ldap_attr);
	}

  // Don't save if the existing list matches the LDAP list
  if (($items == $tids) || count($items) == count($tids)) {
    $local_tids = array_map('_simple_ldap_user_tid_value', empty($items) ? array() : $items);
    $ldap_tids = array_map('_simple_ldap_user_tid_value', empty($tids) ? array() : $tids);

    sort($local_tids);
    sort($ldap_tids);

    if ($local_tids === $ldap_tids) {
      return;
    }
  }
  $edit[$info['field_name']][$language] = $tids;
}

function simple_ldap_user_translate_term_drupal_to_ldap(&$value, $field_info, $items) {
  if (is_array($items)) {
    $tids = array();
    // Collect the TIDs.
    foreach ($items as $item) {
      $tids = array_merge($tids, array_values($item));
    }
    // Load the terms by TID
    $terms = taxonomy_term_load_multiple($tids);

    // Save the term.
    foreach ($terms as $term) {
      $value[] = $term->name;
    }
  }  
}

// Helper function used by array_map() above.
function _simple_ldap_user_tid_value($val) {
  return $val['tid'];
}

// Search the database to collect the TIDs matching the terms.
function simple_ldap_user_find_tids_by_terms($info, $terms) {
  if (empty($terms)) {
    return array();
  }

  // Find all the valid vocabularies
  $vocab_machine_names = array();
  foreach ($info['settings']['allowed_values'] as $allowed_vocab) {
    $vocab_machine_names[] = $allowed_vocab['vocabulary'];
  }

  // Build the SQL
  $sql = "SELECT tid FROM {taxonomy_term_data} td WHERE td.name IN (:terms)";
  if (!empty($vocab_machine_names)) {
    $sql .= " AND vid IN (SELECT vid FROM {taxonomy_vocabulary} WHERE machine_name IN (:machine_names))";
  }

  // One query is all we need.
  $db_result = db_query($sql, array(':terms' => $terms, ':machine_names' => $vocab_machine_names));
  $results = array();
  foreach($db_result as $record) {
    $results[] = (array)$record;
  }

  return $results;
}

function simple_ldap_user_translate_url_ldap_to_drupal(&$edit, $info, $items, $ldap_attr, $language) {
  // Synchronize types that go in ['value'] and are strings
  $dirty = FALSE;
  for ($i = 0; $i < $ldap_attr['count']; $i++) {
    if ($i < $info['cardinality'] || $info['cardinality'] == FIELD_CARDINALITY_UNLIMITED) {
      $new_url = array();
      $new_url['attributes'] = array();
      preg_match('/(<a.*href="(.*?)".*>(.*)<\/a>|(.*))/', $ldap_attr[$i], $matches);
      if (!empty($matches[4])) {
        $new_url['value'] = $matches[4];
        $new_url['title'] = '';
      }
      else {
        $new_url['title'] = $matches[3];
        $new_url['value'] = $matches[2];
      }
      // Still save it in edit, in case only one of the set changed.
      $edit[$info['field_name']][$language][$i] = $new_url;
      if ($items[$i] != $new_url) {
        $dirty = TRUE;
      }
    }
  }

  // Check if any changes were actually made.
  if (!$dirty) {
    unset($edit[$info['field_name']]);
  }
}

function simple_ldap_user_translate_url_drupal_to_ldap(&$value, $field_info, $items) {
  if (is_array($items)) {
    foreach ($items as $item) {
      if (empty($item['title'])) {
        $value[] = $item['value'];
      }
      else {
        $value[] = '<a href="' . $item['value'] . '">' . $item['title'] . '</a>';
      }
    }
  }  
}