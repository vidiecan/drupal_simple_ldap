<?php
/**
 * @file
 * Class defining a simple LDAP user.
 */

class SimpleLdapUser {

  // Variables exposed by __get() and __set()
  protected $attributes = array();
  protected $dn = FALSE;
  protected $exists = FALSE;
  protected $server;

  // Internal variables.
  protected $dirty = array();
  protected $move = FALSE;

  /**
   * Constructor.
   *
   * @param string $name
   *   The drupal user name or email address to search for, and load from LDAP.
   *
   * @throw SimpleLdapException
   */
  public function __construct($name) {
    // Load the LDAP server object.
    $this->server = SimpleLdapServer::singleton();

    // Get the LDAP configuration.
    $base_dn = simple_ldap_user_variable_get('simple_ldap_user_basedn');
    $scope = simple_ldap_user_variable_get('simple_ldap_user_scope');
    $attribute_name = simple_ldap_user_variable_get('simple_ldap_user_attribute_name');
    $attribute_mail = simple_ldap_user_variable_get('simple_ldap_user_attribute_mail');
    $puid_attr = simple_ldap_user_variable_get('simple_ldap_user_unique_attribute');
    $safe_name = preg_replace(array('/\(/', '/\)/'), array('\\\(', '\\\)'), $name);

    // Search first for the user by name, then by email and finally by PUID.
    // Ensures that if someone has a username that is an email address, we find only
    // one record.
    $filter_list = array();
    $filter_list[] = '(&(' . $attribute_name . '=' . $safe_name . ')' . self::filter() . ')';
    $filter_list[] = '(&(' . $attribute_mail . '=' . $safe_name . ')' . self::filter() . ')';
    if ($puid_attr) {
      $filter_list[] = '(&(' . $puid_attr . '=' . $safe_name . ')' . self::filter() . ')';
    }

    // List of attributes to fetch from the LDAP server.
    // Using key => value autmatically dedups the list.
    $attributes = array(
      $attribute_name => $attribute_name,
      $attribute_mail => $attribute_mail
    );
    $attribute_map = simple_ldap_user_variable_get('simple_ldap_user_attribute_map');

    // Collect all the attributes to load
    $attributes = array_keys($attribute_map);
    $config_extra_attributes = array_values(simple_ldap_user_variable_get('simple_ldap_user_extra_attrs'));
    $hook_extra_attributes = array_values(module_invoke_all('simple_ldap_user_extra_attributes', $this->server));

    // Merge them into a single array.
    $attributes = array_merge($attributes, $config_extra_attributes, $hook_extra_attributes);

    // Add the unique attribute, if it is set.
    if ($puid_attr) {
      $attributes[] = $puid_attr;
    }

    // filter to keep ldap_search happy
    $attributes = array_unique(array_map('strtolower', array_values($attributes)));

    // Include the userAccountControl attribute for Active Directory.
    try {
      if ($this->server->type == 'Active Directory') {
        $attributes['useraccountcontrol'] = 'useraccountcontrol';
      }
    } catch (SimpleLdapException $e) {}

    foreach($filter_list as $filter) {
      // Attempt to load the user from the LDAP server.
      try {
        $result = $this->server->search($base_dn, $filter, $scope, array_values($attributes), 0, 1);
      } catch (SimpleLdapException $e) {
        if ($e->getCode() == -1) {
          $result = array('count' => 0);
        }
        else {
          throw $e;
        }
      }
      if ($result['count'] == 1) {
        break;
      }
    }

    // Populate the attribute array.
    if ($result['count'] == 1) {
      $this->dn = $result[0]['dn'];
      foreach ($attributes as $attribute) {
        $attribute = strtolower($attribute);
        // Search for the attribute in the LDAP schema.
        $schema_attribute = $this->server->schema->get('attributeTypes', $attribute);
        $schema_attribute_name = strtolower($schema_attribute['name']);
        // Check whether the attribute or any of its aliases are present in the
        // LDAP user.
        $found = FALSE;
        if (isset($result[0][$schema_attribute_name])) {
          $found = $schema_attribute_name;
        }
        if (!$found) {
          foreach($schema_attribute['aliases'] as $alias) {
            $alias = strtolower($alias);
            if (isset($result[0][$alias])) {
              $found = $alias;
              break;
            }
          }
        }

        // Assign the attribute value to the SimpleLdapUser object.
        if ($found) {
          $this->attributes[$attribute] = $result[0][$found];
        }
      }
      $this->exists = TRUE;
    }
    else {
      $this->attributes[$attribute_name] = array('count' => 1, 0 => $name);
    }
  }

  /**
   * Magic __get() function.
   *
   * @param string $name
   *   Name of the variable to get.
   *
   * @return mixed
   *   Returns the value of the requested variable, if allowed.
   */
  public function __get($name) {
    switch ($name) {
      case 'attributes':
      case 'dn':
      case 'exists':
      case 'server':
        return $this->$name;

      case 'dirty':
        return !empty($this->dirty);

      default:
        if (isset($this->attributes[$name])) {

          // Make sure 'count' is set accurately.
          if (!isset($this->attributes[$name]['count'])) {
            $this->attributes[$name]['count'] = count($this->attributes[$name]);
          }
          else {
            $this->attributes[$name]['count'] = count($this->attributes[$name]) - 1;
          }

          return $this->attributes[$name];
        }
        return array('count' => 0);
    }
  }

  /**
   * Magic __set() function.
   *
   * @param string $name
   *   The name of the attribute to set.
   * @param mixed $value
   *   The value to assigned to the given attribute.
   */
  public function __set($name, $value) {
    $attribute_pass = simple_ldap_user_variable_get('simple_ldap_user_attribute_pass');

    switch ($name) {
      // Read-only values.
      case 'attributes':
      case 'exists':
        break;

      case 'dn':
        if ($this->dn != $value) {
          try {
            // Validate the DN format before trying to use it.
            SimpleLdap::ldap_explode_dn($value);
            // Save the old DN, so a move operation can be done during save().
            $this->move = $this->dn;
            $this->dn = $value;
          } catch (SimpleLdapException $e) {}
        }
        break;

      // Look up the raw password from the internal reverse hash map. This
      // intentionally falls through to default:.
      case $attribute_pass:
        if (isset(self::$hash[$value[0]])) {
          $algorithm = simple_ldap_user_variable_get('simple_ldap_user_password_hash');
          $value = SimpleLdap::hash(self::$hash[$value[0]], $algorithm);
        }
        else {
          // A plain text copy of the password is not available. Do not
          // overwrite the existing value.
          return;
        }

      default:
        // Make sure $value is an array.
        if (!is_array($value)) {
          $value = array($value);
        }

        if (!array_key_exists('count', $value)) {
          $value['count'] = count($value);
        }

        // Make sure $this->attributes[$name] is an array.
        if (!isset($this->attributes[$name])) {
          $this->attributes[$name] = array();
        }

        // Compare the current value with the given value.
        $diff1 = @array_diff($this->attributes[$name], $value);
        $diff2 = @array_diff($value, $this->attributes[$name]);

        // Don't trigger a write if the only difference is the count field,
        // which may be missing from the $value array.
        unset($diff1['count']);
        unset($diff2['count']);

        // If there are any differences, update the current value.
        if (!empty($diff1) || !empty($diff2)) {
          $this->attributes[$name] = $value;
          $this->dirty[$name] = $value;
        }

    }

  }

  /**
   * Authenticates this user with the given password.
   *
   * @param string $password
   *   The password to use for authentication.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure
   */
  public function authenticate($password) {
    if ($this->exists) {
      if ($password[0] === chr(0)) {
        $password[0] = chr(0x20);
      }
      $auth = $this->server->bind($this->dn, $password);
      return $auth;
    }
    return FALSE;
  }

  /**
   * Save user to LDAP.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  public function save() {
    // Move(rename) the entry if the DN was changed.
    if ($this->move) {
      $this->server->move($this->move, $this->dn);
    }

    // If there is nothing to save, return "success".
    if (empty($this->dirty)) {
      return TRUE;
    }

    // Active Directory has some restrictions on what can be modified.
    if ($this->server->type == 'Active Directory') {
      $attribute_pass = simple_ldap_user_variable_get('simple_ldap_user_attribute_pass');
      $attribute_rdn = simple_ldap_user_variable_get('simple_ldap_user_attribute_rdn');
      // Passwords can only be changed over LDAPs.
      if (stripos($this->server->host, 'ldaps://') === FALSE) {
        unset($this->attributes[$attribute_pass]);
      }
      unset($this->attributes[$attribute_rdn]);
    }

    if ($this->exists) {
      // Update existing entry, writing out only changed values
      $this->server->modify($this->dn, $this->dirty);
    }
    else {
      // Create new entry.
      try {
        $this->attributes['objectclass'] = simple_ldap_user_parent_objectclasses(simple_ldap_user_variable_get('simple_ldap_user_objectclass'));
        $this->server->add($this->dn, $this->attributes);
      } catch (SimpleLdapException $e) {
        if ($e->getCode() == 68) {
          // An "already exists" error was returned, try to do a modify instead.
          // We don't know what is dirty, so write the whole record
          $this->server->modify($this->dn, $this->attributes);
        }
        else {
          throw $e;
        }
      }
    }

    // No exceptions were thrown, so the save was successful.
    $this->exists = TRUE;
    $this->attributes += $this->fetch_puid();
    $this->dirty = array();
    $this->move = FALSE;
    return TRUE;
  }

  /**
   * Delete user from LDAP directory.
   *
   * @return boolean
   *   TRUE on success. FALSE if a save was not performed, which would only
   *   happen if a valid DN has not been defined for the object.
   *
   * @throw SimpleLdapException
   */
  public function delete() {
    if ($this->move) {
      $this->server->delete($this->move);
    }
    elseif ($this->dn) {
      $this->server->delete($this->dn);
    }
    else {
      return FALSE;
    }

    // There were no exceptions thrown, so the entry was successfully deleted.
    $this->exists = FALSE;
    $this->dirty = array();
    $this->move = FALSE;
    return TRUE;
  }

  /**
   * Return the LDAP search filter, as set by the module configuration.
   *
   * @return string
   *   The LDAP search filter to satisfy the module configuration options.
   */
  public static function filter() {
    // Get the relevant configurations.
    $objectclass = simple_ldap_user_variable_get('simple_ldap_user_objectclass');
    $extrafilter = simple_ldap_user_variable_get('simple_ldap_user_filter');

    // Construct the filter.
    $filter = '(&(objectclass=' . implode(')(objectclass=', $objectclass) . '))';
    if (!empty($extrafilter)) {
      $filter = '(&' . $filter . '(' . $extrafilter . '))';
    }

    return $filter;
  }

  protected static $users = array();

  /**
   * Return a SimpleLdapUser object for the given username.
   *
   * @param string $name
   *   The drupal user name or email address to search for, and load from LDAP.
   * @param boolean $reset
   *   If TRUE, the cache for the specified user is cleared, and the user is
   *   reloaded from LDAP.
   *
   * @return object
   *   SimpleLdapUser
   *
   * @throw SimpleLdapException
   */
  public static function singleton($name, $reset = FALSE) {
    if ($reset || !isset(self::$users[$name])) {
      self::$users[$name] = new SimpleLdapUser($name);
    }

    return self::$users[$name];
  }

  /**
   * Clear the cache for the given username.
   *
   * @param string $name
   *   If specified, clear the cache entry for the given user. If not
   *   specified, all cache entries are cleared.
   */
  public static function reset($name = NULL) {
    if ($name === NULL) {
      self::$users = array();
    }
    else {
      unset(self::$users[$name]);
    }
  }

  // This is intentionally private because it handles sensitive information.
  private static $hash = array();

  /**
   * Internal password hash storage.
   *
   * This is called by the customized user_hash_password() function in
   * simple_ldap_user.password.inc to create an internal reverse hash lookup, so
   * passwords can be updated in LDAP. The hash is not exposed by the class API,
   * and is cleared after every page load.
   *
   * @param string $key
   *   The hash key
   * @param string $value
   *   The hash value
   */
  public static function hash($key, $value) {
    self::$hash[$key] = $value;
  }

  /**
   * Special function to fetch the PUID of a record.
   */
  private function fetch_puid() {
    // Configuration
    $base_dn = simple_ldap_user_variable_get('simple_ldap_user_basedn');
    $scope = simple_ldap_user_variable_get('simple_ldap_user_scope');
    $puid_attr = strtolower(simple_ldap_user_variable_get('simple_ldap_user_unique_attribute'));

    // Should we bother?
    if (!$puid_attr || !$this->exists) {
      return array();
    }

    try {
      $result = $this->server->search($this->dn, 'objectclass=*', 'sub', array($puid_attr), 0, 1);
    } catch (SimpleLdapException $e) {
      if ($e->getCode() == -1) {
        $result = array('count' => 0);
      }
      else {
        throw $e;
      }
    }

    return ($result['count'] == 1) ? $result[0] : array();
  }

}
