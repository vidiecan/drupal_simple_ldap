<?php
/**
 * @file
 * Describe hooks provided by the Simple LDAP Role module.
 */

/**
 * SimpleLdapRole fingerprint.
 *
 * Variables exposed by __get() and __set()
 * ----------------------------------------
 * $attributes
 * $dn
 * $exists
 * $server
 *
 * Magic methods
 * -------------
 * __construct($name)
 * __get($name)
 * __set($name, $value)
 *
 * Public functions
 * ----------------
 * save()
 * delete()
 * addUser()
 * deleteUser()
 *
 * Public static methods
 * ---------------------
 * filter()
 * singleton($name)
 */

/**
 * simple_ldap_role helper functions.
 *
 * simple_ldap_role_variable_get($variable)
 */

/**
 * Alter excluded groups during role saving.
 *
 * This hook is called when determining whether a role should be synced with
 * LDAP.  The list of roles to exclude will usually include "anonymous user"
 * and "authenticated user".
 *
 * This example excludes the role MY_OTHER_RID in addition to any other roles
 * being excluded from syncronization.
 *
 * @param array $exclude
 *   Array of rids to ignore during syncronization.
 */
function hook_simple_ldap_role_exclude_alter(&$exclude) {
  $exclude[] = MY_OTHER_RID;
}
