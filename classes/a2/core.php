<?php

/**
 * User AUTHORIZATION library. 
 * 
 * - Authentication vs Authorization -
 * "However, more precise usage describes authentication as the process of verifying a claim made by a 
 *  subject that it should be treated as acting on behalf of a given principal (person, computer, smart 
 *  card etc.), while authorization is the process of verifying that an authenticated subject has the 
 *  authority to perform a certain operation. Authentication, therefore, must precede authorization."
 * [http://en.wikipedia.org/wiki/Authentication#Authentication_vs._authorization]
 *
 * This library offers advanced user authorization using a user defined Authentication library, and an
 * improved version of Zend's ACL for Kohana.
 *
 * The Access Control List (roles,resources,rules) and the desired Authentication library are stored in a
 * config file. Usage in your code (controller/libraries/models) are as follow:

		// simple acl usage (resource string 'blog')
		if(A2::instance()->allowed('blog','read'))
			// do
		else
			// don't 

		// advanced acl usage (resource object: $blog), allows using the improved assertions
		if(A2::instance()->allowed($blog,'delete')) 
			// do
		else
			// don't
 *
 */

abstract class A2_Core extends Acl {

	public    $a1;          // the Authentication library (used to retrieve user)
	protected $_guest_role; // name of the guest role (used when no user is logged in)

	/**
	 * Return an instance of A2.
	 *
	 * @return  object
	 */
	public static function instance($_name = 'a2')
	{
		static $_instances;

		if ( ! isset($_instances[$_name]))
		{
			$_instances[$_name] = new A2($_name);
		}

		return $_instances[$_name];
	}

	/**
	 * Build default A2 from config.
	 *
	 * @return  void
	 */
	public function __construct($_name = 'a2')
	{
		// Read config
		$config = Kohana::$config->load($_name);

		// Create instance of Authenticate lib (a1, auth, authlite)
		$instance = new ReflectionMethod($config->lib['class'],'instance');

		$params = !empty($config->lib['params']) 
			? $config->lib['params'] 
			: array();

		$this->a1 = $instance->invokeArgs(NULL, $params);

		// Throw exceptions?
		$this->_exception = $config->exception;

		// Guest role
		$this->_guest_role = $config['guest_role'];

		// Add Guest Role as role
		if ( ! array_key_exists($this->_guest_role,$config['roles']))
		{
			$this->add_role($this->_guest_role);
		}

		// Load ACL data
		$this->load($config);
	}

	/**
	 * Load ACL data (roles/resources/rules)
	 *
	 * This allows you to add context specific rules
	 * roles and resources. 
	 *
	 * @param  array|Kohana_Config  configiration data
	 */
	public function load($config)
	{
		// Roles
		if ( isset($config['roles']))
		{
			foreach ( $config['roles'] as $role => $parent)
			{
				$this->add_role($role,$parent);
			}
		}

		// Resources
		if ( isset($config['resources']))
		{
			foreach($config['resources'] as $resource => $parent)
			{
				$this->add_resource($resource,$parent);
			}
		}

		// Rules
		if(isset($config['rules']))
		{
			foreach(array('allow','deny') as $method)
			{
				if ( isset($config['rules'][$method]))
				{
					foreach ( $config['rules'][$method] as $rule)
					{
						// create variables
						$role = $resource = $privilege = $assertion = NULL;

						// extract variables from rule
						extract($rule);

						// create assert object
						if ( $assertion )
						{
							if ( is_array($assertion))
							{
								$assertion = count($assertion) === 2
									? new $assertion[0]($assertion[1])
									: new $assertion[0];
							}
							else
							{
								$assertion = new $assertion;
							}
						}

						// this is faster than calling $this->$method
						if ( $method === 'allow')
						{
							$this->allow($role,$resource,$privilege,$assertion);
						}
						else
						{
							$this->deny($role,$resource,$privilege,$assertion);
						}
					}
				}
			}
		}
	}

	/**
	 * Check if logged in user (or guest) has access to resource/privilege.
	 *
	 * @param   mixed     Resource
	 * @param   string    Privilege
	 * @param   boolean   Override exception handling set by config
	 * @return  boolean   Is user allowed
	 * @throws  A2_Exception   In exception modus, when user is not allowed
	 */
	public function allowed($resource = NULL, $privilege = NULL, $exception = NULL)
	{
		if ( ! is_bool($exception))
		{
			// take config value
			$exception = $this->_exception;
		}

		// retrieve user
		$role = ($user = $this->a1->get_user()) ? $user : $this->_guest_role;

		$result = $this->is_allowed($role,$resource,$privilege);

		if ( ! $exception || $result === TRUE )
		{
			return $result;
		}
		else
		{
			$resources = $privileges = $errors = array();

			if ( $resource !== NULL)
			{
				$resources[] = $resource instanceof Acl_Resource_Interface ? $resource->get_resource_id() : (string) $resource;
			}

			if ( $privilege !== NULL)
			{
				$privileges[] = $privilege;
			}

			$resources[]  = 'default';
			$privileges[] = 'default';

			foreach ( $resources as $r)
			{
				foreach ( $privileges as $p)
				{
					if ( $message = Kohana::message('a2', $r . '.' . $p))
					{
						throw new A2_Exception($message);
					}
				}
			}

			// this only happens when someone has removed the 'default.default' error message from messages/a2.php
			throw new A2_Exception('No error messages defined');
		}
	}

	/**
	 * Alias of the logged_in method
	 */
	public function logged_in() 
	{
		return $this->a1->logged_in();
	}

	/**
	 * Alias of the get_user method
	 */
	public function get_user()
	{
		return $this->a1->get_user();
	}

} // End A2 lib