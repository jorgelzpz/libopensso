<?php
/**
 * OpenSSO integration library for PHP
 *
 * @license MIT
 * @author Jorge López Pérez <jorge@adobo.org>
 * @version 1.0
 * @package libopensso-php
 */

namespace OpenSSO;

/**
  * Class for OpenSSO integration
  * @package libopensso-php
  */
class Handler {

	/**
	 * Library version, used inside User-Agent
	 */
	const version = '1.0.0-alpha';

	/**
	 * Default cookie name
	 */
	const cookiename = 'iPlanetDirectoryPro';

	/**
	 * Metadata path
	 */
	protected $path;

	/**
	 * Cached metadata
	 */
	protected $metadata;

	/**
	 * Chosen environment
	 */
	protected $env;

	/**
	 * Current cookie name
	 */
	private $cookiename;

	/**
	 * Current user SSO token
	 */
	private $token;

	/**
	 * Attributes for current user
	 */
	private $attributes;

	/**
	 * Context needed for stream functions
	 */
	private $context;

	/**
	 * Constructs a new OpenSSO client handler
	 *
	 * @param string $env Which environment from metadata should this helper use
	 * @param boolean $fetch_cookie_name When true cookie name will be
	 *        fetched from server using getCookieNameForToken
	 * @param string $metadata_dir Directory to load metadata from
	 * @throws \Exception On error
	 */
	public function __construct($env = 'prodV1', $fetch_cookie_name = FALSE,
			$metadata_dir = '') {
		// Set current path
		$this->path = empty($metadata_dir) ?
			dirname(__FILE__) . '/../../metadata_default/' :
			$metadata_dir;

		// Initialization
		$metadata = @parse_ini_file($this->path . '/metadata.ini',
				TRUE);
		
		if (!isset($metadata[$env])) {
			throw new \Exception('Metada for ' . $env . ' not found');
		} else {
			$this->env = $env;
			$this->metadata = $metadata[$env];
		}

		$this->context = stream_context_create();

		// SSL verification
		$options = array('ssl' =>
				array(
					'verify_peer' => TRUE,
					'cafile' => $this->path . '/crt/' . $env . '/ca.crt',
					'capture_peer_cert' => TRUE,
					));

		if (isset($this->metadata['self_signed']) &&
				$this->metadata['self_signed'] == '1') {
			unset($options['ssl']['cafile']);
			$options['ssl']['allow_self_signed'] = TRUE;
		} else {
			if (!file_exists($options['ssl']['cafile'])) {
				throw new \Exception('CA certificate file not found on '
						. $options['ssl']['cafile']);
			}
		}

		$result = stream_context_set_option($this->context, $options);
		if (FALSE === $result) {
			throw new \Exception('Error setting options for ssl context');
		}

		if ($fetch_cookie_name === TRUE) {
			// Fetch cookie name
			$res = $this->identity_query('getCookieNameForToken', 'POST');
			$this->cookiename = preg_replace('/^string=/', '', $res);
		} else {
			$this->cookiename = self::cookiename;
		}


		// Retrieve token from GET or cookie (IE bug)
		if (isset($_GET[$this->cookiename]) &&
				(!isset($_COOKIE[$this->cookiename]) ||
				 $_COOKIE[$this->cookiename] != $_GET[$this->cookiename])) {

			// Internet Explorer workaround
			if (isset($_SERVER['HTTPS'])) {
				$this->token = $_GET[$this->cookiename];
			}

			setcookie($this->cookiename, $this->token, 0, '/',
					$_SERVER['HTTP_HOST'], TRUE);
		} elseif (isset($_COOKIE[$this->cookiename])) {
			// Incorrect encoding of + to " "
			$this->token = preg_replace('/ /', '+',
					$_COOKIE[$this->cookiename]);
		}
	}

	/**
	 * Forces OpenSSO login
	 *
	 * @param string $gotourl	Return URL. If not specified, current URL is used
	 * @return boolean	User has a valid SSO session or not
	 */
	public function check_and_force_sso($gotourl = '') {
		/*
		 * 1. Look for current token
		 * 2. If not present, redirect user
		 * 3. If present, check for validity
		 * 3.1. If valid session found, return TRUE
		 * 3.2. If not, redirect user
		 */
		if (!$this->check_sso()) {
			if (empty($gotourl)) {
				$gotourl = $this->current_url();
			}

			header("Location: " . $this->metadata['login_url']
					. '?goto=' . urlencode($gotourl));

			return FALSE;
		} else {
			return TRUE;
		}
	}

	/**
	 * Checks if current user has a valid SSO session
	 *
	 * @return boolean	User has a valid SSO session or not
	 */

	public function check_sso() {
		if (empty($this->token)) {
			return FALSE;
		}

		// Check for valid session
		try {
			$res = $this->identity_query('isTokenValid', 'GET',
					'tokenid=' . urlencode($this->token));
		} catch (\Exception $e) {
			$this->token = '';
			$code = $e->getCode();

			if ($code == 403) {
				throw new \Exception('Access forbidden to OpenSSO');
			} elseif ($code == 401) {
				return FALSE;
			} else {
				throw $e;
			}
		}

		if (preg_match('/true/', $res)) {
			// SSO token is valid
			$this->fetch_attributes();
			return TRUE;
		} else {
			$this->token = '';
			return FALSE;
		}
	}


	/**
	 * Fetchs user attributes
	 *
	 * @internal
	 * @return void
	 */

	protected function fetch_attributes() {
		if (empty($this->token)) {
			throw new \Exception('Empty token');
		}

		$res = $this->identity_query('attributes', 'GET',
				'subjectid=' . urlencode($this->token));

		$attributes = array();

		$lines = preg_split("/\r\n|\n|\r/", $res);
		$atr = "";
		$values = array();
		foreach ($lines as $line) {
			$piece = preg_split("/=/", $line);
			if ($piece[0] == "userdetails.attribute.name") {
				// Store attribute
				if (!empty($atr)) {
					$atr = strtolower($atr);
					$this->attributes[$atr] = count($values) == 1 ?
								$values[0] :
								$values;
					$values = array();
				}
				$atr = $piece[1];
			} else if ($piece[0] == "userdetails.attribute.value") {
				$values[] = $piece[1];
			}
		}

		// Last attribute
		if (!empty($atr)) {
			$this->attributes[$atr] = count($values) == 1 ?
						$values[0] :
						$values;
			$values = array();
		}
	}

	/**
	 * Connects to an OpenSSO identity service and retrieves answer
	 *
	 * @internal
	 * @param string $service Web service to be queried
	 * @param string $method HTTP method to be used
	 * @param string $query Query that have to be appended to the URL
	 * @return string Answer from server
	 * @throw \Exception Thrown on connection problems and when HTTP response code is not 200
	 */

	protected function identity_query($service, $method = 'GET', $query = '') {
		$uri = parse_url($this->metadata['ws_base_url'] . $service);

		$socket_dest = $uri['scheme'] == 'http' ? 'tcp' : 'ssl';
		$socket_dest .= '://';

		switch ($uri['scheme']) {
			case 'http':
				$port = isset($uri['port']) ? $uri['port'] : 80;
				$socket_dest .= $uri['host'] . ':' . $port . '/';
				$fp = @stream_socket_client($socket_dest, $errno, $errstr,
						15, STREAM_CLIENT_CONNECT);
				break;
			case 'https':
				$port = isset($uri['port']) ? $uri['port'] : 443;
				$socket_dest .= $uri['host'] . ':' . $port . '/';
				$fp = @stream_socket_client($socket_dest, $errno, $errstr,
						20, STREAM_CLIENT_CONNECT, $this->context);
				break;
			default:
				throw new \Exception('Invalid protocol: ' . $uri['scheme']);
		}

		if (!$fp) {
			if (FALSE === $fp && $errno == 0) {
				throw new \Exception('SSL verification failed or '
						.'connection failed. ['.$errstr.']');
			} else {
				throw new \Exception('Connection failed. ['.$errno
						. ', ' . $errstr.']');
			}
		}


		// Certificate validation
		$options = stream_context_get_options($this->context);
		$site_cert =
			openssl_x509_parse($options['ssl']['peer_certificate']);

		if (isset($this->metadata['crt_serialnumber'])) {
			if ($site_cert['serialNumber'] !=
					$this->metadata['crt_serialnumber']) {
				throw new \Exception('Invalid certificate serial number '
						. '('.$site_cert['serialNumber'].')');
			}
		}

		$path = isset($uri['path']) ? $uri['path'] : '/';
		if (!empty($query)) {
			$path .= '?' . $query;
		}

		// Create HTTP request.
		$defaults = array(
				'Host' => "Host: " . $uri['host'],
				'User-Agent' => 'User-Agent: libopensso-php '
					. self::version,
		);

		$request = $method .' '. $path ." HTTP/1.0\r\n";
		$request .= implode("\r\n", $defaults);
		$request .= "\r\n\r\n";

		fwrite($fp, $request);

		// Fetch response.
		$response = '';
		while (!feof($fp) && $chunk = fread($fp, 1024)) {
			$response .= $chunk;
		}
		fclose($fp);

		// Parse response.
		$tmpdata = '';
		list($split, $tmpdata) = explode("\r\n\r\n", $response, 2);
		$split = preg_split("/\r\n|\n|\r/", $split);

		list($protocol, $code, $text) = explode(' ', trim(array_shift($split)), 3);

		if ($code != '200') {
			throw new \Exception('HTTP response code ' . $code,
					intval($code));
		}

		return trim($tmpdata);
	}


	/**
	 * Returns an attribute value/values
	 *
	 * @param string $atr Attribute name
	 * @param boolean $force_array Whether to cast to array even if attribute has a single value
	 */

	public function attribute($atr, $force_array = FALSE) {
		if (empty($atr)) {
			throw new \Exception('Empty attribute name');
		} else {
			$atr = strtolower($atr);
			if (isset($this->attributes[$atr])) {
				if ($force_array && !is_array($this->attributes[$atr])) {
					return array($this->attributes[$atr]);
				} else {
					return $this->attributes[$atr];
				}
			} else {
				return $force_array ? array() : '';
			}
		}
	}

	/**
	 * Returns all attributes
	 *
	 * @param boolean $force_arrays Force use of arrays even on single valued attributes
	 */
	public function all_attributes($force_arrays = FALSE) {
		$atr = array();
		if ($force_arrays === TRUE) {
			foreach ($this->attributes as $a => $v) {
				if (!is_array($v)) {
					$v = array($v);
				}

				$atr[$a] = $v;
			}
		} else {
			$atr = $this->attributes;
		}
		return $atr;
	}


	/**
	 * Logs out user from OpenSSO
	 *
	 * @param string $gotourl URL to return to after logging out
	 */
	public function logout($gotourl = '') {
		// IE bug. If testExplorerBug cookie is not set, it means
		// it didn't store any cookies for *.xx.tld, so
		// unset cookie for current hostname
		if (!isset($_COOKIE['testExplorerBug'])) {
			setcookie($this->cookiename, "", time() - 3600, "/");
		}

		$gotourl = empty($gotourl) ? $this->current_url() : $gotourl;
		header("Location: " . $this->metadata['logout_url']
				. "?goto=" . urlencode($gotourl));
	}



	/**
	 * Returns current URL
	 *
	 * @internal
	 * @return string Current URL
	 */

	private function current_url() {
		return (isset($_SERVER['HTTPS']) ? 'https' : 'http')
			. '://' . $_SERVER['SERVER_NAME']  . ':'
			. $_SERVER['SERVER_PORT']
			. $_SERVER['REQUEST_URI'];
	}

}
