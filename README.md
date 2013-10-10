OAUTH2 library for Codeigniter:
--------------

A Codeigniter library which allows users to authorize your Linkedin, Facebook, Google, Instagram or Foursquare applications using OAuth2.


Usage example:
--------------
	<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

	class Test extends CI_Controller {
		private $api_basic_info = array (
			'site' => 'facebook',
			'app_key' => 'APP KEY',
			'app_secret' => 'APP SECRET',
			'redirect_url' => 'REDIRECT URL',
			'scope' => 'SCOPE'
		);

		function connect() {
			$this->load->library('oauth2', $this->api_basic_info);
			$connect_url = $this->oauth2->build_request_url();
			echo '<a href="'.$connect_url.'">connect</a>';
		}
	
		function after_connect() {
			$this->load->library('oauth2', $this->api_basic_info );
			if (!$this->session->userdata($this->api_basic_info['site'].'_oauth2_access_token')) {
				$this->oauth2->retrieve_access_token();
			}
			var_dump($this->oauth2->api_call());
		}
	}
	
Requirements:
--------------

- libcurl. 
	


Version 1.31 - October 10 2013
--------------

- Refactored code.	

Version 1.3 - July 5 2013
---------------

- Added Foursquare authorization.
	 	
Version 1.2 - June 20 2013
--------------	 

- Added Instagram authorization.
	
Version 1.1 - May 17 2013
--------------

- Added Google authorization.
- Removed the need for the cURL spark. 

Version 1.0 - May 11 2013
--------------

- First release.