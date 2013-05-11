<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Test extends CI_Controller {
	private $api_basic_info = array (
			'site' => 'facebook',
			'app_key' => 'APP KEY',
			'app_secret' => 'APP SECRET',
			'redirect_url' => 'REDIRECT URL',
			'scope' => 'SCOPE'
	);
	
	function __construct() {
		parent::__construct();
	}

	function connect() {
		$this->load->library('oauth2', $this->api_basic_info);
		$connect_url = $this->oauth2->build_request_url();
		echo '<a href="'.$connect_url.'">connect</a>';
	}

	function after_connect() {
		$this->load->library('oauth2', $this->api_basic_info );
		
		if (!$this->session->userdata($this->api_basic_info['site'].'_oauth2_access_token')) {
			if ($this->oauth2->retrieve_access_token()) {
				var_dump($this->oauth2->api_call());
			}
		}
		else {
			var_dump($this->oauth2->api_call());
		}
	}
}