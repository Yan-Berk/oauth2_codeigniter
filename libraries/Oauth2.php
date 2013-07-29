<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/*
 The MIT License (MIT)

Copyright (c) 2013 Wicked Onion

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

define ('NO_EXPIRE_VALUE', 0);

class Oauth2 {

	private $site;
	private $consumer_key;
	private $consumer_secret;
	private $redirect_url;
	private $scope;
	private $state;
	private $access_token;
	private $access_token_expires_in;

	private $extra_param_sites = array('linkedin', 'google', 'instagram', 'foursquare');

	private $initial_urls = array (
			'facebook'	=>	'https://www.facebook.com/dialog/oauth/?',
			'linkedin'	=>	'https://www.linkedin.com/uas/oauth2/authorization?',
			'google'	=>	'https://accounts.google.com/o/oauth2/auth?',
			'instagram'	=>	'https://api.instagram.com/oauth/authorize/?',
			'foursquare'	=>	'https://foursquare.com/oauth2/authenticate?'
	);

	private $response_urls = array (
			'facebook'	=>	'https://graph.facebook.com/oauth/access_token?',
			'linkedin'	=>	'https://www.linkedin.com/uas/oauth2/accessToken?',
			'google'	=>	'https://accounts.google.com/o/oauth2/token?',
			'instagram'	=>	'https://api.instagram.com/oauth/access_token?',
			'foursquare'	=>	'https://foursquare.com/oauth2/access_token?'
	);

	private $api_urls = array (
			'facebook'	=>	'https://graph.facebook.com/me?access_token=',
			'linkedin'	=>	'https://api.linkedin.com/v1/people/~?oauth2_access_token=',
			'google'	=>	'https://www.googleapis.com/oauth2/v1/userinfo?access_token=',
			'instagram'	=>	'https://api.instagram.com/v1/users/self/feed?access_token=',
			'foursquare'	=>	'https://api.foursquare.com/v2/users/self/checkins?v=YYYYMMDD&oauth_token='
	);

	public $ci;

	public function __construct($input) {
		$this->ci = get_instance();
		$this->load_framework_basics();
		$this->set_oauth2_class_params($input);
	}

	private function load_framework_basics() {
		$this->ci->load->database();
		$this->ci->load->helper('url');
		$this->ci->load->library('session');
	}

	private function set_oauth2_class_params($input) {
		$this->set_site($input['site']);
		$this->set_consumer_key($input['app_key']);
		$this->set_consumer_secret($input['app_secret']);
		$this->set_redirect_url($this->set_url($input['redirect_url']));
		$this->set_scope($input['scope']);

		$this->set_state($this->ci->session->userdata($this->get_site().'_oauth2_state'));
		$this->set_access_token($this->ci->session->userdata($this->get_site().'_oauth2_access_token'));
		$this->set_access_token_expires_in($this->ci->session->userdata($this->get_site().'_oauth2_access_token_expires_in'));
	}

	public function build_initial_request_url() {
		$request_url = $this->get_request_base_url();
		$request_url .= $this->get_request_parameters();
		return $request_url;
	}

	private function get_request_base_url() {
		return $this->initial_urls[$this->get_site()];
	}

	private function get_request_parameters() {
		$this->create_new_state_and_save_in_session();

		$query_params = $this->get_query_params('request');

		if (in_array($this->get_site(), $this->extra_param_sites)) {
			$query_params['response_type'] = 'code';
		}

		return http_build_query($query_params);
	}

	private function create_new_state_and_save_in_session() {
		$state = substr(md5(rand()), 0, 8);
		$this->ci->session->set_userdata($this->get_site().'_oauth2_state', $state);
		$this->set_state($state);
	}

	private function get_query_params($type) {

		$query_params = array('client_id' => $this->get_consumer_key(),
				'redirect_uri' => $this->get_redirect_url()
		);

		if ($type == 'request') {
			$query_params = array_merge($query_params, $this->get_request_query_params());
		}
		else if ($type == 'access_token') {
			$query_params = array_merge($query_params, $this->get_access_token_query_params());
		}

		return $query_params;
	}

	private function get_request_query_params() {
		return array ('scope' => $this->get_scope(),
				'state' => $this->get_state()
		);
	}

	private function get_access_token_query_params() {
		return array('code' => $this->ci->input->get('code'),
				'client_secret' => $this->get_consumer_secret()
		);
	}

	public function retrieve_access_token_and_save_in_session() {
		if (!$this->is_response_valid()) {
			return false;
		}

		return $this->get_access_token_and_save_in_session();
	}

	private function is_response_valid() {
		if ($this->ci->input->get('state') != $this->get_state()) {
			return false;
		}
		if ($this->ci->input->get('error')) {
			//Handle error
			$this->ci->input->get('error_description');
			return true;
		}

		if (!$this->ci->input->get('code')) {
			return false;
		}

		return true;
	}

	private function build_access_token_retrieve_url() {
		$request_url = $this->get_access_token_base_url();
		$request_url .= $this->get_access_token_parameters();
		return $request_url;
	}

	private function get_access_token_base_url() {
		return $this->response_urls[$this->get_site()];
	}

	private function get_access_token_parameters() {
		$query_params = $this->get_query_params('access_token');

		if (in_array($this->get_site(), $this->extra_param_sites)) {
			$query_params['grant_type'] = 'authorization_code';
		}

		return http_build_query($query_params);
	}

	private function get_access_token_and_save_in_session() {

		$method_name = 'get_'.$this->get_site().'_token';
		$this->$method_name();

		$this->save_access_token_in_session();
		return true;
	}

	private function get_linkedin_token() {
		$result = json_decode($this->get_access_token_by_get_request());
		if ($result->access_token) {
			$this->set_access_token_data($result->access_token, $result->expires_in);
			return true;
		}
		return false;
	}

	private function get_facebook_token() {
		$result = json_decode($this->get_access_token_by_get_request());
		$params = null;
		parse_str($result, $params);
		if (array_key_exists('access_token', $params)) {
			$this->set_access_token_data($params['access_token'], $params['expires']);
			return true;
		}
		return false;
	}

	private function get_google_token() {
		$result = json_decode($this->get_access_token_by_post_request());
		if ($result->access_token) {
			$this->set_access_token_data($result->access_token, $result->expires_in);
			return true;
		}
		return false;
	}

	private function get_instagram_token() {
		$result = json_decode($this->get_access_token_by_post_request());
		if ($result->access_token) {
			$this->set_access_token_data($result->access_token, NO_EXPIRE_VALUE);
			return true;
		}
		return false;
	}
	
	private function get_foursquare_token() {
		$result = json_decode($this->get_access_token_by_get_request());
		
		if ($result->access_token) {
			$this->set_access_token_data($result->access_token, NO_EXPIRE_VALUE);
			return true;
		}
		return false;
	}

	private function save_access_token_in_session() {
		$this->ci->session->set_userdata($this->get_site().'_oauth2_access_token', $this->get_access_token());
		$this->ci->session->set_userdata($this->get_site().'_oauth2_access_token_expires_in', $this->get_access_token_expires_in());
	}

	private function get_access_token_by_get_request() {
		return file_get_contents($this->build_access_token_retrieve_url());
	}

	private function get_access_token_by_post_request() {
		return $this->run_curl($this->get_access_token_base_url(), 'POST', $this->get_access_token_parameters());
	}

	private function set_access_token_data($access_token, $expires_in) {
		$this->set_access_token($access_token);
		$this->set_access_token_expires_in($expires_in);
	}

	public function run_curl($url, $type, $params) {
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		if ($type == 'POST') {
			curl_setopt($ch, CURLOPT_POST, 1);
		}
		curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER  ,1);
		$result = curl_exec($ch);
		curl_close($ch);

		return $result;
	}

	/**
	 * Run a basic API call to test that the process was successful.
	 */
	public function api_call() {

		$this->prepare_api_url();

		$xml_sites = array('linkedin');

		if (in_array($this->get_site(), $xml_sites)) {
			return $this->get_xml_api_call();
		}

		$json_sites = array('facebook', 'google', 'instagram', 'foursquare');

		if (in_array($this->get_site(), $json_sites)) {
			return $this->get_json_api_call();
		}
	}

	private function prepare_api_url() {
		if ($this->get_site() == 'foursquare') {
			$this->api_urls[$this->get_site()] = str_replace('v=YYYYMMDD', 'v='.date('Ymd'), $this->api_urls[$this->get_site()]);
		}
	}
	
	private function get_xml_api_call() {
		$results_xml = file_get_contents($this->api_urls[$this->get_site()].$this->get_access_token());
		return new SimpleXMLElement($results_xml);
	}

	private function get_json_api_call() {
		return json_decode(file_get_contents($this->api_urls[$this->get_site()].$this->get_access_token()));
	}
	
	/**
	 * Normalizes the URL. Turns a relative URL into an absolute one.
	 * @param string $url
	 */
	public function set_url($url) {
		if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
			return site_url($url);
		}
		return $url;
	}


	public function get_site() {
		return $this->site;
	}

	public function set_site($site) {
		$this->site = $site;
	}

	public function get_consumer_key() {
		return $this->consumer_key;
	}

	public function set_consumer_key($consumer_key) {
		$this->consumer_key = $consumer_key;
	}

	public function get_consumer_secret() {
		return $this->consumer_secret;
	}

	public function set_consumer_secret($consumer_secret) {
		$this->consumer_secret = $consumer_secret;
	}

	public function get_redirect_url() {
		return $this->redirect_url;
	}

	public function set_redirect_url($redirect_url) {
		$this->redirect_url = $redirect_url;
	}

	public function get_state() {
		return $this->state;
	}

	public function set_state($state) {
		$this->state = $state;
	}

	public function get_access_token() {
		return $this->access_token;
	}

	public function set_access_token($access_token) {
		$this->access_token = $access_token;
	}

	public function get_access_token_expires_in() {
		return $this->access_token_expires_in;
	}

	public function set_access_token_expires_in($access_token_expires_in) {
		$this->access_token_expires_in = $access_token_expires_in;
	}

	public function get_scope() {
		return $this->scope;
	}

	public function set_scope($scope) {
		$this->scope = $scope;
	}
}