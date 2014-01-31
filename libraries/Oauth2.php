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

	private $api_call_json_sites = array('facebook', 'google', 'instagram', 'foursquare', 'stripe', 'dropbox');
	private $api_call_xml_sites = array('linkedin');
	
	private $get_sites = array('linkedin', 'foursquare', 'facebook');
	private $post_sites = array('google', 'instagram', 'stripe', 'dropbox', 'box');
	
	private $non_json_encoded_access_token_sites = array('facebook');
	
	private $api_call_prepared_sites = array('foursquare');
	
	private $authorize_urls = array (
			'facebook'	=>	'https://www.facebook.com/dialog/oauth/?',
			'linkedin'	=>	'https://www.linkedin.com/uas/oauth2/authorization?',
			'google'	=>	'https://accounts.google.com/o/oauth2/auth?',
			'instagram'	=>	'https://api.instagram.com/oauth/authorize/?',
			'foursquare'	=>	'https://foursquare.com/oauth2/authenticate?',
			'stripe'	=>	'https://connect.stripe.com/oauth/authorize?',
			'dropbox'	=>	'https://www.dropbox.com/1/oauth2/authorize?',
			'box'		=>	'https://www.box.com/api/oauth2/authorize?'
	);

	private $access_token_urls = array (
			'facebook'	=>	'https://graph.facebook.com/oauth/access_token?',
			'linkedin'	=>	'https://www.linkedin.com/uas/oauth2/accessToken?',
			'google'	=>	'https://accounts.google.com/o/oauth2/token?',
			'instagram'	=>	'https://api.instagram.com/oauth/access_token?',
			'foursquare'	=>	'https://foursquare.com/oauth2/access_token?',
			'stripe'	=>	'https://connect.stripe.com/oauth/token?',
			'dropbox'	=>	'https://api.dropbox.com/1/oauth2/token?',
			'box'		=> 'https://www.box.com/api/oauth2/token?'
	);

	private $api_urls = array (
			'facebook'	=>	'https://graph.facebook.com/me?access_token=',
			'linkedin'	=>	'https://api.linkedin.com/v1/people/~?oauth2_access_token=',
			'google'	=>	'https://www.googleapis.com/oauth2/v1/userinfo?access_token=',
			'instagram'	=>	'https://api.instagram.com/v1/users/self/feed?access_token=',
			'foursquare'	=>	'https://api.foursquare.com/v2/users/self/checkins?v=YYYYMMDD&oauth_token=',
			'stripe'	=>	'https://api.stripe.com/v1/charges?access_token=',
			'dropbox'	=>	'https://api.dropbox.com/1/account/info?access_token=',
			'box'		=>	'https://www.box.com/api/2.0/folders/0?access_token='
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

	private function set_oauth2_class_params($input = NULL) {
		if ($input) {
			$this->set_site($input['site']);
			$this->set_consumer_key($input['app_key']);
			$this->set_consumer_secret($input['app_secret']);
			$this->set_redirect_url($this->normalize_url($input['redirect_url']));
			$this->set_scope($input['scope']);			
		}

		$this->set_state($this->ci->session->userdata($this->get_site().'_oauth2_state'));
		$this->set_access_token($this->ci->session->userdata($this->get_site().'_oauth2_access_token'));
		$this->set_access_token_expires_in($this->ci->session->userdata($this->get_site().'_oauth2_access_token_expires_in'));
	}

	public function build_initial_request_url_and_create_state() {
		$this->set_state($this->create_random_state());
		$this->save_state_in_session();
		$request_url = $this->get_request_base_url();
		$request_url .= $this->get_request_parameters();
		return $request_url;
	}

	public function get_request_base_url() {
		return $this->authorize_urls[$this->get_site()];
	}

	public function get_request_parameters() {
		$query_params = $this->get_request_query_params();
		return http_build_query($query_params);
	}

	public function save_state_in_session() {
		$this->ci->session->set_userdata($this->get_site().'_oauth2_state', $this->get_state());
	}
	
	public function create_random_state() {
		return substr(md5(rand()), 0, 8);
	}
	
	public function get_request_query_params($state) {
		return array_merge($this->get_basic_query_params(), array ('scope' => $this->get_scope(),
				'state' => $this->get_state(), 'response_type' => 'code'));
	}

	public function get_access_token_query_params($code) {
		return array_merge($this->get_basic_query_params(), array('code' => $code,
				'client_secret' => $this->get_consumer_secret(), 'grant_type' => 'authorization_code'
		));
	}

	public function get_basic_query_params() {
		return array('client_id' => $this->get_consumer_key(),
						'redirect_uri' => $this->get_redirect_url()
		);		
	}
	
	public function retrieve_access_token_and_save_in_session() {
		if (!$this->is_response_valid($this->ci->input->get())) {
			return FALSE;
		}

		return $this->get_access_token_and_save_in_session($this->ci->input->get('code'));
	}

	public function is_response_valid($get) {
		if (isset($get['state']) && $get['state'] == $this->get_state() && isset($get['code'])) {
			return TRUE;
		}
		
		return FALSE;
	}

	private function build_access_token_retrieve_url($code) {
		$request_url = $this->get_access_token_base_url();
		$request_url .= $this->get_access_token_parameters($code);
		return $request_url;
	}

	private function get_access_token_base_url() {
		return $this->access_token_urls[$this->get_site()];
	}

	private function get_access_token_parameters($code) {
		$query_params = $this->get_access_token_query_params($code);
		return http_build_query($query_params);
	}

	private function get_access_token_and_save_in_session($code) {
		$result = $this->get_access_token_by_site($code);
		$this->save_access_token_in_session($result['access_token'], $result['expires_in']);
		return TRUE;
	}
	
	public function get_access_token_by_site($code) {
		if (in_array($this->get_site(), $this->get_get_sites())) {
			$result = $this->get_access_token_by_get_request($code);
		}
		else if (in_array($this->get_site(), $this->get_post_sites())) {
			$result = $this->get_access_token_by_post_request($code);
		}
		return $this->get_access_token_data($result);
	}

	public function get_access_token_by_get_request($code) {
		$result = $this->get_access_token_by_get_request_connection($code);
		
		if (in_array($this->get_site(), $this->get_non_json_encoded_access_token_sites())) {
			return $result;
		}
		return json_decode($result);
	}
	
	public function get_access_token_by_post_request($code) {
		return json_decode($this->get_access_token_by_post_request_connection($code));		
	}	

	public function get_access_token_data($result) {
		$params = null;
		
		if (is_object($result)) {
			$params = $this->convert_object_to_array($result);
		}
		if (is_string($result)) {
			parse_str($result, $params);
		}
		
		if (array_key_exists('access_token', $params)) {
			$expires_in = NO_EXPIRE_VALUE;
			if (array_key_exists('expires', $params)) {
				$expires_in = $params['expires'];
			}
			else if (array_key_exists('expires_in', $params)) {
				$expires_in = $params['expires_in'];
			}
			$this->set_access_token_data($params['access_token'], $expires_in);

			return array('access_token' => $params['access_token'], 'expires_in' => $expires_in);
		}
		return FALSE;
	}
	
	private function convert_object_to_array($obj) {
		$access_token = NULL;
		if (isset($obj->access_token)) {
			$access_token = $obj->access_token;
		}
		
		$expires_in = NULL;
		if (isset($obj->expires_in)) {
			$expires_in = $obj->expires_in;
		}
		return array('access_token' => $access_token, 'expires_in' => $expires_in);
	}

	private function save_access_token_in_session($access_token, $expires_in) {
		$this->ci->session->set_userdata($this->get_site().'_oauth2_access_token', $access_token);
		$this->ci->session->set_userdata($this->get_site().'_oauth2_access_token_expires_in', $expires_in);
	}

	private function get_access_token_by_get_request_connection($code) {
		return file_get_contents($this->build_access_token_retrieve_url($code));
	}

	private function get_access_token_by_post_request_connection($code) {
		return $this->run_curl($this->get_access_token_base_url(), 'POST', $this->get_access_token_parameters($code));
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

		if (in_array($this->get_site(), $this->api_call_xml_sites)) {
			return $this->get_xml_api_call($this->get_access_token());
		}

		if (in_array($this->get_site(), $this->api_call_json_sites)) {
			return $this->get_json_api_call();
		}
	}

	private function prepare_api_url() {
		if (in_array($this->get_site(), $this->get_api_call_prepared_sites())) {
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
	public function normalize_url($url) {
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
	
	public function get_get_sites() {
		return $this->get_sites;
	}
	
	public function get_post_sites() {
		return $this->post_sites;
	}
	
	public function get_api_call_json_sites()
	{
		return $this->api_call_json_sites;
	}
	
	public function set_api_call_json_sites($api_call_json_sites)
	{
		$this->api_call_json_sites = $api_call_json_sites;
	}
	
	public function get_api_call_xml_sites()
	{
		return $this->api_call_xml_sites;
	}
	
	public function set_api_call_xml_sites($api_call_xml_sites)
	{
		$this->api_call_xml_sites = $api_call_xml_sites;
	}	

	public function get_non_json_encoded_access_token_sites()
	{
	    return $this->non_json_encoded_access_token_sites;
	}

	public function set_non_json_encoded_access_token_sites($non_json_encoded_access_token_sites)
	{
	    $this->non_json_encoded_access_token_sites = $non_json_encoded_access_token_sites;
	}

	public function get_api_call_prepared_sites()
	{
	    return $this->api_call_prepared_sites;
	}

	public function set_api_call_prepared_sites($api_call_prepared_sites)
	{
	    $this->api_call_prepared_sites = $api_call_prepared_sites;
	}
}