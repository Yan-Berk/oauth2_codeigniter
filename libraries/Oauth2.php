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

class Oauth2 {

	private $site;
	private $consumer_key;
	private $consumer_secret;
	private $redirect_url;
	private $scope;
	private $state;
	private $access_token;
	private $access_token_expires_in; 
	
	private $initial_urls = array (
				'facebook'	=> 'https://www.facebook.com/dialog/oauth/?',
				'linkedin'	=> 'https://www.linkedin.com/uas/oauth2/authorization?',
				'google'	=> 'https://accounts.google.com/o/oauth2/auth?'
			);
	
	private $response_urls = array (
				'facebook'	=> 'https://graph.facebook.com/oauth/access_token?',
				'linkedin'	=> 'https://www.linkedin.com/uas/oauth2/accessToken?',
				'google'	=> 'https://accounts.google.com/o/oauth2/token?'
			);
	
	private $api_urls = array (
				'facebook'	=> 'https://graph.facebook.com/me?access_token=',
				'linkedin'	=> 'https://api.linkedin.com/v1/people/~?oauth2_access_token=',
				'google'	=> 'https://www.googleapis.com/oauth2/v1/userinfo?access_token='
			);
	
	public $ci;
	
	
	public function __construct($input) {
		$this->ci = get_instance();
		$this->ci->load->database();
		$this->ci->load->helper('url');
		$this->ci->load->library('session');		
		
		
		$this->set_site($input['site']);
		$this->set_consumer_key($input['app_key']);
		$this->set_consumer_secret($input['app_secret']);
		$this->set_redirect_url($this->set_url($input['redirect_url']));
		$this->set_scope($input['scope']);
		
		$this->set_state($this->ci->session->userdata($this->get_site().'_oauth2_state'));
		$this->set_access_token($this->ci->session->userdata($this->get_site().'_oauth2_access_token'));
		$this->set_access_token_expires_in($this->ci->session->userdata($this->get_site().'_oauth2_access_token_expires_in'));		
	}

	/**
	 * Build the initial request URL.
	 */
	public function build_request_url() {
		$request_url = $this->get_request_url();
		$request_url .= $this->get_request_parameters();
		return $request_url;			
	}
	
	/**
	 * Build the first part of the initial URL.
	 */
	public function get_request_url() {
		return $this->initial_urls[$this->get_site()];
	}
	
	/**
	 * Get the required parameters for the initial URL.
	 */
	public function get_request_parameters() {
		$state = substr(md5(rand()), 0, 8);
		$this->ci->session->set_userdata($this->get_site().'_oauth2_state', $state);
	
		$query_params = array (
					'client_id' => $this->get_consumer_key(),
					'scope' => $this->get_scope(),
					'state' => $state,
					'redirect_uri' => $this->get_redirect_url()
		);
		
		if ($this->get_site() == 'linkedin' || $this->get_site() == 'google') {
			$query_params['response_type'] = 'code';
		}
		
		return http_build_query($query_params); 
	}	
	
	/**
	 * Check whether the response is valid, build the response URL and save the access token to session.
	 */
	public function retrieve_access_token() {
		if ($this->ci->input->get('state') != $this->ci->session->userdata($this->get_site().'_oauth2_state')) {
			return false;
		}
		
		if ($this->ci->input->get('error')) {
			
			//Handle error
			$this->ci->input->get('error_description');
		}
		
		if (!$this->ci->input->get('code')) {
			return false;
		}
		
		$request_url = $this->build_retrieve_access_token_url();
		
		return $this->save_access_token_data($request_url);
	}

	/**
	 * Build the response URL
	 */
	public function build_retrieve_access_token_url() {
		$request_url = $this->get_access_token_url();
		$request_url .= $this->get_access_token_parameters();
		return $request_url;			
	}
	
	
	/**
	 * Build the first part of the response URL.
	 */	
	public function get_access_token_url() {
		return $this->response_urls[$this->get_site()];
	}
	
	/**
	 * Get the parameters of the response URL 
	 */
	public function get_access_token_parameters() {

		$query_params = array (
							'code' => $this->ci->input->get('code'),
							'redirect_uri' => $this->get_redirect_url(),
							'client_id' => $this->get_consumer_key(),
							'client_secret' => $this->get_consumer_secret()
						);	
		if ($this->get_site() == 'linkedin' || $this->get_site() == 'google') {
			$query_params['grant_type'] = 'authorization_code';
		}
		return http_build_query($query_params);
	}
	
	/**
	 * Save the received access token and the time it expires on to session
	 * @param string $request_url
	 */
	public function save_access_token_data($request_url) {
		
		if ($this->get_site() == 'linkedin') {
			$result = json_decode(file_get_contents($this->get_access_token_url().$this->get_access_token_parameters()));
			if (!isset($result->access_token)) {
				return false;
			}
			$this->set_access_token($result->access_token);
			$this->set_access_token_expires_in($result->expires_in);
		}
		else if ($this->get_site() == 'facebook') {
			$result = file_get_contents($this->get_access_token_url().$this->get_access_token_parameters());
			$params = null;
			parse_str($result, $params);
			if (array_key_exists('access_token', $params)) {
				$this->set_access_token($params['access_token']);
				$this->set_access_token_expires_in($params['expires']);
			}
			else {
				return false;
			}
		}
		else if ($this->get_site() == 'google') {
			$result = json_decode($this->run_curl($this->get_access_token_url(), 'POST', $this->get_access_token_parameters()));
			if (!isset($result->access_token)) {
				return false;
			}
			$this->set_access_token($result->access_token);
			$this->set_access_token_expires_in($result->expires_in);
		}
		
		$this->ci->session->set_userdata($this->get_site().'_oauth2_access_token', $this->get_access_token());
		$this->ci->session->set_userdata($this->get_site().'_oauth2_access_token_expires_in', $this->get_access_token_expires_in());	
		return true;
	}
	
	/**
	 * Run a basic API call to test that the process was successful.
	 */
	public function api_call() {
		if ($this->get_site() == 'linkedin') {
			$results_xml = file_get_contents($this->api_urls[$this->get_site()].$this->get_access_token());
			return new SimpleXMLElement($results_xml);			
		}
		else if ($this->get_site() == 'facebook') {
			return json_decode(file_get_contents($this->api_urls[$this->get_site()].$this->get_access_token()));
		}
		else if ($this->get_site() == 'google') {	
			return json_decode(file_get_contents($this->api_urls[$this->get_site()].$this->get_access_token()));	
		}
	}
	/**
	 * Runs the cURL
	 * @param string $url
	 * @param string $type
	 * @param array $params
	 */
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

	public function get_scope()
	{
	    return $this->scope;
	}

	public function set_scope($scope)
	{
	    $this->scope = $scope;
	}
}