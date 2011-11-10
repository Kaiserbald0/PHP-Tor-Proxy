<?php

/**
 * Description of proxyConnector
 *
 * PHP5 class for interfacing php with the Tor network,
 * the proxy host is fully configurable by the user,
 * so the class is not limited to only the Tor
 * network.
 *
 * by Marco Baldini <info@marcobaldini.com>
 *
 * Licensed: GNU General Public License, version 2 (GPLv2)
 *
 * The default setting however is to run
 * through the Tor/Polipo network.
 *
 * New identity are changed using hashed password,
 * remember to configure your Tor Proxy to allow this.
 *
 * @author Marco Baldini 
 *
 * @copyright 2011 Marco Baldini
 *
 * @license GNU General Public License, version 2 (GPLv2)
 *
 * @version proxyConnector 1.1 TorVersion (28/01/2011)
 *
 * @example index.php
 *
 * Based on TOR Class by Josh Sandlin <josh@thenullbyte.org>
 */

class proxyConnector {


    private static $instance;

    private $destinationUrl;
    private $userAgent;
    private $timeout;
    private $vector;
    private $payload;
    private $returnData;
    private $ip;
    private $port;
    private $controlPort;
    private $controlPassword;
    private $switchIdentityAfterRequest = true;


    ##PUBLIC
    public static function getIstance()
    {
        if (!isset(self::$instance)) {
            $c = __CLASS__;
            self::$instance = new $c;
        }

        return self::$instance;
    }


    /**
     *
     * SetUp the proxy configuration
     *
     * @param string $extIp Proxy Ip
     * @param number $extPort  Proxy Port
     */
    public function setProxy($extIp="127.0.0.1", $extPort="8118")
    {
        $this->ip = $extIp;
        $this->port =$extPort;

    }

    /**
     *
     * SetUp the control information
     * used by a Tor proxy to renew identity
     *
     * @param string $extPort Proxy Ip
     * @param number $extPassword Proxy Control Port
     */
    public function setControlParameters($extPort, $extPassword)
    {
        $this->controlPassword = '"'.$extPassword.'"';
        $this->controlPort = $extPort;

    }

   /**
    *
    * Request a remote url using Curl
    *
    * @param string $extUrl
    * @param string $extVector
    * @param number $extTimeout
    */
   public function launch($extUrl, $extVector, $extTimeout = null)
    {
        //set parameters
        $this->destinationUrl = str_replace(" ","%20",$extUrl);
        $this->vector =$extVector;
        
        $this->setUserAgent();

        //set payload
        $this->setPayload();

        //if a timeout is set in the args, use it
        if(isset($timeout))
        {
            $this->timeout = $extTimeout;
        }

        //run cURL action against url
        $this->setCurl();

        //renew identity
        if ($this->switchIdentityAfterRequest) {
            $this->newIdentity();
            $this->setUserAgent();
        }
    }

    /**
     *
     * Return downloaded data from the proxy
     *
     * @return array
     *          url: requested url
     *          userAgent: used userAgent
     *          timeout: used timeout
     *          proxy: proxy address
     *          payload: payload
     *          return: url content
     */
    public function getProxyData()
    {
        return array(
                'url' => $this->destinationUrl,
                'userAgent' => $this->userAgent,
                'timeout' => $this->timeout,
                'proxy' => $this->ip .":". $this->port,
                'payload' => $this->payload,
                'return' => $this->returnData
        );
    }


    /**
     *
     * Change identity in the Tor Network
     * (change public IP Address)
     *
     * @return bool
     *          true is new identity is created
     *          false is fail creating a new identity
     */
    public function newIdentity(){
            $fp = fsockopen($this->ip, $this->controlPort, $errno, $errstr, 30);
            if (!$fp) return false; //can't connect to the control port

            fputs($fp, "AUTHENTICATE ".$this->controlPassword."\r\n");
            $response = fread($fp, 1024);
            list($code, $text) = explode(' ', $response, 2);
            if ($code != '250') return false; //authentication failed

            //send the request to for new identity
            fputs($fp, "signal NEWNYM\r\n");
            $response = fread($fp, 1024);
            list($code, $text) = explode(' ', $response, 2);
            if ($code != '250') return false; //signal failed

            fclose($fp);
            return true;
    }


    /**
     * Load the default configuration for the proxy connection
     * located in "proxyConfiguration.ini"
     */
    public function loadDefaultSetUp() {

        $loaded_ini_array = parse_ini_file("./proxyConfiguration.ini",TRUE);

        $this->destinationUrl = null;
        $this->userAgent = null;
        $this->vector = null;
        $this->payload = null;
        $this->returnData = null;

        $this->timeout = $loaded_ini_array["general"]["timeout"];
        $this->ip = $loaded_ini_array["general"]["ip"];
        $this->port = $loaded_ini_array["general"]["port"];
        $this->controlPort = $loaded_ini_array["TOR"]["controlPort"];
        $this->controlPassword = '"'.$loaded_ini_array["TOR"]["controlPassword"].'"';
        $this->switchIdentityAfterRequest = $loaded_ini_array["TOR"]["switchIdentityAfterRequest"];
    }


    ##PRIVATE
    private function  __construct() {
        $this->loadDefaultSetUp();
    }

    private function setUserAgent()
    {
        //list of browsers
        $agentBrowser = array(
                'Firefox',
                'Safari',
                'Opera',
                'Flock',
                'Internet Explorer',
                'Seamonkey',
                'Konqueror',
                'GoogleBot'
        );
        //list of operating systems
        $agentOS = array(
                'Windows 3.1',
                'Windows 95',
                'Windows 98',
                'Windows 2000',
                'Windows NT',
                'Windows XP',
                'Windows Vista',
                'Redhat Linux',
                'Ubuntu',
                'Fedora',
                'AmigaOS',
                'OS 10.5'
        );
        //randomly generate UserAgent
        $this->userAgent = $agentBrowser[rand(0,7)].'/'.rand(1,8).'.'.rand(0,9).' (' .$agentOS[rand(0,11)].' '.rand(1,7).'.'.rand(0,9).'; en-US;)';
    }


    private function setCurl()
    {
        $action = curl_init();
        curl_setopt($action, CURLOPT_PROXY, $this->ip .":". $this->port);
        curl_setopt($action, CURLOPT_URL, $this->payload);
        curl_setopt($action, CURLOPT_HEADER, 1);
        curl_setopt($action, CURLOPT_USERAGENT, $this->userAgent);
        curl_setopt($action, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($action, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($action, CURLOPT_TIMEOUT, $this->timeout);
        $this->returnData = curl_exec($action);
        curl_close($action);
    }

    private function setPayload()
    {
        $this->payload = $this->destinationUrl . $this->vector;
    }

    private function  __clone() {
        trigger_error("Clonig not allowed");
    }


}
