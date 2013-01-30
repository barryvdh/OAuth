<?php
namespace JoakimKejser\OAuth;

class Consumer
{
    public $key;
    public $secret;

    /**
     * Constructor
     * @param String $key
     * @param String $secret
     * @param String $callbackUrl
     */
    public function __construct($key, $secret, $callbackUrl = null)
    {
        $this->key = $key;
        $this->secret = $secret;
    
    }

    /**
     * To string
     * @return String
     */
    public function __toString()
    {
        return "OAuthConsumer[key=$this->key,secret=$this->secret]";
    }
}
