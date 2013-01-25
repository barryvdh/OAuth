<?php
namespace JoakimKejser\OAuth;

class Consumer
{
    public $key;
    public $secret;

    public function __construct($key, $secret, $callbackUrl = null)
    {
        $this->key = $key;
        $this->secret = $secret;
    
    }

    public function __toString()
    {
        return "OAuthConsumer[key=$this->key,secret=$this->secret]";
    }
}
