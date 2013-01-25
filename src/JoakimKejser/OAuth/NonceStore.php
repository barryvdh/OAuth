<?php
namespace JoakimKejser\OAuth;

interface NonceStore
{   
    /*
     * Lookup at nonce and if it doesn't exist save it
     */
    public function lookup(Consumer $consumer, $nonce, $timestamp, Token $token = null);
}
