<?php
namespace JoakimKejser\OAuth\NonceStore;

use JoakimKejser\OAuth\Consumer;
use JoakimKejser\OAuth\Token;

class ArrayNonceStore implements \JoakimKejser\OAuth\NonceStore
{
    protected $nonces;

    public function __construct(array $nonces = array())
    {
        $this->nonces = $nonces;
    }

    public function lookup(Consumer $consumer, $nonce, $timestamp, Token $token = null)
    {
        if (array_key_exists($nonce, $this->nonces)) {
            list($storedConsumer, $storedTimestamp, $storedToken) = $this->nonces[$nonce];

            if ($storedConsumer === $consumer AND $storedTimestamp === $timestamp AND $storedToken === $token) {
                return true;
            }
        }

        return false;
    }
}
