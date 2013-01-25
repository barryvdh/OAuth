<?php
namespace JoakimKejser\OAuth;

interface TokenStore
{
    public function get(Consumer $consumer, $tokenType, $tokenField);

    public function newRequestToken(Consumer $consumer, $callback = null);

    public function newAccessToken(RequestToken $token, Consumer $consumer, $verifier = null);
}
