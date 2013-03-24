<?php
namespace JoakimKejser\OAuth;

interface TokenStore
{
    public function getToken(Consumer $consumer, $tokenType, $tokenField);

    public function newRequestToken(Consumer $consumer, $callback = null);

    public function newAccessToken(RequestToken $token, Consumer $consumer, $verifier = null);
}
