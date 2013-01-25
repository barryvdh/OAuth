<?php
namespace JoakimKejser\OAuth;

interface ConsumerStore
{
    public function get($publicKey);
}
