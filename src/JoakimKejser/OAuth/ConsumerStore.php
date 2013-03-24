<?php
namespace JoakimKejser\OAuth;

interface ConsumerStore
{
    public function getConsumer($publicKey);
}
