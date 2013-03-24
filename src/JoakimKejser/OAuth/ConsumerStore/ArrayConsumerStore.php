<?php
namespace JoakimKejser\OAuth\ConsumerStore;

use JoakimKejser\OAuth\Consumer;

class ArrayConsumerStore implements \JoakimKejser\OAuth\ConsumerStore
{
    protected $consumers;

    public function __construct(array $consumers)
    {
        $this->consumers = $consumers;
    }

    public function getConsumer($publicKey)
    {
        if (array_key_exists($publicKey, $this->consumers)) {
            return new Consumer($publicKey, $this->consumers[$publicKey]);
        }

        return null;
    }
}
