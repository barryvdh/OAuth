<?php
namespace JoakimKejser\OAuth;

use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class TwoLeggedServer extends Server
{

    public $request;

    protected $consumerStore;
    protected $nonceStore;


    public function __construct(Request $request, ConsumerStore $consumerStore, NonceStore $nonceStore)
    {
        $this->consumerStore = $consumerStore;

        $this->nonceStore = $nonceStore;

        $this->request = $request;
    }

    public static function createFromRequest(SymfonyRequest $symfonyRequest, ConsumerStore $consumerStore, NonceStore $nonceStore)
    {
        return new TwoLeggedServer(Request::createFromRequest($symfonyRequest), $consumerStore, $nonceStore);
    }

    public static function createFromGlobals(ConsumerStore $consumerStore, NonceStore $nonceStore)
    {
        return new TwoLeggedServer(Request::createFromGlobals(), $consumerStore, $nonceStore);
    }
}
