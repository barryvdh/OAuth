<?php

use JoakimKejser\OAuth\Util;
use JoakimKejser\OAuth\Request;

class UtilTest extends PHPUNIT_Framework_Testcase
{
    public function testUrlencodeRfc3986()
    {

    }

    public function testUrlDecodeRfc3986()
    {

    }

    public function testSplitHeader()
    {
        $consumer = new JoakimKejser\OAuth\Consumer('key', 'secret');
        $request = Request::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php');
        $request->sign(new JoakimKejser\OAuth\SignatureMethod\HmacSha1, $consumer);

        $headers = Util::splitHeader($request->toHeader());

        $this->assertEquals($request->getParameter('oauth_signature'), $headers['oauth_signature']);
        $this->assertEquals($request->getParameter('oauth_signature_method'), $headers['oauth_signature_method']);
        $this->assertEquals($request->getParameter('oauth_consumer_key'), $headers['oauth_consumer_key']);
        $this->assertEquals($request->getParameter('oauth_nonce'), $headers['oauth_nonce']);
        $this->assertEquals($request->getParameter('oauth_timestamp'), $headers['oauth_timestamp']);
    }

    public function testGetHeaders()
    {

    }

    public function testParseParameters()
    {

    }

    public function testBuildHttpQuery()
    {

    }
}
