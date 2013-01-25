<?php

use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use JoakimKejser\OAuth\Request;

class RequestTest extends PHPUNIT_Framework_TestCase
{

    public function testToStringNoParameters()
    {
        $request = new JoakimKejser\OAuth\Request("GET", "http://localhost/index.php");

        $this->assertEquals("http://localhost/index.php", (String) $request);

    }

    public function testToStringWithParameters()
    {
        $request = new Request("GET", "http://localhost/index.php", array('a' => '123', 'q' => "as", 'c' => '321'));

        $this->assertEquals("http://localhost/index.php?a=123&c=321&q=as", (String) $request);

    }

    public function testCreateFromRequest()
    {
        $request = $this->getRequest();

        $this->assertEquals(new Request('GET', 'http://localhost/index.php'), $request);
    }

    public function testCreateFromRequestPost()
    {
        $request = Request::createFromRequest(SymfonyRequest::create('/index.php', 'POST', array(), array(), array(), array(), "data=lotsofdata&action=doit"));

        $this->assertEquals(new Request('POST', 'http://localhost/index.php', array('data' => 'lotsofdata', 'action' => 'doit')), $request);
        $this->assertEquals('lotsofdata', $request->getParameter('data'));
        $this->assertEquals('doit', $request->getParameter('action'));

    }

    public function testCreateFromConsumerAndToken()
    {
        $consumer = new JoakimKejser\OAuth\Consumer('key', 'secret');

        $request = Request::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php');

        $this->assertEquals('key', $request->getParameter('oauth_consumer_key'));
        $this->assertEquals(Request::$version, $request->getParameter('oauth_version'));
        $this->assertTrue($request->getParameter('oauth_nonce') != null);
        $this->assertTrue(is_int($request->getParameter('oauth_timestamp')));
        $this->assertTrue($request->getParameter('oauth_timestamp') != null);

        return $request;
    }

    public function testCreateWithAuthorizationHeader()
    {

        $consumer = new JoakimKejser\OAuth\Consumer('key', 'secret');

        $request = Request::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php', null, array('foo' => 'bar'));

        $request->sign(new JoakimKejser\OAuth\SignatureMethod\HmacSha1, $consumer, null);

        // Strip the Authorization part as we will be providing the header directly to the Request as HTTP_AUTHORIZATION
        $authHeader = str_replace('Authorization: ', '', $request->toHeader());

        $server = array('HTTP_AUTHORIZATION' => $authHeader);

        $sRequest = SymfonyRequest::create('/index.php', 'POST', array(), array(), array(), $server);

        $request2 = Request::createFromRequest($sRequest);

        $this->assertNotNull($request2->getParameter('oauth_signature'));
        $this->assertNotNull($request2->getParameter('oauth_version'));
        $this->assertNotNull($request2->getParameter('oauth_consumer_key'));
        $this->assertNotNull($request2->getParameter('oauth_timestamp'));
        $this->assertNotNull($request2->getParameter('oauth_nonce'));
        $this->assertNotNull($request2->getParameter('oauth_signature_method'));

        $this->assertNull($request2->getParameter('oauth_token'));
    }

    /**
     * @depends testCreateFromConsumerAndToken
     **/
    public function testToHeaderWithRealm(Request $request)
    {
        $this->assertEquals('realm="testRealm"', substr($request->toHeader('testRealm'), 21, 17));
    }

    /**
     * @depends testCreateFromConsumerAndToken
     **/
    public function testSigningRequest(Request $request)
    {
        $signatureMethod = new JoakimKejser\OAuth\SignatureMethod\HmacSha1;

        $consumer = new JoakimKejser\OAuth\Consumer('key', 'secret');

        $this->assertNull($request->getParameter('oauth_signature'));
        $this->assertNull($request->getParameter('oauth_signature_method'));

        $request->sign($signatureMethod, $consumer);

        $oldSig = $request->getParameter('oauth_signature');

        $this->assertEquals('HMAC-SHA1', $request->getParameter('oauth_signature_method'));
        $this->assertEquals(28, strlen($request->getParameter('oauth_signature')));

        $request->sign($signatureMethod, $consumer);

        $this->assertEquals($oldSig, $request->getParameter('oauth_signature'));

    }

    /**
     * @depends testCreateFromConsumerAndToken
     **/
    public function testArraysInParameters(Request $request)
    {
        $request->setParameter('oauth_signature', array($request->getParameter('oauth_signature')));

        try {
            $request->toHeader();
        } catch (JoakimKejser\OAuth\Exception $e) {
            $this->assertTrue($e instanceOf JoakimKejser\OAuth\Exception\ArrayNotSupportedInHeaders);
        }
    }

    public function testCreateFromConsumerAndTokenWithToken()
    {
        $token = new JoakimKejser\OAuth\Token('tokenkey', 'tokensecret');
        $consumer = new JoakimKejser\OAuth\Consumer('key', 'secret');
        $request = Request::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php', $token, array('foo' => 'bar'));

        $this->assertEquals('tokenkey', $request->getParameter('oauth_token'));
    }

    public function testCreateFromGlobals()
    {
        $_SERVER = array(
            'HTTP_HOST' => 'localhost',
            'SERVER_PORT' => 80,
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/index.php'
        );

        $request = Request::createFromGlobals();

        $this->assertEquals(new Request('GET', 'http://localhost/index.php'), $request);
    }

    public function testGetNormalizedUri()
    {   
        $symfonyRequest = SymfonyRequest::create('http://localhost:80/index.php', 'GET');
        $request = Request::createFromRequest($symfonyRequest);

        $url = $request->getNormalizedHttpUrl();

        $this->assertEquals('http://localhost/index.php', $url);

        $symfonyRequest = SymfonyRequest::create('http://localhost:8080/index.php', 'GET');
        $request = Request::createFromRequest($symfonyRequest);

        $url = $request->getNormalizedHttpUrl();

        $this->assertEquals('http://localhost:8080/index.php', $url);
    }

    public function testUnsetParameter()
    {
        $request = $this->getRequest();

        $request->setParameter('foo','bar');

        $this->assertEquals($request->getParameter('foo'), 'bar');

        $request->unsetParameter('foo');

        $this->assertEquals($request->getParameter('foo'), null);
    }

    public function testSetParameter()
    {
        $request = $this->getRequest();

        $request->setParameter('foo', 'bar');

        $this->assertEquals($request->getParameter('foo'), 'bar');

        $request->setParameter('foo', 'baz', true);

        $this->assertEquals($request->getParameter('foo'), array('bar', 'baz'));
    }

    public function testToPostDataNoOAuth()
    {
        $consumer = new JoakimKejser\OAuth\Consumer('key', 'secret');

        $request = Request::createFromConsumerAndToken($consumer, 'POST', 'http://localhost/index.php', null, array('foo' => 'bar'));

        $request->sign(new JoakimKejser\OAuth\SignatureMethod\HmacSha1, $consumer, null);

        $postDataParameters = JoakimKejser\OAuth\Util::parseParameters($request->toPostData(true));

        $this->assertFalse(array_key_exists('oauth_signature', $postDataParameters));
        $this->assertTrue(array_key_exists('foo', $postDataParameters));

    }

    protected function getRequest($httpMethod = null, $httpUrl = null, $parameters = null)
    {
        return Request::createFromRequest(SymfonyRequest::create('/index.php', 'GET'));
    }
}