<?php
namespace JoakimKejser\OAuth;

class Server
{
    protected $timestampThreshold = 300; // in seconds, five minutes
    protected $version = '1.0';             // hi blaine
    protected $signatureMethods = array();

    protected $consumerStore;
    protected $nonceStore;
    protected $tokenStore;

    /**
     * Constructor
     * @param JoakimKejser\OAuth\Request       $request
     * @param JoakimKejser\OAuth\ConsumerStore $consumerStore
     * @param JoakimKejser\OAuth\NonceStore    $nonceStore
     * @param JoakimKejser\OAuth\TokenStore    $tokenStore
     */
    public function __construct(Request $request, ConsumerStore $consumerStore, NonceStore $nonceStore, TokenStore $tokenStore = null)
    {
        $this->request = $request;
        $this->consumerStore = $consumerStore;
        $this->nonceStore = $nonceStore;
        $this->tokenStore = $tokenStore;
    }

    /**
     * Adds a signature method to the server object
     *
     * Adds the signature method to the supported signature methods
     * 
     * @param JoakimKejser\OAuth\SignatureMethod $signatureMethod
     */
    public function addSignatureMethod(SignatureMethod $signatureMethod)
    {
        $this->signatureMethods[$signatureMethod->getName()] = $signatureMethod;
    }

    // high level functions

    /**
    * process a request_token request
    * returns the request token on success
    */
    public function fetchRequestToken()
    {
        $this->getVersion();

        $consumer = $this->getConsumer();

        // no token required for the initial token request
        $token = null;

        $this->checkSignature($consumer, $token);

        // Rev A change
        $callback = $this->request->getParameter('oauth_callback');
        $newToken = $this->tokenStore->newRequestToken($consumer, $callback);

        return $newToken;
    }

    /**
    * process an access_token request
    * returns the access token on success
    */
    public function fetchAccessToken()
    {
        $this->getVersion();

        $consumer = $this->getConsumer();

        // requires authorized request token
        $token = $this->getToken($consumer, "request");

        $this->checkSignature($consumer, $token);

        // Rev A change
        $verifier = $this->request->getParameter('oauth_verifier');
        $newToken = $this->tokenStore->newAccessToken($token, $consumer, $verifier);

        return $newToken;
    }

    /**
    * verify an api call, checks all the parameters
    */
    public function verifyRequest()
    {
        $this->getVersion();
        $consumer = $this->getConsumer();
        $token = $this->getToken($consumer, "access");
        $this->checkSignature($consumer, $token);

        return array($consumer, $token);
    }

    // Internals from here
    /**
    * version 1
    */
    private function getVersion()
    {
        $version = $this->request->getParameter("oauth_version");
        if ( ! $version) {
            // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
            // Chapter 7.0 ("Accessing Protected Ressources")
            $version = '1.0';
        }
        if ($version !== $this->version) {
            throw new Exception\VersionNotSupported();
        }

        return $version;
    }

    /**
    * figure out the signature with some defaults
    */
    private function getSignatureMethod()
    {
        $signatureMethod = $this->request->getParameter("oauth_signature_method");

        if ( ! $signatureMethod) {
            // According to chapter 7 ("Accessing Protected Ressources") the signature-method
            // parameter is required, and we can't just fallback to PLAINTEXT
            throw new Exception\SignatureMethodMissing();
        }

        if ( ! in_array($signatureMethod, array_keys($this->signatureMethods))) {
            throw new Exception\SignatureMethodNotSupported(
                "Signature method '$signature_method' not supported, try one of the following: " .
                implode(", ", array_keys($this->signatureMethods))
            );
        }
        return $this->signatureMethods[$signatureMethod];
    }

    /**
    * try to find the consumer for the provided request's consumer key
    */
    private function getConsumer()
    {
        $consumerKey = $this->request->getParameter("oauth_consumer_key");

        if ( ! $consumerKey) {
            throw new Exception\ConsumerKeyMissing();
        }

        $consumer = $this->consumerStore->get($consumerKey);
        if ( ! $consumer) {
            throw new Exception\InvalidConsumer();
        }

        return $consumer;
    }

    /**
    * try to find the token for the provided request's token key
    */
    private function getToken(Consumer $consumer, $tokenType = "access")
    {
        if ($this->tokenStore === null) {
            return null;
        }

        $tokenField = $this->request->getParameter('oauth_token');

        $token = $this->tokenStore->get(
            $consumer,
            $tokenType,
            $tokenField
        );

        if ( ! $token) {
            throw new Exception\InvalidToken("Invalid $token_type token: $token_field");
        }

        return $token;
    }

    /**
    * all-in-one function to check the signature on a request
    * should guess the signature method appropriately
    */
    private function checkSignature(Consumer $consumer, Token $token = null)
    {
        // this should probably be in a different method
        $timestamp = $this->request->getParameter('oauth_timestamp');
        $nonce = $this->request->getParameter('oauth_nonce');

        $this->checkTimestamp($timestamp);
        $this->checkNonce($consumer, $nonce, $timestamp, $token);

        $signatureMethod = $this->getSignatureMethod($this->request);

        $signature = $this->request->getParameter('oauth_signature');
        $validSig = $signatureMethod->checkSignature(
            $signature,
            $this->request,
            $consumer,
            $token
        );

        if ( ! $validSig) {
            throw new Exception\InvalidSignature();
        }
    }

    /**
    * check that the timestamp is new enough
    */
    private function checkTimestamp($timestamp)
    {
        if ( ! $timestamp ) {
            throw new Exception\TimestampMissing();
        }

        // verify that timestamp is recentish
        $now = time();
        if (abs($now - $timestamp) > $this->timestampThreshold) {
            throw new Exception\TimestampExpired();
        }
    }

    /**
    * check that the nonce is not repeated
    */
    private function checkNonce(Consumer $consumer, $nonce, $timestamp, Token $token = null)
    {
        if ( ! $nonce ) {
            throw new Exception\NonceMissing();
        }

        // verify that the nonce is uniqueish
        $found = $this->nonceStore->lookup(
            $consumer,
            $nonce,
            $timestamp,
            $token
        );

        if ($found) {
            throw new Exception\NonceAlreadyUsed();
        }
    }
}
