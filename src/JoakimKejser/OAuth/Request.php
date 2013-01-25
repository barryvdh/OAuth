<?php
namespace JoakimKejser\OAuth;

use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class Request
{
    protected $parameters;
    protected $httpMethod;
    protected $httpUrl;

    // for debug purposes
    public $baseString;
    public static $version = '1.0';

    public function __construct($httpMethod, $httpUrl, $parameters = null)
    {
        $parameters = ($parameters) ? $parameters : array();
        $parameters = array_merge(Util::parseParameters(parse_url($httpUrl, PHP_URL_QUERY)), $parameters);
        $this->parameters = $parameters;
        $this->httpMethod = $httpMethod;
        $this->httpUrl = $httpUrl;
    }


    /**
    * attempt to build up a request from what was passed to the server
    */
    public static function createFromRequest(SymfonyRequest $symfonyRequest, $httpMethod = null, $httpUrl = null, $parameters = null)
    {
        $httpUrl = ($httpUrl) ? $httpUrl : $symfonyRequest->getSchemeAndHttpHost() . $symfonyRequest->getRequestUri();
        $httpMethod = ($httpMethod) ? $httpMethod : $symfonyRequest->getMethod();

        // We weren't handed any parameters, so let's find the ones relevant to
        // this request.
        // If you run XML-RPC or similar you should use this to provide your own
        // parsed parameter-list
        if ( ! $parameters) {
            // Find request headers
            $requestHeaders = Util::getHeaders($symfonyRequest, true);

            // Parse the query-string to find GET parameters
            $parameters = Util::parseParameters($symfonyRequest->getQueryString());

            // It's a POST request of the proper content-type, so parse POST
            // parameters and add those overriding any duplicates from GET
            if ($httpMethod == "POST" AND isset($requestHeaders['Content-Type']) AND strstr($requestHeaders['Content-Type'], 'application/x-www-form-urlencoded')) {
                $postData = Util::parseParameters(
                    $symfonyRequest->getContent()
                );
                $parameters = array_merge($parameters, $postData);
            }

            // We have a Authorization-header with OAuth data. Parse the header
            // and add those overriding any duplicates from GET or POST
            if (isset($requestHeaders['Authorization']) AND substr($requestHeaders['Authorization'], 0, 6) == 'OAuth ') {
                $headerParameters = Util::splitHeader($requestHeaders['Authorization']);
                $parameters = array_merge($parameters, $headerParameters);
            }

        }

        return new Request($httpMethod, $httpUrl, $parameters);
    }

    /**
     * Create the OAuth Request object from globals
     */
    public static function createFromGlobals($httpMethod = null, $httpUrl = null, $parameters = null)
    {
        return Request::createFromRequest(SymfonyRequest::createFromGlobals(), $httpMethod, $httpUrl, $parameters);
    }

    /**
    * pretty much a helper function to set up the request
    */
    public static function createFromConsumerAndToken(Consumer $consumer, $httpMethod, $httpUrl, Token $token = null, $parameters = null)
    {
        $parameters = ($parameters) ?  $parameters : array();
        $defaults = array(
            "oauth_version" => Request::$version,
            "oauth_nonce" => Request::generateNonce(),
            "oauth_timestamp" => Request::generateTimestamp(),
            "oauth_consumer_key" => $consumer->key
        );

        if ($token) {
            $defaults['oauth_token'] = $token->key;
        }

        $parameters = array_merge($defaults, $parameters);

        return new Request($httpMethod, $httpUrl, $parameters);
    }

    public function setParameter($name, $value, $allowDuplicates = true)
    {
        if ($allowDuplicates AND isset($this->parameters[$name])) {
            // We have already added parameter(s) with this name, so add to the list
            if (is_scalar($this->parameters[$name])) {
                // This is the first duplicate, so transform scalar (string)
                // into an array so we can add the duplicates
                $this->parameters[$name] = array($this->parameters[$name]);
            }

            $this->parameters[$name][] = $value;
        } else {
            $this->parameters[$name] = $value;
        }
    }

    public function getParameter($name)
    {
        return isset($this->parameters[$name]) ? $this->parameters[$name] : null;
    }

    public function getParameters()
    {
        return $this->parameters;
    }

    public function unsetParameter($name)
    {
        unset($this->parameters[$name]);
    }

    /**
    * The request parameters, sorted and concatenated into a normalized string.
    * @return string
    */
    public function getSignableParameters()
    {
        // Grab all parameters
        $params = $this->parameters;

        // Remove oauth_signature if present
        // Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
        if (isset($params['oauth_signature'])) {
            unset($params['oauth_signature']);
        }

        return Util::buildHttpQuery($params);
    }

    /**
    * Returns the base string of this request
    *
    * The base string defined as the method, the url
    * and the parameters (normalized), each urlencoded
    * and the concated with &.
    */
    public function getSignatureBaseString()
    {
        $parts = array(
            $this->getNormalizedHttpMethod(),
            $this->getNormalizedHttpUrl(),
            $this->getSignableParameters()
        );

        $parts = Util::urlencodeRfc3986($parts);

        return implode('&', $parts);
    }

    /**
    * just uppercases the http method
    */
    public function getNormalizedHttpMethod()
    {
        return strtoupper($this->httpMethod);
    }

    /**
    * parses the url and rebuilds it to be
    * scheme://host/path
    */
    public function getNormalizedHttpUrl()
    {
        $parts = parse_url($this->httpUrl);

        $scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
        $port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
        $host = (isset($parts['host'])) ? strtolower($parts['host']) : '';
        $path = (isset($parts['path'])) ? $parts['path'] : '';

        if (($scheme == 'https' AND $port != '443') OR ($scheme == 'http' AND $port != '80')) {
            $host = "$host:$port";
        }

        return "$scheme://$host$path";
    }

    /**
    * builds a url usable for a GET request
    */
    public function toUrl($noOAuthParameters = false)
    {
        $postData = $this->toPostdata($noOAuthParameters);
        $out = $this->getNormalizedHttpUrl();
        if ($postData) {
            $out .= '?'.$postData;
        }
        return $out;
    }

    /**
    * builds the data one would send in a POST request
    * strip the oauth parameters if request for when the authorization header is used
    */
    public function toPostData($noOAuthParameters = false)
    {
        $parameters = $this->getParameters();
        if ($noOAuthParameters === true) {
            foreach ($parameters as $k => $v) {
                if (substr($k, 0, 5) == "oauth") {
                    unset($parameters[$k]);
                }
            }
        }

        return Util::buildHttpQuery($parameters);
    }

    /**
    * builds the Authorization: header
    */
    public function toHeader($realm = null)
    {
        $first = true;
        if ($realm) {
            $out = 'Authorization: OAuth realm="' . Util::urlencodeRfc3986($realm) . '"';
            $first = false;
        } else {
            $out = 'Authorization: OAuth';
        }

        $total = array();
        foreach ($this->parameters as $k => $v) {
            if (substr($k, 0, 5) != "oauth") {
                continue;
            }
            if (is_array($v)) {
                throw new Exception\ArrayNotSupportedInHeaders();
            }
            $out .= ($first) ? ' ' : ',';
            $out .= Util::urlencodeRfc3986($k) . '="' . Util::urlencodeRfc3986($v) . '"';
            $first = false;
        }
        return $out;
    }

    public function __toString()
    {
        return $this->toUrl();
    }


    public function sign(SignatureMethod $signatureMethod, Consumer $consumer, Token $token = null)
    {
        $this->setParameter(
            "oauth_signature_method",
            $signatureMethod->getName(),
            false
        );
        $signature = $this->buildSignature($signatureMethod, $consumer, $token);
        $this->setParameter("oauth_signature", $signature, false);
    }

    public function buildSignature(SignatureMethod $signatureMethod, Consumer $consumer, Token $token = null)
    {
        $signature = $signatureMethod->buildSignature($this, $consumer, $token);
        return $signature;
    }

    public function setBaseString($baseString)
    {
        $this->baseString = $baseString;
    }

    /**
    * util function: current timestamp
    */
    private static function generateTimestamp()
    {
        return time();
    }

    /**
    * util function: current nonce
    */
    private static function generateNonce()
    {
        $mt = microtime();
        $rand = mt_rand();

        return md5($mt . $rand); // md5s look nicer than numbers
    }
}
