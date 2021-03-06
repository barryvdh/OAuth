<?php
namespace JoakimKejser\OAuth\SignatureMethod;

use JoakimKejser\OAuth\OAuthUtil;
use JoakimKejser\OAuth\SignatureMethod;
use JoakimKejser\OAuth\Request;
use JoakimKejser\OAuth\Consumer;
use JoakimKejser\OAuth\Token;
use Joakimkejser\OAuth\Util;

/**
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used 
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 */
class Plaintext extends SignatureMethod
{
    public function getName()
    {
        return "PLAINTEXT";
    }

    /**
    * oauth_signature is set to the concatenated encoded values of the Consumer Secret and 
    * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is 
    * empty. The result MUST be encoded again.
    *   - Chapter 9.4.1 ("Generating Signatures")
    *
    * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
    * OAuthRequest handles this!
    */
    public function buildSignature(Request $request, Consumer $consumer, Token $token = null)
    {
        $keyParts = array(
            $consumer->secret,
            ($token) ? $token->secret : ""
        );

        $keyParts = Util::urlencodeRfc3986($keyParts);
        $key = implode('&', $keyParts);
        $request->setBaseString($key);

        return $key;
    }
}
