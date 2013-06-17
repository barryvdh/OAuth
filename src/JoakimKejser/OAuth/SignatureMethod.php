<?php
namespace JoakimKejser\OAuth;

/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */

abstract class SignatureMethod
{
    /**
    * Needs to return the name of the Signature Method (ie HMAC-SHA1)
    * @return String
    */
    abstract public function getName();

    /**
    * Build up the signature
    * NOTE: The output of this function MUST NOT be urlencoded.
    * the encoding is handled in OAuthRequest when the final
    * request is serialized
    * @param Request    $request
    * @param Consumer   $consumer
    * @param Token      $token
    * @return String
    */
    abstract public function buildSignature(Request $request, Consumer $consumer, Token $token);

    /**
    * Verifies that a given signature is correct
    * @param Request    $request
    * @param Consumer   $consumer
    * @param Token      $token
    * @param String $signature
    * @return boolean
    */
    public function checkSignature($signature, Request $request, Consumer $consumer, Token $token = null)
    {
        $built = $this->buildSignature($request, $consumer, $token);

        // Check for zero length, although unlikely here
        if (strlen($built) == 0 OR strlen($signature) == 0) {
            return false;
        }

        if (strlen($built) != strlen($signature)) {
            return false;
        }

        // Avoid a timing leak with a (hopefully) time insensitive compare
        $result = 0;
        for ($i = 0; $i < strlen($signature); $i++) {
            $result |= ord($built{$i}) ^ ord($signature{$i});
        }

        return $result == 0;
    }
}
