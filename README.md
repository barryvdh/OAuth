#OAuth
PSR2 Compliant OAuth 1.0 library base on **Andy Smith's** OAuth library found here:
http://oauth.googlecode.com/svn/code/php/

#2-Legged OAuth Server example
```php
$request = JoakimKejser\OAuth\Request::createFromGlobals();

// Simple Example ConsumerStore using arrays
$consumerStore = new JoakimKejser\OAuth\ConsumerStore\ArrayConsumerStore(array('key' => 'secret', 'key2' => 'secret2'));

// Simple Example NonceStore using arrays
$nonceStore = new JoakimKejser\OAuth\NonceStore\ArrayNonceStore();

// We don't need a TokenStore since we'll be doing Two Legged
$server = new JoakimKejser\OAuth\Server($request, $consumerStore, $nonceStore);

try {
    list($consumer, $token) = $server->verifyRequest();
} catch (JoakimKejser\OAuth\Exception $e) {
    echo "Something went wrong: " . $e->getMessage();
}

```