#OAuth
PSR2 Compliant OAuth 1.0 library base on **Andy Smith's** OAuth library found here:
http://oauth.googlecode.com/svn/code/php/

##2-Legged OAuth Server Example
```php
$request = JoakimKejser\OAuth\Request::createFromGlobals();

// Simple Example ConsumerStore using arrays
$consumerStore = new JoakimKejser\OAuth\ConsumerStore\ArrayConsumerStore(array('key' => 'secret', 'key2' => 'secret2'));

// Simple Example NonceStore using arrays - you should use a persistent store
$nonceStore = new JoakimKejser\OAuth\NonceStore\ArrayNonceStore();

// We don't need a TokenStore since we'll be doing Two Legged
$server = new JoakimKejser\OAuth\Server($request, $consumerStore, $nonceStore, null);

// Add the signature method you wanna support
$server->addSignatureMethod(new JoakimKejser\OAuth\SignatureMethod\HmacSha1);

try {
    list($consumer, $token) = $server->verifyRequest();
    echo "Welcome consumer with key: " . $consumer->key;
} catch (JoakimKejser\OAuth\Exception $e) {
    echo "Something went wrong: " . $e->getMessage();
}

```

##2-Legged OAuth Client Example
```php
$key = 'key';
$secret = 'secret';
$consumer = new JoakimKejser\OAuth\Consumer($key, $secret);

$sigMethod = new JoakimKejser\OAuth\SignatureMethod\HmacSha1;

$method = "POST";

//API endpoint to call
$api_endpoint = 'http://apiyouwanna/call';

//Create and sign the request - 2-Legged so token is null
$req = Request::createFromConsumerAndToken($consumer, $method, $api_endpoint, null);
$req->sign($sigMethod, $consumer, null); //Token is still null

$ch = curl_init();

$url = $req->getNormalizedHttpUrl();

// Get the URL for the GET request, without oauth parameters, as we'll add them to the Authorization header
if ($method == "GET") {
    $url = $req->toUrl(true);
}

// Set up CURL
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

// Add the Authorization header to the request
curl_setopt($ch, CURLOPT_HTTPHEADER, array($req->toHeader()));

// If it's post, add the post data
if ($method == "POST") {
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $req->toPostData(true));
}

// And go
$output = curl_exec($ch);
 
curl_close($ch);

echo $output;
```