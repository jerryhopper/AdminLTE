<?php

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;


class SurfwijzerPiFunctions {

    var $installationId;

    var $oauthClientId       = "705dbbd8-0155-4e7e-9199-20b8e47388e5";
    var $oauthClientSecret   = "DOMJ0k7U5msfSTOVp6mOTkXzs41uYX5T_8nXxLIKUVw";

    var $oauthAuthorizeUrl   = "https://idp.surfwijzer.nl/oauth2/authorize";
    var $oauthTokenUrl       = "https://idp.surfwijzer.nl/oauth2/token";

    var $oauthIssuer         = "idp.surfwijzer.nl";

    private $tokenExpires    = "";
    private $tokenOwner      = "";
    private $tokenOwnerEmail  = "";
    private $token          = "";

    function __construct (){
        if( !file_exists("/etc/pihole/surfwijzerVars.conf") ){
            $this->installationId = "REINSTALLATION REQUIRED!";
        }else{
            $setupVars = parse_ini_file("/etc/pihole/surfwijzerVars.conf");
            $this->installationId = $setupVars['installationId'];
            #$this->oauthIssuer = $setupVars['oauthIssuer'];
            #$this->oauthClientId = $setupVars['oauthClientId'];
            #$this->oauthAuthorizeUrl = $setupVars['oauthAuthorizeUrl'];
            #$this->oauthTokenUrl = $setupVars['oauthTokenUrl'];



        }
    }

    public function getInstallationId(){
        return $this->installationId;
    }

    public function oAuthloginUrl(){
        return $this->oauthAuthorizeUrl."?response_type=code&scope=email&client_id=".$this->oauthClientId."&state=&redirect_uri=http%3A%2F%2Fpi.hole%2Fadmin%2Findex.php";
    }

    function exchangeCodeForToken($code){

        $curl = new CurlPost( $this->oauthTokenUrl );

        try {
            // execute the request
            $res = $curl([
                'code' => $code,
                'grant_type' => 'authorization_code',
                'redirect_uri'=>'http://pi.hole/admin/index.php',
                'client_id'=>$this->oauthClientId,
                'client_secret'=> $this->oauthClientSecret,
            ]);

        } catch (\RuntimeException $ex) {
            // catch errors
            die(sprintf('Http error %s with code %d', $ex->getMessage(), $ex->getCode()));
        }

        //echo "<pre>";
        $res = json_decode($res);

        if(isset($res->error) ){
            #$res->error_description;
            #$res->error_reason;
            #$res->error;
            throw new \Exception( $res->error." ".$res->error_description);
        }


        // test the token
        $this->validate( $res->access_token );


        #echo "<pre>";
        #print_r( $this->getTokenExpiry() );
        #print_r( $this->getTokenOwner() );
        #print_r( $this->getTokenOwnerEmail() );
        #echo "</pre>";

        #$res = explode(".",$res->access_token);
        //$res = '';
        #$res =  json_decode(base64_decode($res[1]) );
        return $res->access_token;
    }


    function validate( $token ){
        $time = time();
        $token = (new Parser())->parse((string) $token); // Parses from a string
        $token->getHeaders(); // Retrieves the token header
        //print_r($token->getClaims()); // Retrieves the token claims

        //echo $token->getHeader('email'); // will print "4f1g23a12aa"
        $email = $token->getClaim('email'); // will print "http://example.com"
        $expires = $token->getClaim('exp');
        $subject = $token->getClaim('sub');


        $dataWithLeeway = new ValidationData($time, 20);
        $dataWithLeeway->setIssuer($this->oauthIssuer);
        //$dataWithLeeway->setAudience('http://example.org');
        //$dataWithLeeway->setId('4f1g23a12aa');

        //var_dump($token->validate($dataWithLeeway)); // false, because token can't be used before now() + 60, not within leeway
        if(! $token->validate($dataWithLeeway) ){
            throw new \Exception("invalid_token");
        }

        $this->tokenExpires = $expires;
        $this->tokenOwnerEmail = $email;
        $this->tokenOwner = $subject;
        $this->token = $token;

        return true;
    }
    public function getBlockAdmins(){
        return array();
    }

    public function getToken(){
        return $this->token;
    }
    public function getTokenOwnerEmail(){
        return $this->tokenOwnerEmail;
    }
    public function getTokenOwner(){
        return $this->tokenOwner;
    }
    public function getTokenExpiry(){
        return $this->tokenExpires;
    }


}



class CurlPost
{
    private $url;
    private $options;

    /**
     * @param string $url     Request URL
     * @param array  $options cURL options
     */
    public function __construct($url, array $options = [])
    {
        $this->url = $url;
        $this->options = $options;
    }

    /**
     * Get the response
     * @return string
     * @throws \RuntimeException On cURL error
     */
    public function __invoke(array $post)
    {
        $ch = curl_init($this->url);

        foreach ($this->options as $key => $val) {
            curl_setopt($ch, $key, $val);
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);

        $response = curl_exec($ch);
        $error    = curl_error($ch);
        $errno    = curl_errno($ch);

        if (is_resource($ch)) {
            curl_close($ch);
        }

        if (0 !== $errno) {
            throw new \RuntimeException($error, $errno);
        }

        return $response;
    }
}


