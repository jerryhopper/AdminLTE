<?php

class SurfwijzerPiFunctions {

    var $installationId;

    var $oauthClientId       = "705dbbd8-0155-4e7e-9199-20b8e47388e5";
    var $oauthAuthorizeUrl   = "https://idp.surfwijzer.nl/oauth2/authorize";

    function __construct (){

        if( !file_exists("/etc/pihole/surfwijzerVars.conf") ){
            $this->installationId = "REINSTALLATION REQUIRED!";
        }else{
            $setupVars = parse_ini_file("/etc/pihole/surfwijzerVars.conf");
            $this->installationId = $setupVars['installationId'];
        }


    }

    function getInstallationId(){
        return $this->installationId;
    }

    function oAuthloginUrl(){
        return $this->oauthAuthorizeUrl."?response_type=code&scope=email+openid&client_id=".$this->oauthClientId."&state=&redirect_uri=http%3A%2F%2Fpi.hole%2Fadmin%2Findex.php";
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



