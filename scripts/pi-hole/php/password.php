<?php
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

    require_once('func.php');

    // Start a new PHP session (or continue an existing one)
    session_start();

    // Read setupVars.conf file
    $setupVars = parse_ini_file("/etc/pihole/setupVars.conf");
    // Try to read password hash from setupVars.conf
    if(isset($setupVars['WEBPASSWORD']))
    {
        $pwhash = $setupVars['WEBPASSWORD'];
    }
    else
    {
        $pwhash = "";
    }

    $wrongpassword = false;
    $auth = false;

    // If the user wants to log out, we free all session variables currently registered
    // and delete any persistent cookie.
    if(isset($_GET["logout"]))
    {
        session_unset();
        setcookie('persistentlogin', '');
        setcookie('oauthlogin', '');

        header('Location: index.php');
        exit();
    }elseif( (!isset($indexpage)  && isset($_GET['code'])  || isset($_GET['code'])  ) ){
        // oAuth Redirect code.
        $token = false;
        try{
            $token = $sw_functions->exchangeCodeForToken($_GET['code']);
        }catch(\Exception $e){
            ///die($e->getMessage() );
            // ERROR WITH TOKEN
            $auth=false;
            //break;
        }




        if(isset($setupVars['ADMIN_EMAIL']) && $token){
            if($sw_functions->getTokenOwnerEmail()==$setupVars['ADMIN_EMAIL']){

                setcookie('persistentlogin', $setupVars['WEBPASSWORD'], $sw_functions->getTokenExpiry() );
                setcookie('oauthlogin', $sw_functions->getToken(), $sw_functions->getTokenExpiry() );
                $_SESSION["hash"] = $setupVars['WEBPASSWORD'];
                $auth = true;
                //die("XXXXXXXXXXXXXX");
            }elseif(in_array($sw_functions->getTokenOwner(),$sw_functions->blockadmins() )){
                setcookie('persistentlogin', $setupVars['WEBPASSWORD'], $sw_functions->getTokenExpiry() );
                setcookie('oauthlogin', $sw_functions->getToken(), $sw_functions->getTokenExpiry() );
                $_SESSION["hash"] = $setupVars['WEBPASSWORD'];
                $auth = true;
            }else{
                $auth = false;
            }

        }elseif(!isset($setupVars['ADMIN_EMAIL']) && $token ){
            exec('sudo pihole -a -e \''.$sw_functions->getTokenOwnerEmail().'\'');
            setcookie('persistentlogin', $setupVars['WEBPASSWORD'], $sw_functions->getTokenExpiry() );
            setcookie('oauthlogin', $sw_functions->getToken(), $sw_functions->getTokenExpiry() );
            $_SESSION["hash"] = $setupVars['WEBPASSWORD'];
            $auth = true;
        }

    }

    if($auth && isset($_COOKIE['piblock'])){
        header("Location: http://pi.hole/admin/block.php?piblock=".base64_encode($_COOKIE['piblock']));
        //die($_COOKIE['piblock']);
    }
/*
    if(isset($_GET['code']) && isset($_GET['state'])){
        try{
            $res = $sw_functions->exchangeCodeForToken($_GET['code']);
            //$_COOKIE["oauthlogin"] = $sw_functions->getToken();

            //setcookie('oauthlogin', $sw_functions->getToken(), $sw_functions->getTokenExpiry() );

        }catch(\Exception $e){
            //die($e->getMessage() );
            echo $e->getMessage();
        }

    }*/
    #var_dump($res);
    #die();
    #error_log("Cookie is set");

    // Test if password is set
    if(strlen($pwhash) > 0)
    {
        // Check for and authorize from persistent cookie 
        if (isset($_COOKIE["persistentlogin"]))
        {
            //error_log("Cookie is set");

/*
            if ( $sw_functions->validate($_COOKIE["oauthlogin"]) ){
                // token is valid!
                $auth=true;
                //$sw_functions->getTokenExpiry();
                setcookie('oauthlogin', $_COOKIE["oauthlogin"], $sw_functions->getTokenExpiry() );
                setcookie('persistentlogin', $setupVars['WEBPASSWORD'], $sw_functions->getTokenExpiry());
                error_log("auth=true");

            }else{
                // token is invalid
                $auth=false;
                error_log("baahx");
                setcookie('oauthlogin', '');
                error_log("auth=false");
            }
*/

            if ($pwhash === $_COOKIE["persistentlogin"] && $auth==false)
            {
                //error_log("WTF? ".$_SERVER['SCRIPT_NAME']);
                $auth = true;
                // Refresh cookie with new expiry
                //setcookie('persistentlogin', $pwhash, time()+60*60*24*7);
            }
            else
            {
                //error_log("baah");
                // Invalid cookie
                $auth = false;
                setcookie('persistentlogin', '');
            }
        }
        // Compare doubly hashes password input with saved hash
        else if(isset($_POST["pw"]))
        {
            $postinput = hash('sha256',hash('sha256',$_POST["pw"]));
            if(hash_equals($pwhash, $postinput))
            {
                $_SESSION["hash"] = $pwhash;

                // Login successful, redirect the user to the homepage to discard the POST request
                if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['QUERY_STRING'] === 'login') {
                    // Set persistent cookie if selected
                    if (isset($_POST['persistentlogin']))
                    {
                        setcookie('persistentlogin', $pwhash, time()+60*60*24*7);
                    }
                    header('Location: index.php');
                    exit();
                }

                $auth = true;
            }
            else
            {
                $wrongpassword = true;
            }
        }
        // Compare auth hash with saved hash
        else if (isset($_SESSION["hash"]))
        {
            if(hash_equals($pwhash, $_SESSION["hash"]))
                $auth = true;
        }
        // API can use the hash to get data without logging in via plain-text password
        else if (isset($api) && isset($_GET["auth"]))
        {
            if(hash_equals($pwhash, $_GET["auth"]))
                $auth = true;
        }
        else
        {
            // Password or hash wrong
            $auth = false;
        }
    }
    else
    {
        // No password set

        $auth = true;
    }







/*
   oAuth login redirect occurred!
*/
if(!$auth && (!isset($indexpage)  && isset($_GET['code'])  || isset($_GET['code'])  ) )
{
    $scriptname = "login";

    #$_GET['userState'];
    #$_GET['code'];
    #$_GET['state'];


    try{
        //$sw_functions->exchangeCodeForToken($_GET['code']);
    }catch(\Exception $e){
        die($e->getMessage() );
    }
    // we are authenticated now.

    #echo "<pre>";
    #    print_r( $sw_functions->getTokenExpiry() );
    #    print_r( $sw_functions->getTokenOwner() );
    #    print_r( $sw_functions->getTokenOwnerEmail() );
    #echo "</pre>";

    //echo "<pre>";
    //print_r($setupVars['ADMIN_EMAIL']);

    //die($sw_functions->getTokenOwnerEmail());
/*
    if(isset($setupVars['ADMIN_EMAIL']) ){
        if($sw_functions->getTokenOwnerEmail()==$setupVars['ADMIN_EMAIL']){

            setcookie('persistentlogin', $setupVars['WEBPASSWORD'], $sw_functions->getTokenExpiry() );
            setcookie('oauthlogin', $sw_functions->getToken(), $sw_functions->getTokenExpiry() );
            $_SESSION["hash"] = $setupVars['WEBPASSWORD'];
            $auth = true;
            //die("XXXXXXXXXXXXXX");
        }

    }*/

}



?>
