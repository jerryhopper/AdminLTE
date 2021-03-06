<?php
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */


//sw_blacklist();

require_once('auth.php');

$type = $_POST['list'];

// Perform all of the authentication for list editing
// when NOT invoked and authenticated from API
if (empty($api)) {
    list_verify($type);
}

// Don't check if the added item is a valid domain for regex expressions. Regex
// filters are validated by FTL on import and skipped if invalid
if($type !== "regex") {
    check_domain();
}






function sw_blacklist(){

    $curl = new CurlPost('https://blocklists.surfwijzer.nl/blacklist');

    try {
        // execute the request
        echo $curl([
            'domain' => $_POST['domain'],
            'password' => 'passuser1',
            'gender'   => 1,
        ]);
    } catch (\RuntimeException $ex) {
        // catch errors
        die(sprintf('Http error %s with code %d', $ex->getMessage(), $ex->getCode()));
    }

}


switch($type) {
    case "white":
        if (!isset($_POST["auditlog"])) {
            echo shell_exec("sudo pihole -w ${_POST['domain']}");
            sw_blacklist();
        } else {
            echo shell_exec("sudo pihole -w -n ${_POST['domain']}");
            echo shell_exec("sudo pihole -a audit ${_POST['domain']}");
            sw_blacklist();
        }
        break;
    case "black":
        if (!isset($_POST["auditlog"])){
            echo shell_exec("sudo pihole -b ${_POST['domain']}");
            sw_blacklist();
        }
        else
        {
            echo shell_exec("sudo pihole -b -n ${_POST['domain']}");
            echo shell_exec("sudo pihole -a audit ${_POST['domain']}");
        }
        break;
    case "wild":
        // Escape "." so it won't be interpreted as the wildcard character
        $domain = str_replace(".","\.",$_POST['domain']);
        // Add regex filter for legacy wildcard behavior
        add_regex("(^|\.)".$domain."$");
        break;
    case "regex":
        add_regex($_POST['domain']);
        break;
    case "audit":
        echo exec("sudo pihole -a audit ${_POST['domain']}");
        break;
}

?>
