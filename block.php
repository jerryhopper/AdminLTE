<?php
header("Access-Control-Allow-Origin: *");
#header("Content-Type: Application/Javascript");

require_once ("vendor/autoload.php");

// Read setupVars.conf file
$setupVars = parse_ini_file("/etc/pihole/setupVars.conf");

//require "scripts/pi-hole/php/header.php";
require_once ("scripts/pi-hole/php/sw_functions.php");

function parse_cookie($str) {
    $cookies = array();
    $tok     = strtok($str, ';');
    while ($tok !== false) {
        $a                       = sscanf($tok, "%[^=]=%[^;]");
        $cookies[ltrim($a[0])][] = urldecode($a[1]);
        $tok                     = strtok(';');
    }
    return $cookies;
}

$cookie = parse_cookie($_SERVER['HTTP_COOKIE']);


$sw_functions= new SurfwijzerPiFunctions();
$auth = false;
if( isset($_GET['code'])   ) {
    // oAuth Redirect code.
    $token = false;
    try {
        $token = $sw_functions->exchangeCodeForToken($_GET['code']);
    } catch (\Exception $e) {
        die("XXXXXXXX".$e->getMessage() );
        // ERROR WITH TOKEN
        $auth = false;
        //break;
    }
}elseif(isset($cookie['oauthlogin'])){
    try{
        $sw_functions->validate( $cookie['oauthlogin'][0] );
        $auth=true;
    }catch(\Exception $e){
        $auth=false;
        #die($e->getMessage());
    }
}

#var_dump($auth);
#die();
/*
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

}*/

//$auth = false;
if( isset($cookie['oauthlogin']) ){




}

#print_r($cookie);




/*
if( $sw_functions->getTokenExpiry()-time()<10){

};

echo "<pre>";
echo $sw_functions->getTokenExpiry()-time();
//print_r($sw_functions);
echo "</pre>";

echo "<br>";
echo time();
echo "<br>";
echo $sw_functions->getTokenExpiry();
echo "<br>";
echo $sw_functions->getTokenOwner();
echo "<br>";
echo $sw_functions->getTokenOwnerEmail();
echo "<br>";
//echo ;
#die();

*/
//var_dump($auth);



// Remove external ipv6 brackets if any


if( isset($cookie['piblock']) && !isset($_GET['piblock'])){
    // Sanitise HTTP_HOST output
    $serverName = htmlspecialchars(base64_decode($cookie['piblock'][0]));
    $serverName = preg_replace('/^\[(.*)\]$/', '${1}', $serverName);


}else{
    // Sanitise HTTP_HOST output
    $serverName = htmlspecialchars(base64_decode($_GET['piblock']));
    $serverName = preg_replace('/^\[(.*)\]$/', '${1}', $serverName);


    if(!$auth){
        //setcookie("piblock",$serverName,120);
    }

}





if (!is_file("/etc/pihole/setupVars.conf"))
    die("[ERROR] File not found: <code>/etc/pihole/setupVars.conf</code>");

if (is_file("/etc/pihole/surfwijzerVars.conf"))
    $surfwijzerVars = parse_ini_file("/etc/pihole/surfwijzerVars.conf");

// Get values from setupVars.conf
$setupVars = parse_ini_file("/etc/pihole/setupVars.conf");
$svPasswd = !empty($setupVars["WEBPASSWORD"]);
$svEmail = (!empty($setupVars["ADMIN_EMAIL"]) && filter_var($setupVars["ADMIN_EMAIL"], FILTER_VALIDATE_EMAIL)) ? $setupVars["ADMIN_EMAIL"] : "";
unset($setupVars);

// Set mobile friendly viewport
$viewPort = '<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1"/>';


/* Start processing Block Page from here */

// Define admin email address text based off $svEmail presence
$bpAskAdmin = !empty($svEmail) ? '<a href="mailto:'.$svEmail.'?subject=Site Blocked: '.$serverName.'"></a>' : "<span/>";

// Determine if at least one block list has been generated
$blocklistglob = glob("/etc/pihole/list.0.*.domains");
if ($blocklistglob === array()) {
    die("[ERROR] There are no domain lists generated lists within <code>/etc/pihole/</code>! Please update gravity by running <code>pihole -g</code>, or repair Pi-hole using <code>pihole -r</code>.");
}

// Set location of adlists file
if (is_file("/etc/pihole/adlists.list")) {
    $adLists = "/etc/pihole/adlists.list";
} elseif (is_file("/etc/pihole/adlists.default")) {
    $adLists = "/etc/pihole/adlists.default";
} else {
    die("[ERROR] File not found: <code>/etc/pihole/adlists.list</code>");
}

// Get all URLs starting with "http" or "www" from adlists and re-index array numerically
$adlistsUrls = array_values(preg_grep("/(^http)|(^www)/i", file($adLists, FILE_IGNORE_NEW_LINES)));

if (empty($adlistsUrls))
    die("[ERROR]: There are no adlist URL's found within <code>$adLists</code>");

// Get total number of blocklists (Including Whitelist, Blacklist & Wildcard lists)
$adlistsCount = count($adlistsUrls) + 3;

// Set query timeout
ini_set("default_socket_timeout", 3);

// Logic for querying blocklists
function queryAds($serverName) {
    // Determine the time it takes while querying adlists
    $preQueryTime = microtime(true)-$_SERVER["REQUEST_TIME_FLOAT"];
    $queryAds = file("http://127.0.0.1/admin/scripts/pi-hole/php/queryads.php?domain=$serverName&bp", FILE_IGNORE_NEW_LINES);
    $queryAds = array_values(array_filter(preg_replace("/data:\s+/", "", $queryAds)));
    $queryTime = sprintf("%.0f", (microtime(true)-$_SERVER["REQUEST_TIME_FLOAT"]) - $preQueryTime);

    // Exception Handling
    try {
        // Define Exceptions
        if (strpos($queryAds[0], "No exact results") !== FALSE) {
            // Return "none" into $queryAds array
            return array("0" => "none");
        } else if ($queryTime >= ini_get("default_socket_timeout")) {
            // Connection Timeout
            throw new Exception ("Connection timeout (".ini_get("default_socket_timeout")."s)");
        } elseif (!strpos($queryAds[0], ".") !== false) {
            // Unknown $queryAds output
            throw new Exception ("Unhandled error message (<code>$queryAds[0]</code>)");
        }
        return $queryAds;
    } catch (Exception $e) {
        // Return exception as array
        return array("0" => "error", "1" => $e->getMessage());
    }
}

// Get results of queryads.php exact search
$queryAds = queryAds($serverName);

// Pass error through to Block Page
if ($queryAds[0] === "error")
    die("[ERROR]: Unable to parse results from <i>queryads.php</i>: <code>".$queryAds[1]."</code>");

// Count total number of matching blocklists
$featuredTotal = count($queryAds);

// Place results into key => value array
$queryResults = null;
foreach ($queryAds as $str) {
    $value = explode(" ", $str);
    @$queryResults[$value[0]] .= "$value[1]";
}

// Determine if domain has been blacklisted, whitelisted, wildcarded or CNAME blocked
if (strpos($queryAds[0], "blacklist") !== FALSE) {
    $notableFlagClass = "blacklist";
    $adlistsUrls = array("π" => substr($queryAds[0], 2));
} elseif (strpos($queryAds[0], "whitelist") !== FALSE) {
    $notableFlagClass = "noblock";
    $adlistsUrls = array("π" => substr($queryAds[0], 2));
    $wlInfo = "recentwl";
} elseif (strpos($queryAds[0], "wildcard") !== FALSE) {
    $notableFlagClass = "wildcard";
    $adlistsUrls = array("π" => substr($queryAds[0], 2));
} elseif ($queryAds[0] === "none") {
    $featuredTotal = "0";
    $notableFlagClass = "noblock";

    // QoL addition: Determine appropriate info message if CNAME exists
    // Suggests to the user that $serverName has a CNAME (alias) that may be blocked
    $dnsRecord = dns_get_record("$serverName")[0];
    if (array_key_exists("target", $dnsRecord)) {
        $wlInfo = $dnsRecord['target'];
    } else {
        $wlInfo = "unknown";
    }
}

// Set #bpOutput notification
$wlOutputClass = (isset($wlInfo) && $wlInfo === "recentwl") ? $wlInfo : "hidden";
$wlOutput = (isset($wlInfo) && $wlInfo !== "recentwl") ? "<a href='http://$wlInfo'>$wlInfo</a>" : "";

// Get Pi-hole Core version
$phVersion = exec("cd /etc/.pihole/ && git describe --long --tags");

// Print $execTime on development branches
// Testing for - is marginally faster than "git rev-parse --abbrev-ref HEAD"
if (explode("-", $phVersion)[1] != "0")
    $execTime = microtime(true)-$_SERVER["REQUEST_TIME_FLOAT"];





$r = array( "persistentlogin"=>$cookie['persistentlogin'][0], "oauthlogin"=>$cookie['oauthlogin'][0] );

?><!DOCTYPE html>
<!-- Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  This file is copyright under the latest version of the EUPL. -->
<html>
<head>
    <meta charset="UTF-8">
    <?=$viewPort ?>
    <meta name="robots" content="noindex,nofollow"/>
    <meta http-equiv="x-dns-prefetch-control" content="off">
    <link rel="shortcut icon" href="//pi.hole/admin/img/favicon.png" type="image/x-icon"/>
    <link rel="stylesheet" href="//pi.hole/pihole/blockingpage.css" type="text/css"/>
    <title>● <?=$serverName ?></title>
    <script src="//pi.hole/admin/scripts/vendor/jquery.min.js"></script>
    <script>
        window.onload = function () {
            <?php
            // Remove href fallback from "Back to safety" button
            if ($featuredTotal > 0) {
                echo '$("#bpBack").removeAttr("href");';

                // Enable whitelisting if JS is available
                echo '$("#bpWhitelist").prop("disabled", false);';

                // Enable password input if necessary
                if (!empty($svPasswd)) {
                    echo '$("#bpWLPassword").attr("placeholder", "Password");';
                    echo '$("#bpWLPassword").prop("disabled", false);';
                }
                // Otherwise hide the input
                else {
                    echo '$("#bpWLPassword").hide();';
                }
            }
            ?>
        }
    </script>
</head>
<body id="blockpagex"><div id="bpWrapper">
    <header>
        <h1 id="bpTitle">
            <a class="title" href="/"><?php //Website Blocked ?></a>
        </h1>

        <div class="spc"><?php echo $surfwijzerVars['installationId']?></div>

        <input id="bpAboutToggle" type="checkbox"/>
        <div id="bpAbout">
            <div class="aboutPH">
                <div class="aboutImg"/></div>
            <p>Open Source Ad Blocker
                <small>Designed for Raspberry Pi</small>
            </p>
        </div>
        <div class="aboutLink">
            <a class="linkPH" href="https://github.com/pi-hole/pi-hole/wiki/What-is-Pi-hole%3F-A-simple-explanation"><?php //About PH ?></a>
            <?php if (!empty($svEmail)) echo '<a class="linkEmail" href="mailto:'.$svEmail.'"></a>'; ?>
        </div>
</div>

<div id="bpAlt">
    <label class="altBtn" for="bpAboutToggle"><?php //Why am I here? ?></label>
</div>
</header>

<main>
    <div id="bpOutput" class="<?=$wlOutputClass ?>"><?=$wlOutput ?></div>
    <div id="bpBlock">
        <p class="blockMsg"><a href="http://<?=$serverName ?>"><?=$serverName ?></a></p>
    </div>

    <?php if(isset($notableFlagClass)) { ?>
        <div id="bpFlag">
            <p class="flagMsg <?=$notableFlagClass ?>"></p>
        </div>
    <?php } ?>

    <div id="bpHelpTxt"><?=$bpAskAdmin ?></div>
    <!---
    <div id="bpButtons" class="buttons">
        <a id="bpBack" onclick="javascript:history.back()" href="about:home"></a>
        <?php if ($featuredTotal > 0) echo '<label id="bpInfo" for="bpMoreToggle"></label>'; ?>
    </div>-->

    <style>
        #bpChoiceA:before { content: "Deblokkeer deze website"; }
        #bpChoiceA {
            background-color: #3c8dbc;

        }

        #bpChoiceB:before { content: "Breekt functionaliteit"; }
        #bpChoiceB {
            background-color: #a94442;

        }

        #bpChoiceC:before { content: "Foutief geblocked"; }
        #bpChoiceC {
            background-color: #00a65a;

        }
        #bpChoiceL:before { content: "Login"; }
        #bpChoiceL {
            background-color: #00a65a;

        }
    </style>
    <div class="row">
<?php
if($auth && $notableFlagClass!="noblock"){
?>
        <div id="bpButtons" class="buttons">
            <a id="bpChoiceA" onclick="javascript:add();return false;" href="#"></a>
        </div>
        <!---
        <br>
        <div id="bpButtons" class="buttons">
            <a id="bpChoiceB" onclick="javascript:history.back()" href="about:home"></a>
        </div>
        <br>
        <div id="bpButtons" class="buttons">
            <a id="bpChoiceC" onclick="javascript:history.back()" href="about:home"></a>
        </div> --->
    </div>
<?php
}else{
    ?>
    <div id="bpButtons" class="buttons">
        <button>UNBLOCK</button>>
        <a id="bpChoiceL" onclick="javascript:login();return false;" href="#"></a>
    </div>
    <?php
}
    ?>

    <input id="bpMoreToggle" type="checkbox">
    <div>
        <pre></pre>
            <?php //ECHO $cookie['oauthlogin'][0]; ?><br>
            <?php //echo $cookie['persistentlogin'][0]; ?><br>
            <?php
            $blockListCategorie = "";
            if ($featuredTotal > 0){
                foreach ($queryResults as $num => $value) {
                    if(strpos($adlistsUrls[$num],"blocklists.surfwijzer.nl") ){
                        $blockListCategorie = str_replace("https://blocklists.surfwijzer.nl/category/","",$adlistsUrls[$num]);
                    }
                }
            }
            //echo "<h1>Categorie: ".$blockListCategorie."</h1>";

            ?>
<!---
            <div class="form-group">
                <label for="exampleFormControlSelect1">Reden voor unblock? </label>
                <select id="swunblockreason" class="form-control" id="exampleFormControlSelect1">
                    <option>Persoonlijke whitelist</option>
                    <option>Breekt functionaliteit</option>
                    <option>Falsly Blocked</option>
                    <option>4</option>
                    <option>5</option>
                </select>
                <button type="submit" class="btn btn-primary" id="swunblock">Submit</button>
            </div>-->
            <div class="form-group">


            </div>

        <hr>
    </div>
    <div id="bpMoreInfoc">
        <!--- x --->
        <span id="bpFoundIn"><span><?=$featuredTotal ?></span><?=$adlistsCount ?></span>
        <!--- x --->
        <pre id='bpQueryOutput'><?php if ($featuredTotal > 0) foreach ($queryResults as $num => $value) { echo "<span>[$num]:</span>$adlistsUrls[$num]\n"; } ?></pre>
        <!--- x --->
        <?php

        if ($cookie['persistentlogin'][0]=="" && $cookie['oauthlogin'][0]==""){
            ?>
        <form id="bpWLButtons" class="buttons">
            <input id="bpWLDomain" type="text" value="<?=$serverName ?>" disabled/>
            <input id="bpWLPassword" type="password" placeholder="Javascript disabled" disabled/><button id="bpWhitelist" type="button" disabled></button>
        </form>
        <?php } ?>
    </div>
</main>

<footer><span><?=date("l g:i A, F dS"); ?>.</span> Pi-hole <?=$phVersion ?> (<?=gethostname()."/".$_SERVER["SERVER_ADDR"]; if (isset($execTime)) printf("/%.2fs", $execTime); ?>)</footer>
</div>

<script>

    /*
    postData('https://example.com/answer', { answer: 42 }).then((data) => {

        console.log(data); // JSON data parsed by `response.json()` call
    });
    */

    async function postData(url = '', data = {}) {
        // Default options are marked with *
        const response = await fetch(url, {
            method: 'POST', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'same-origin', // include, *same-origin, omit
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Bearer: '+ window.getCookie("oauthlogin"),
            },
            redirect: 'follow', // manual, *follow, error
            referrerPolicy: 'no-referrer', // no-referrer, *client
            body: JSON.stringify(data) // body data type must match "Content-Type" header
        });
        console.log(response);
        return await response.json(); // parses JSON response into native JavaScript objects
    }

    function login(){
        var domain = "<?=$serverName ?>";
        setCookie("piblock",domain,0.002);
        var redir = "https://idp.surfwijzer.nl/oauth2/authorize?response_type=code&scope=email&client_id=705dbbd8-0155-4e7e-9199-20b8e47388e5&state=&redirect_uri=http%3A%2F%2Fpi.hole%2Fadmin%2Findex.php"
        window.location = redir;
    }
    function setCookie(cname, cvalue, exdays) {
        var d = new Date();
        d.setTime(d.getTime() + (exdays*24*60*60*1000));
        var expires = "expires="+ d.toUTCString();
        document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
    }

    function add() {
        $("#bpOutput").removeClass("hidden error exception");
        $("#bpOutput").addClass("add");

        var reason = $("#swunblockreason option:selected" ).text();
        var domain = "<?=$serverName ?>";
        var pw = $("#bpWLPassword");
        if(domain.length === 0) {
            return;
        }
        console.log(reason);
        console.log(domain);
        console.log(pw);
        console.log(window.getCookie("oauthlogin"));

        $.ajax({
            url: "/admin/scripts/pi-hole/php/add.php",
            method: "post",
            data: {
                "domain":domain,
                "list":"white",
                "pw":pw.val()+"x",
                "reason": $("#swunblockreason option:selected" ).text()
            },
            success: function(response) {
                if(response.indexOf("Pi-hole blocking") !== -1) {
                    setTimeout(function(){window.location.reload(1);}, 10000);
                    $("#bpOutput").removeClass("add");
                    $("#bpOutput").addClass("success");
                    $("#bpOutput").html("");
                } else {
                    $("#bpOutput").removeClass("add");
                    $("#bpOutput").addClass("error");
                    $("#bpOutput").html(""+response+"");
                }
            },
            error: function(jqXHR, exception) {
                $("#bpOutput").removeClass("add");
                $("#bpOutput").addClass("exception");
                $("#bpOutput").html("");
            }
        });
        //originaladd();
        //postData('https://blocklists.surfwijzer.nl/whitelist', { domain: domain }).then((data) => {

            //console.log(data); // JSON data parsed by `response.json()` call
            //originaladd();
        //});

    }

    window.getCookie = function(name) {
        var match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        if (match) return match[2];
        return "anon";
    }

    function originaladd() {
        $("#bpOutput").removeClass("hidden error exception");
        $("#bpOutput").addClass("add");
        var domain = "<?=$serverName ?>";
        var pw = $("#bpWLPassword");
        if(domain.length === 0) {
            return;
        }
        $.ajax({
            url: "/admin/scripts/pi-hole/php/add.php",
            method: "post",
            data: {
                "domain":domain,
                "list":"white",
                "pw":pw.val(),
                "reason": $("#swunblockreason option:selected" ).text()
            },
            success: function(response) {
                if(response.indexOf("Pi-hole blocking") !== -1) {
                    setTimeout(function(){window.location.reload(1);}, 10000);
                    $("#bpOutput").removeClass("add");
                    $("#bpOutput").addClass("success");
                    $("#bpOutput").html("");
                } else {
                    $("#bpOutput").removeClass("add");
                    $("#bpOutput").addClass("error");
                    $("#bpOutput").html(""+response+"");
                }
            },
            error: function(jqXHR, exception) {
                $("#bpOutput").removeClass("add");
                $("#bpOutput").addClass("exception");
                $("#bpOutput").html("");
            }
        });
    }
    <?php if ($featuredTotal > 0) { ?>
    $(document).keypress(function(e) {
        if(e.which === 13 && $("#bpWLPassword").is(":focus")) {

            add();
        }
    });

    $("#swunblock").on("click", function() {
        add();
    });
    $("#bpWhitelist").on("click", function() {
        add();
    });
    <?php } ?>
</script>
</body></html>
