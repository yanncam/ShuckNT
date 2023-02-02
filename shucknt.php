<?php
/*
 __ _                _        __  _____
/ _\ |__  _   _  ___| | __ /\ \ \/__   \
\ \| '_ \| | | |/ __| |/ //  \/ /  / /\/
_\ \ | | | |_| | (__|   </ /\  /  / /
\__/_| |_|\__,_|\___|_|\_\_\ \/   \/  v1.0
DES-based authentication token shucker (https://shuck.sh)
@author : ycam | @asafety.fr / @yann.cam

ShuckNT is design to dowgrade, convert, dissect and shuck authentication token based on Data Encryption Standard (DES).
Algorithms / formats supported :
        - NetNTLMv1(-ESS/SSP)
	- MSCHAPv2
        - NET(NT)LM
        - (LM|NT)HASH
        - PPTP-VPN $99$
	- All with any challenge value!

ShuckNT rely on "hash shucking" principle to optimize challenge-response cracking and exploitability.

From a list of input tokens, ShuckNT provides :
- The NT-hash instantly (pass-the-hash ready) through a smart-research in the HaveIBeenPwned latest database (if present);
- The Crack.Sh ready-to-use optimized token, to pay less or nothing if NT-hash not found in HIBP-DB;
- Several converted formats to try to crack them via other tools (hashcat, jtr, CloudCracker, etc.) :
        - Hashcat mode 5500 : to crack NetNTLMv1 to plaintext (unpredictable result, depend on wordlists, masks, rules...);
        - Hashcat mode 27000: to shuck NetNTLMv1 to NT-hash (unpredictable result / depend on NT-wordlists...);
        - Hashcat mode 14000: to shuck NetNTLMv1 to DES-keys then NT-hash (100% result / time needed);
- All the details of the dissection of the challenge-response (PT1/2/3, K1/2/3, CT1/2/3, HIBP occurences/candidates, LMresp, NTresp, challenges, etc.).
*/

/* You can customize the constants here */
if(!defined("MAX_HASH_LENGTH")) define("MAX_HASH_LENGTH", 255); // Maximum number of characters in a single token (default 255) (for web and CLI inputs)
if(!defined("MAX_HASH_NUMBER")) define("MAX_HASH_NUMBER", 500); // Maximum number of tokens to be processed at once (default 500) (for web inputs only)
if(!defined("HIBP_REVERSED_ORDERED_WORDLIST_BIN")) define("HIBP_REVERSED_ORDERED_WORDLIST_BIN", "./pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin"); // Default HIBP database path

/* #######################################################################################################
Do not modify anything afterwards
####################################################################################################### */
define("SHUCKNT_VERSION", "1.0");

$shortopts  = "h";	// -h (help)
$shortopts .= "f:";     // -f inputs.txt
$shortopts .= "i:";     // -i '$99$1a7F1qr2HihoXfs/56u5XMdpDZ83N6hW/HI='
$shortopts .= "w:";     // -w wordlist-nthash-reversed-ordered-by-hash.bin
$shortopts .= "o:";     // -o json
$shortopts .= "v";      // -v (verbose output with all details)
$shortopts .= "r:";     // -r 'pwned-passwords-ntlm-ordered-by-hash-v8.txt' (reverse hashes)
$shortopts .= "b:";     // -b 'pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed-sorted' (binarize DB)
$shortopts .= "t:";     // -t 'pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin' (to output file)
$shortopts .= "j";      // -j (no display header for json output)

$options = getopt($shortopts);

$help		= (is_array($options) && array_key_exists("h", $options));
$inputHash      = (is_array($options) && array_key_exists("i", $options) && !empty($options["i"])) ? trim($options["i"]) : "";
$inputFile      = (is_array($options) && array_key_exists("f", $options) && is_readable($options["f"])) ? $options["f"] : "";
$wordlistFile   = (is_array($options) && array_key_exists("w", $options) && is_readable($options["w"])) ? $options["w"] : HIBP_REVERSED_ORDERED_WORDLIST_BIN;
$verbosity      = (is_array($options) && array_key_exists("v", $options));
$outputFormat   = (is_array($options) && array_key_exists("o", $options) && in_array($options["o"], array("json", "web", "stdout"))) ? $options["o"] : ((php_sapi_name() === "cli") ? "stdout" : "web");
$reverseFile   	= (is_array($options) && array_key_exists("r", $options) && is_readable($options["r"])) ? $options["r"] : "";
$binarizeFile   = (is_array($options) && array_key_exists("b", $options) && is_readable($options["b"])) ? $options["b"] : "";
$toFile   	= (is_array($options) && array_key_exists("t", $options) && !file_exists($options["t"])) ? $options["t"] : "";
$noHeader   	= (is_array($options) && array_key_exists("j", $options));

printHeader($wordlistFile, $noHeader);

if($help)
	printHelp(); 				// auto exit
if($reverseFile !== "")
	reverseHIBPDB($reverseFile, $toFile); 	// auto exit
if($binarizeFile !== "")
	binarizeHIBPDB($binarizeFile, $toFile);	// auto exit

$inputs = getHashes($inputFile, $inputHash);
if(count($inputs) === 0) return;

$start = time();
$reversect3toNTLMs = array();
$inputs = extractDataFromHash($inputs, $reversect3toNTLMs);
$reversect3toNTLMs = array_unique($reversect3toNTLMs);
sort($reversect3toNTLMs);
$reversect3toNTLMs = array_flip($reversect3toNTLMs);
$reversect3toNTLMs = getHashNTCandidates($reversect3toNTLMs, $wordlistFile);
foreach($inputs AS $hash => &$data){
	$data["candidates"] = &$reversect3toNTLMs[$data["reversePt3"]];
	$data["HIBPcountCandidates"] = count($data["candidates"])-1; // -1 to not count the empty-NThash
	foreach($data["candidates"] AS $id => $candidate){
		if( computeCtPartFromDesKeyChall($candidate["des01"], $data["challenge"]) === $data["ct1"] &&
			computeCtPartFromDesKeyChall($candidate["des02"], $data["challenge"]) === $data["ct2"]){
			$data["HIBPoccurence"] = $candidate["occurence"];
			$data["deskeys"]["k1"] = $candidate["des01"];
			$data["deskeys"]["k2"] = $candidate["des02"];
			$data["pt1"] = des2ntlm($data["deskeys"]["k1"]);
			$data["pt2"] = des2ntlm($data["deskeys"]["k2"]);
			$data["nthash"] = $data["pt1"] . $data["pt2"] . $data["pt3"];
			unset($data["candidates"][$id]);
			array_unshift($data["candidates"], $candidate); // if DES keys match, place it at the begining of candidates array for other same hashes
			continue;
		}
	}
}
foreach($inputs AS $hash => &$data)
	unset($data["candidates"]);
unset($reversect3toNTLMs); // delete all candidates to free memory
usort($inputs,  function($a, $b){ // sort results by NThash cracked first, then free crack.sh token, then others.
			return [$b["nthash"], $b["crackshToken"], $b["token"]] <=> [$a["nthash"], $a["crackshToken"], $a["token"]];
                });
displayOutput($inputs, $outputFormat, $verbosity);

function printHeader($wordlistFile, $noHeader){
	if(defined("NO_DISPLAY_HEADER") || $noHeader) return;
	if(php_sapi_name() === "cli") {
		$h =  " __ _                _        __  _____\n";
		$h .= "/ _\ |__  _   _  ___| | __ /\ \ \/__   \\\n";
		$h .= "\ \| '_ \| | | |/ __| |/ //  \/ /  / /\/\n";
		$h .= "_\ \ | | | |_| | (__|   </ /\  /  / /\n";
		$h .= "\__/_| |_|\__,_|\___|_|\_\_\ \/   \/  v".SHUCKNT_VERSION."\n";
		$h .= "DES-based authentication token shucker (https://shuck.sh)\n";
		$h .= "@author : ycam | @asafety.fr / @yann.cam\n";
		$h .= "\n";
		$h .= "ShuckNT is design to dowgrade, convert, dissect and shuck authentication token based on Data Encryption Standard (DES).\n";
		$h .= "Algorithms / formats supported :\n";
		$h .= "        - NetNTLMv1(-ESS/SSP)\n";
		$h .= "        - MSCHAPv2\n";
		$h .= "        - NET(NT)LM\n";
		$h .= "        - (LM|NT)HASH\n";
		$h .= "        - PPTP-VPN $99$\n";
		$h .= "        - All with any challenge value!\n";
		$h .= "\n";
		$h .= "ShuckNT rely on \"hash shucking\" principle to optimize challenge-response cracking and exploitability.\n";
		$h .= "\n";
		$h .= "From a list of input tokens, ShuckNT provides :\n";
		$h .= "- The NT-hash instantly (pass-the-hash ready) through a smart-research in the HaveIBeenPwned latest database (if present);\n";
		$h .= "- The Crack.Sh ready-to-use optimized token, to pay less or nothing if NT-hash not found in HIBP-DB;\n";
		$h .= "- Several converted formats to try to crack them via other tools (hashcat, jtr, CloudCracker, etc.) :\n";
		$h .= "        - Hashcat mode 5500 : to crack NetNTLMv1 to plaintext (unpredictable result, depend on wordlists, masks, rules...);\n";
		$h .= "        - Hashcat mode 27000: to shuck NetNTLMv1 to NT-hash (unpredictable result / depend on NT-wordlists...);\n";
		$h .= "        - Hashcat mode 14000: to shuck NetNTLMv1 to DES-keys then NT-hash (100% result / time needed);\n";
		$h .= "- All the details of the dissection of the challenge-response (PT1/2/3, K1/2/3, CT1/2/3, HIBP occurences/candidates, LMresp, NTresp, challenges, etc.).\n\n";
		$h .= "Use '-h' to print help.\n";
		echo $h;
	} else {
		echo "<style>.header, h1, #shuckingresults{font-family: Arial, Geneva, Helvetica, sans-serif;}</style><div class='header'>";
		echo "<h1>ShuckNT v".SHUCKNT_VERSION." : Shuck hash before trying to crack it | <a href='https://shuck.sh' target='_blank'>Shuck.sh</a>'s script</h1>";
		echo "<h2>NetNTLMv1(-ESS/SSP)/MSCHAPv2/PPTP-VPN to HIBP-NT-Hash / Hashcat / Crack.sh optimizer</h2>";
		echo "<p>";
		echo "This tool extract all usefull information from a MSCHAPv2/PPTP-VPN/NetNTLMv1 with/without Extended Session Security (ESS/SSP) and with any challenge's value.<br />";
		echo "From these data, several ways to break tokens are tried :<br />";
		echo "<ul>";
		echo "<li>Smart-research of the NT-Hash (Pass-the-Hash ready) into the HIBP NTLM wordlist is done in very efficient way (result instantly).</li>";
		echo "<li>Crack.sh token ready-to-use dowgraded (to pay less) on the https://crack.sh website to gain the NT-Hash corresponding (from $0 to $200 depending on the challenge and ESS/SSP).</li>";
		echo "<li>Hashcat DES-KPA (mode 14000) ready-to-crack format to convert to NT-Hash corresponding (Pass-the-Hash ready) (several days of cryptanalysis).</li>";
		echo "<li>Hashcat NetNTLMv1 (mode 5500 or 27000) ready-to-crack format to gain plaintext or NT-hash.</li>";
		echo "</ul>";
		echo "<i>Paste input tokens bellow, one per line. Max token length : " . MAX_HASH_LENGTH . " and max number of tokens submited at once : ". MAX_HASH_NUMBER .".</i><br />";
		echo "<i>Current HIBP NT-Hash wordlist used : " . $wordlistFile . " (#Hash candidates : " . number_format(intval(filesize($wordlistFile)/20)) . ")</i>";
		echo "</p>";
		echo "<form action='' method='post'>";
		echo "<textarea id='inputs' name='inputs' placeholder='";
		echo "user::domain.tld:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788\n";
		echo "ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788\n";
		echo '$MSCHAPv2$1337133713371337$F93A1DB1C044133F52582EFDA5C31667EBBE6F8F2814E539$root'."\n";
		echo '$NETLM$FE2CFD84F6C7DEF8$852074A98A9B2AF70D59D449AD0F9B898B4A9455C7B90CE7'."\n";
		echo '$NETNTLM$4803CB182E23B79A$BA4DA703C6A056727CC7B62FFA065970D5D400F18D02C6D1'."\n";
		echo '$99$1a7F1qr2HihoXfs/56u5XMdpDZ83N6hW/HI='."\n";
		echo 'LMHASH:2B56DAEB658F9FE977BD3B61E7976684388EF712DB95C6F8'."\n";
		echo 'NTHASH:D4ACBAA3CD626E2A074D76C7491D332F8FB8989968E88736'."\n";
		echo '$99$ESIzRFVmd4i8671kB52wcm9qK5VdJR7lJKU='."\n";
		echo 'x::x:FEC7A34F78C17A9700000000000000000000000000000000:E875F0A28BD7729D071D7DF05272B0FB4549AE926FE36255:1122334455667788'."\n";
		echo "' rows='10' cols='150'></textarea><br />";
		echo "<input type='submit' value='Submit' />&nbsp;";
		echo "<input type='button' value='Fill with samples' onclick='document.getElementById(\"inputs\").value=document.getElementById(\"inputs\").placeholder;' />";
		echo "</form></div>";
	}
}

function printHelp(){
	echo "\nusage: php shucknt.php \t[-h] [-f tokens.txt] [-i 'tokenValue'] [-w wordlist.bin] [-o json|stdout|web] [-v]\n\t\t\t[-r input_wordlist.txt] [-b input_wordlist_reversed_sorted.txt] [-r output_wordlist] [-j]\n\n";
	echo "Arguments details:\n\n";
	echo "\t-h\t\t\tPrint this help\n";
	echo "\t-f tokens.txt\t\tInput tokens file, one per line.\n";
	echo "\t-i 'tokenValue'\t\tInline input token from stdin.\n";
	echo "\t-w wordlist.bin\t\tSpecific binary-reversed-sorted-wordlist to use.\n";
	echo "\t-o json|stdout|web\tCommandline output in json, stdout or web format.\n";
	echo "\t-v\t\t\tVerbosity for stdout output format only.\n";
	echo "\t-r input_wordlist.txt\tInput wordlist file to be reversed.\n";
	echo "\t-b input_wordlist.txt\tInput reversed-sorted-wordlist file to be binarized.\n";
	echo "\t-r output_wordlist\tOutput file for reversal or binarization.\n";
	echo "\t-j\t\t\tDo not display header (for json output).\n\n";
	echo "These are common ShuckNT commands used in various situations:\n\n";
	echo "\t# Shuck tokens from an input file to stdout with verbosity:\n";
	echo "\tphp shucknt.php -f tokens.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin -v\n\n";
	echo "\t# Shuck token from stdin to json output:\n";
	echo "\tphp shucknt.php -i '\$99\$1a7F1qr2HihoXfs/56u5XMdpDZ83N6hW/HI=' -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin -o json -j\n\n";
	echo "\t# Shuck token from stdin to light stdout (use default wordlist defined as constant in script):\n";
	echo "\tphp shucknt.php -i 'ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788'\n\n";
	echo "\t# Reverse HIBPDB to output file:\n";
	echo "\tphp shucknt.php -r pwned-passwords-ntlm-ordered-by-hash-v8.txt -t pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed\n\n";
	echo "\t# Binarize HIBPDB already reversed and sorted to output file:\n";
	echo "\tphp shucknt.php -b pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed-sorted -t pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin\n\n";
	exit;
}

function displayOutput(&$inputs, $outputFormat = "web", $verbosity = false){
	global $start;
	$broken = 0;
	$brokenForFree = 0;
	$output = $finaloutput = "";

	foreach($inputs AS $hash => &$data){
		if($data["nthash"] !== "")
			$broken++;
		elseif(substr($data["crackshToken"], 0, 6) === "NTHASH")
			$brokenForFree++;
	}
	$stats = count($inputs) . " hashes-challenges analyzed in " . (time()-$start) . " seconds, with $broken NT-Hash instantly broken for pass-the-hash and $brokenForFree that can be broken via crack.sh for free.";

	if($outputFormat === "json"){
		$finaloutput .= json_encode($inputs, JSON_PRETTY_PRINT);
	} elseif($outputFormat === "stdout"){
		$output .= "\n\n$stats\n\n";
		if($verbosity){
			foreach($inputs AS $hash => &$data){
				$output .= "[INPUT] " . $data["token"] . "\n";
				$output .= "\t[USERNAME] " . $data["user"] . "\n";
				$output .= "\t[DOMAIN] " . $data["domain"] . "\n";
				$output .= "\t[LMRESP] " . $data["lmresp"] . "\n";
				$output .= "\t[NTRESP] " . $data["ntresp"] . "\n";
				$output .= "\t\t[CT1] " . $data["ct1"] . "\n";
				$output .= "\t\t[CT2] " . $data["ct2"] . "\n";
				$output .= "\t\t[CT3] " . $data["ct3"] . "\n";
				$output .= "\t[ESS] " . ($data["ess"] ? "YES": "NO") . "\n";
				if($data["ess"]){
					$output .= "\t\t[CLIENTCHALL] " . $data["clientchallenge"] . "\n";
					$output .= "\t\t[SERVERCHALL] " . strtoupper(substr($data["lmresp"], 0, 16)) . "\n";
				}
				$output .= "\t[CHALLENGE] " . $data["challenge"] . "\n";
				if($data["nthash"] !== "")
					$output .= "\t[NTHASH-SHUCKED] " . $data["nthash"] . "\n";
				else
					$output .= "\t[NTHASH-SHUCKED] " . str_repeat("*", 28) . $data["pt3"] . "\n";
				$output .= "\t\t[HIBP-CANDIDATES] " . $data["HIBPcountCandidates"] . "\n";
				$output .= "\t\t[HIBP-OCCURENCE] " . $data["HIBPoccurence"] . "\n";
				$output .= "\t\t[PT1] " . $data["pt1"] . "\n";
				$output .= "\t\t[PT2] " . $data["pt2"] . "\n";
				$output .= "\t\t[PT3] " . $data["pt3"] . "\n";
				$output .= "\t\t[K1] " . $data["deskeys"]["k1"] . "\n";
				$output .= "\t\t[K2] " . $data["deskeys"]["k2"] . "\n";
				$output .= "\t\t[K3] " . $data["deskeys"]["k3"] . "\n";
				$output .= "\t[CRACK.SH-TOKEN] " . $data["crackshToken"] . "\n";
				$output .= "\t[FORMAT-NETNTLMV1-NO-ESS] " .$data["user"]. "::" . $data["domain"] . "::" . $data["ntresp"] . ":" . $data["challenge"] . "\n";
				$output .= "\t[FORMAT-MSCHAPV2] \$MSCHAPv2\$" . $data["challenge"] . '$' . $data["ntresp"] . "$\n";
				$output .= "\t[FORMAT-NET(NT)LM] \$NETLM\$" . $data["challenge"] . '$' . $data["ntresp"] . "\n";
				$output .= "\t[FORMAT-PPTP] $99$" . base64_encode(hex2bin($data["challenge"] . $data["ct1"] . $data["ct2"] . $data["pt3"])) . "\n";
				$output .= "\n";
			}
		} else {
			foreach($inputs AS $hash => &$data){
				$output .= "[INPUT] " . $data["token"] . "\n";
				if($data["nthash"] !== ""){
					$output .= "\t[NTHASH-SHUCKED] " . $data["nthash"] . "\n";
				} else {
					$output .= "\t[CRACK.SH-TOKEN] " . $data["crackshToken"] . "\n";
				}
				$output .= "\n";
			}
		}
		$output .= "\n\n$stats\n\n";
		$finaloutput = $output;
	} elseif($outputFormat === "web"){
		$output .= "<table style='font-family:Consolas,monospace;white-space:pre' border='1px'><thead><tr><th>[+]</th><th>Input token</th><th>NT-Hash (pth-ready)</th></tr></thead>";
		$output .= "<tbody>";
		$i = 0;
		foreach($inputs AS $hash => &$data){
			$output .= "<tr " . (($data["nthash"] !== "") ? "style='font-weight:bold;'" : "") . ">";
			$output .= "<td style='cursor:pointer;text-align:center;' onclick='for(const e of document.getElementsByClassName(\"hash$i\")){e.style.display=(e.style.display==\"none\")?\"block\":\"none\";}'>[+]</td>";
			$output .= "<td>" . htmlentities($data["token"]);
			$output .= "<div class='hash$i' style='display:none;'><br /><ul>";
			$output .=      "<li><b>Type:</b> ".$data["description"]."</li>";
			$output .=      "<li><b>Identity:</b> ".($data["user"]!==""?$data["user"]:"N/A")."@".($data["domain"]!==""?$data["domain"]:"N/A")."</li>";
			if($data["ess"]){
				$output .=      "<li>Challenges (ESS/SSP, consider Responder with --lm or --disable-ess):<ul>";
				$output .=      "<li><b>ClientChallenge:</b>".$data["clientchallenge"] . (($data["clientchallenge"]==="1122334455667788")?" (default Responder)":" (consider set 1122334455667788)") . "</li>";
				$output .=      "<li><b>ServerChallenge:</b>".$data["serverchallenge"] . "</li>";
				$output .=      "<li><b>Final (md5(clientchall+LMresp[0:16])[0:16]):</b>" . $data["challenge"] . (($data["challenge"]==="1122334455667788")?" (crack.sh rainbow ready)":"") . "</li>";
				$output .=      "</ul></li>";
			} else
				$output .=      "<li><b>Challenge:</b>" . $data["challenge"] . (($data["challenge"]==="1122334455667788")?" (default Responder / crack.sh rainbow ready)":" (consider set 1122334455667788)") . "</li>";
			$output .=      "<li><b>Responses:</b><ul>";
			$output .=      "<li><b>LMresp:</b>".$data["lmresp"]."</li>";
			$output .=      "<li><b>NTresp:</b>".$data["ntresp"]." (CT1+CT2+CT3)</li>";
			$output .=      "</ul></li>";
			$output .=      "<li><b>CipherText (NT-response):</b><ul>";
			$output .=      "<li><b>CT1:</b>".$data["ct1"]." (DES(K1,Chall))</li>";
			$output .=      "<li><b>CT2:</b>".$data["ct2"]." (DES(K2,Chall))</li>";
			$output .=      "<li><b>CT3:</b>".$data["ct3"]." (DES(K3,Chall))</li>";
			$output .=      "</ul></li>";
			$output .=      "<li><b>Same token after converting to other formats:</b><ul>";
			$output .=      "<li>\$MSCHAPv2\$" . $data["challenge"] . '$' . $data["ntresp"] . "$</li>";
			$output .=      "<li>\$NETLM\$" . $data["challenge"] . '$' . $data["ntresp"] . "</li>";
			$output .=      "<li>\$NETNTLM\$" . $data["challenge"] .'$' . $data["ntresp"] . "</li>";
			$output .=      "<li>$99$" . base64_encode(hex2bin($data["challenge"] . $data["ct1"] . $data["ct2"] . $data["pt3"])) . "</li>";
			$output .=      "</ul></li>";
			$output .=      "<li><b>Most optimized format for Crack.sh (cheaper/faster):</b><ul>";
			$output .=      "<li><a target='_blank' href='https://crack.sh/get-cracking/' style='text-decoration: none;'>";
			if($data["nthash"] !== "")
				$output .= "<s>" . $data["crackshToken"] . "</s> (useless)";
			else
				$output .= ((substr($data["crackshToken"], 0, 6) === "NTHASH") ? "<font color='#FF8C00'><b>" . $data["crackshToken"] . "</b></font>" : $data["crackshToken"]);
			$output .= "</a></li>";
			$output .=      "</ul></li>";
			$output .=      "<li><b>Most optimized format for Hashcat:</b><ul>";
			if($data["nthash"] !== ""){
				$output .=      "<li><b>Mode 5500 or 27000:</b> <s>" .$data["user"]. "::" . $data["domain"] . "::" . $data["ntresp"] . ":" . $data["challenge"] . "</s> (useless)</li>";
				$output .=      "<li><b>Mode 14000:</b><ul><li><s>" . $data["ct1"] . ":" . $data["challenge"] . "</s> (useless)</li><li><s>" . $data["ct2"] . ":" . $data["challenge"] . "</s> (useless)</li></ul></li>";
			} else {
				$output .=      "<li><b>Mode 5500 or 27000:</b> " .$data["user"]. "::" . $data["domain"] . "::" . $data["ntresp"] . ":" . $data["challenge"] . "</li>";
				$output .=      "<li><b>Mode 14000:</b><ul><li>" . $data["ct1"] . ":" . $data["challenge"] . "</li><li>" . $data["ct2"] . ":" . $data["challenge"] . "</li></ul></li>";
			}
			$output .=      "</ul></li>";
			$output .= "</ul></div></td>";
			$output .= "<td>";
			if($data["nthash"] !== ""){
				$output .= "<font color='#228B22'><b>".$data["nthash"]."</b></font>";
			} elseif(substr($data["crackshToken"], 0, 6) === "NTHASH") {
				$output .= "<font color='#FF8C00'><b>".str_repeat("*", 28).$data["pt3"]."</b></font>";
			} else {
				$output .= str_repeat("*", 28)."<i>".$data["pt3"]."</i>";
			}
			$output .= "<div class='hash$i' style='display:none;'><ul>";
			$output .=      "<li><b>NT-hash parts:</b><ul>";
			$output .=      "<li><b>PT1:</b>".$data["pt1"]."</li>";
			$output .=      "<li><b>PT2:</b>".$data["pt2"]."</li>";
			$output .=      "<li><b>PT3:</b>".$data["pt3"]."</li>";
			$output .=      "</ul></li>";
			$output .=      "<li><b>DES-ECB keys:</b><ul>";
			$output .=      "<li><b>K1:</b>".$data["deskeys"]["k1"]."</li>";
			$output .=      "<li><b>K2:</b>".$data["deskeys"]["k2"]."</li>";
			$output .=      "<li><b>K3:</b>".$data["deskeys"]["k3"]."</li>";
			$output .=      "</ul></li>";
			$output .=      "<li><b>HIBP:</b><ul>";
			$output .=      "<li><b>#Candidates:</b> ". $data["HIBPcountCandidates"] ."</li>";
			$output .=      "<li><b>#Leaked:</b> ".$data["HIBPoccurence"]." time(s)</li>";
			$output .=      "</ul></li>";
			$output .= "</ul></div></td>";
			$output .= "</tr>";
			$i++;
		}
		$output .= "</tbody></table>";
		$output .= "<br /><br />";
		
		$finaloutput  = "<h1>Results of Hash-Shucking:</h1>";
		$finaloutput .= "<div id='shuckingresults'><span id='shuckingtime'><b>" . count($inputs) . "</b> token(s) analyzed in <b>" . (time()-$start) . " second(s)</b>.</span><br />";
		if($broken > 0)
			$finaloutput .= "<span id='shuckingok'><font color='#228B22'><b>$broken</b></font> NT-Hash instantly shucked! Pass-the-Hash-ready!</span><br />";
		if($brokenForFree > 0)
			$finaloutput .= "<span id='shuckingpartial'><font color='#FF8C00'><b>$brokenForFree</b></font> that can be broken via crack.sh for free!</span><br />";
		if((count($inputs)-($brokenForFree+$broken)) > 0)
			$finaloutput .= "<span id='shuckingko'><font color='#DC143C'><b>".(count($inputs)-($brokenForFree+$broken))."</b></font> not broken but breakable via crack.sh (non-free) or Hashcat (with time)...</span><br />";
		$finaloutput .= "</div><br />" . $output;
		$finaloutput = nl2br($finaloutput);
	}
	echo $finaloutput;
}

function getHashes($inputFile = "", $inputHash = ""){
	$inputs = array();
	$lines = array();
	// PHP-CLI method through input file or stdin
	if(php_sapi_name() === "cli" && $inputFile !== "")
		$lines = file($inputFile);
	elseif(php_sapi_name() === "cli" && $inputHash !== "")
		$lines[] = $inputHash;
	// Web method through POST-data
	elseif(isset($_POST["inputs"]) && !empty($_POST["inputs"])){
		$lines = explode(PHP_EOL, strval($_POST["inputs"]));
		$lines = array_slice($lines, 0, MAX_HASH_NUMBER); // limit inputs from web (not for PHP-CLI)
	}
	foreach($lines AS $line)
		if(trim($line) !== "")
			$inputs[substr(trim($line), 0, MAX_HASH_LENGTH)] = array();
	return $inputs;
}

function extractDataFromHash(&$inputs, &$reversect3toNTLMs){
	foreach($inputs AS $hash => &$data){
		$data['type']                   = "";
		$data['description']            = "";
		$data['token']                  = trim($hash);
		$data['user']                   = "";
		$data['domain']                 = "";
		$data['lmresp']                 = "";
		$data['ntresp']                 = "";
		$data["ct1"]              	= "";
		$data["ct2"]              	= "";
		$data["ct3"]              	= "";
		$data['ess']                    = false;
		$data["clientchallenge"]	= "";
		$data["serverchallenge"]	= "";
		$data["challenge"]		= "";
		$data["deskeys"]                = array("k1"=>"", "k2"=>"", "k3"=>"");
		$data["nthash"]                 = "";
		$data["pt1"]              	= "";
		$data["pt2"]              	= "";
		$data["pt3"]              	= "";
		$data["reversePt3"]		= "";
		$data["candidates"]             = array();
		$data["HIBPcountCandidates"]    = 0;
		$data["HIBPoccurence"]          = 0;
		// user::domain.tld:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
		// ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788
		if(preg_match('/.+:.*:.*:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}/i', $data['token'])){
			$data['type']                   = "NetNTLMv1";
			$parts = explode(":", $data['token']);
			$data['user']                   = htmlentities($parts[0]);
			$data['domain']                 = htmlentities($parts[2]);
			$data['clientchallenge']        = strtoupper($parts[5]);
			$data['lmresp']                 = strtoupper($parts[3]);
			$data['ntresp']                 = strtoupper($parts[4]);
			$data['ess']                    = (substr($data['lmresp'], 20, 28) === "0000000000000000000000000000");
			if($data['ess']){
				$data['type']			.= " (ESS/SSP)";
				$data["serverchallenge"]	= strtoupper(substr($data["lmresp"], 0, 16));
				$data["challenge"]		= substr(strtoupper(md5(hex2bin($data["clientchallenge"] . substr($data["lmresp"], 0, 16)))), 0, 16);
			} else {
				$data['type']			.= " (no ESS/SSP)";
				$data["challenge"]		= $data["clientchallenge"];
			}
			//$data["h4ntlmv1"]               = computeHashcatNtlmv1($data);
			$data['description']            = $data['type'] . " type with " . $data["challenge"] . " as challenge";
		// $NETLM$FE2CFD84F6C7DEF8$852074A98A9B2AF70D59D449AD0F9B898B4A9455C7B90CE7 // Format for crack.sh (>0$)
		} elseif(preg_match('/\$NETN?T?LM\$[a-fA-F0-9]{16}\$[a-fA-F0-9]{48}/i', $data['token'])){
			$data['type']                   = "NetNTLMv1";
			$parts = explode("$", $data['token']);
			$data['ntresp']                 = strtoupper($parts[3]);
			$data["challenge"]              = $data['clientchallenge']      = strtoupper($parts[2]);
			$data["description"]            = $data['type'] . " type with " . $data["challenge"] . " as challenge";
		// $MSCHAPv2$1337133713371337$F93A1DB1C044133F52582EFDA5C31667EBBE6F8F2814E539$root
		} elseif(preg_match('/\$MSCHAPv2\$[a-fA-F0-9]{16}\$[a-fA-F0-9]{48}\$*.*/i', $data['token'])){
			$data['type']                   = "MSCHAPv2";
			$parts = explode("$", $data['token']);
			$data['ntresp']                 = strtoupper($parts[3]);
			$data["challenge"]              = $data['clientchallenge']      = strtoupper($parts[2]);
			$data["description"]            = $data['type'] . " type with " . $data["challenge"] . " as challenge";
		// NTHASH:D4ACBAA3CD626E2A074D76C7491D332F8FB8989968E88736 // Format for crack.sh without ESS/SSP and challenge 1122334455667788 (0$)
		} elseif(preg_match('/(NT|LM)HASH:[a-fA-F0-9]{48}/i', $data['token'])){
			$data['type']                   = "NetNTLMv1 (no ESS/SSP)";
			$parts = explode(":", $data['token']);
			$data['ntresp']                 = $parts[1];
			$data["challenge"]              = $data['clientchallenge']      = "1122334455667788";
			$data["description"]            = $data['type'] . " type with standard challenge " . $data["challenge"] . ", free to crack via crack.sh rainbow table.";
		// $99$1a7F1qr2HihoXfs/56u5XMdpDZ83N6hW/HI= // PPTP VPNS MS-CHAPv2 handshake via chapcrack
		} elseif(preg_match('/\$99\$[a-zA-Z0-9\/+]{35}=/i', $data['token'])){
			$data['type']                   = "PPTP VPN MSCHAPv2";
			$parts = explode("$", $data['token']);
			$data["challenge"]              = $data['clientchallenge']        = strtoupper(substr(bin2hex(base64_decode($parts[2])), 0, 16));
			$data['ntresp']                 = strtoupper(substr(bin2hex(base64_decode($parts[2])), 16, 36));
			$data["pt3"]              	= strtoupper(substr(bin2hex(base64_decode($parts[2])), 48, 4));
			$data["description"]            = $data['type'] . " type with " . $data["challenge"] . " as challenge";
		} else {
			unset($inputs[$hash]);
			continue;
		}
		$data["ct1"]                    = substr($data['ntresp'], 0, 16);
		$data["ct2"]                    = substr($data['ntresp'], 16, 16);
		$data["ct3"]                    = substr($data['ntresp'], 32, 16);
		if(strlen($data["ct3"]) === 4){ // special case for $99$ hash
			$data["deskeys"]["k3"] = ntlm2des($data["pt3"]);
			$data["ct3"] = computeCtPartFromDesKeyChall($data["deskeys"]["k3"], $data["challenge"]);
			$data['ntresp'] = $data["ct1"] . $data["ct2"] . $data["ct3"];
		}
		$data["pt3"]              	= ($data["pt3"] === "") ? bruteForcePT3FromCT3($data['ct3'], $data["challenge"]) : $data["pt3"]; // no BF for $99$
		$data["deskeys"]["k3"]          = ntlm2des($data["pt3"]);
		$reversect3toNTLMs[]            = $data["reversePt3"]       = strrev($data["pt3"]);
		$data["crackshToken"]           = computeCrackShToken($data);
		$data["h4m14000"]               = computeHashcat14000($data);
		$data["h4m5500"]               	= computeHashcat5500($data);
		$data["h4m27000"]              	= computeHashcat27000($data);
	}
	return $inputs;
}

function getHashNTCandidates(&$reversect3toNTLMs, $wordlistFile){
	$fp = fopen($wordlistFile, "rb");
	$byteLength = 20;       // NT-Hash + integer size
	$hashLength = 16;       // NT-Hash bytes size
	$hashPrefixLength = 4;  // One integer bytes size
	$start = 0;

	foreach($reversect3toNTLMs AS $reversect3toNTLM => &$output){
		$output = array();
		$output[] = array("occurence"=>0, "des01"=>"31EBB3FD0D8BABD3", "des02"=>"31DBCF8B9DBF8381"); // empty-nthash's DES keys (not in HIBP)
		$end = filesize($wordlistFile);
		$mid = $start + ($end-$start)/2;
		while($mid%$byteLength != 0)
			$mid += 1;
		fseek($fp, $mid);
		$extract = fread($fp, $hashLength);
		$hashExtract = strval(strtoupper(bin2hex($extract)));
		$hashPrefixExtract = substr($hashExtract, 0, 4);

		while(1){
			if(strcmp(strval($reversect3toNTLM), strval($hashPrefixExtract)) <= 0){ // equals or inferior
				$end = $mid;
				$mid = $start + ($end-$start)/2;
				while($mid%$byteLength != 0) // Necessary to make sure the position is at the beginning of a hash.
					$mid -= 1;
			} else {
				$start = $mid;
				$mid = $start + ($end-$start)/2;
				while($mid%$byteLength != 0) // Necessary to make sure the position is at the beginning of a hash.
					$mid -= 1;
			}
			fseek($fp, $mid);
			$extract = fread($fp, $hashLength);
			$hashExtract = strval(strtoupper(bin2hex($extract)));
			$hashPrefixExtract = substr($hashExtract, 0, 4);

			if($start === $mid || $end === $mid){ // Positionned to the hash before
				fseek($fp, $mid+$byteLength); // Go down 1 hash+occurence
				$start = $mid+$byteLength;
				while(1){
					$extract = fread($fp, $hashLength);
					$occurenceHash = hexdec(bin2hex(fread($fp, $hashPrefixLength)));
					$hashExtract = strval(strtoupper(bin2hex($extract)));
					$hashPrefixExtract = substr($hashExtract, 0, 4);
					if(strcmp(strval($hashPrefixExtract), strval($reversect3toNTLM)) === 0){
						$output[] = array(	"occurence" => intval($occurenceHash),
									"des01" => ntlm2des(substr(strtoupper(strrev($hashExtract)), 0, 14)),
									"des02" => ntlm2des(substr(strtoupper(strrev($hashExtract)), 14, 14)),
								);
						$start += $byteLength;
					} else break;
				}
				break;
			}
		}
	}
	return $reversect3toNTLMs;
}

function computeCrackShToken(&$data){
	return ((!$data["ess"] && $data["clientchallenge"] === "1122334455667788") ? 'NTHASH:'.$data["ntresp"]." ($0)" : '$NETLM$'.$data["challenge"].'$'.$data["ntresp"]." ($20-$200)");
}

function computeHashcat14000(&$data){
	return 'echo "'.$data["ct1"].':'.$data["challenge"].'">14000.hash;echo "'.$data["ct2"].':'.$data["challenge"].'">>14000.hash;hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1';
}

function computeHashcat5500(&$data){
	return 'echo "'.$data["user"]."::".$data["domain"]."::".$data["ntresp"].":".$data["challenge"].'">5500.hash;hashcat -m 5500 -a 3 5500.hash ?a?a?a?a?a --increment';
}

function computeHashcat27000(&$data){
	return 'echo "'.$data["user"]."::".$data["domain"]."::".$data["ntresp"].":".$data["challenge"].'">27000.hash;hashcat -m 27000 -a 0 27000.hash nthash-wordlist.txt';
}

function ntlm2des($ntlmhex){
	$in = array_map('hexdec', str_split(str_pad($ntlmhex, 14, '0'), 2));
	$out = array();
	$out[] = ((($in[0] & 0xfe) | 1));
	$out[] = ((($in[0] << 7 & 0x80) | ($in[1] >> 1) & 0x7e) | 1);
	$out[] = ((($in[1] << 6 & 0xc0) | ($in[2] >> 2) & 0x3e) | 1);
	$out[] = ((($in[2] << 5 & 0xe0) | ($in[3] >> 3) & 0x1e) | 1);
	$out[] = ((($in[3] << 4 & 0xf0) | ($in[4] >> 4) & 0x0e) | 1);
	$out[] = ((($in[4] << 3 & 0xf8) | ($in[5] >> 5) & 0x06) | 1);
	$out[] = ((($in[5] << 2 & 0xfc) | ($in[6] >> 6) & 0x02) | 1);
	$out[] = ((($in[6] << 1 & 0xfe) | 1));
	return strtoupper(bin2hex(join(array_map("chr", $out))));
}

function des2ntlm($deshex){
	$in = array_map('hexdec', str_split($deshex, 2));
	$out = array();
	$out[] = ((($in[0] & 0xfe) | ($in[1] >> 7)) & 0xff);
	$out[] = ((($in[1] << 1 & 0xFc) | ($in[2] >> 6)) & 0xff);
	$out[] = ((($in[2] << 2 & 0xf8) | ($in[3] >> 5)) & 0xff);
	$out[] = ((($in[3] << 3 & 0xF0) | ($in[4] >> 4)) & 0xff);
	$out[] = ((($in[4] << 4 & 0xe0) | ($in[5] >> 3)) & 0xff);
	$out[] = ((($in[5] << 5 & 0xc0) | ($in[6] >> 2)) & 0xff);
	$out[] = ((($in[6] << 6 & 0x80) | ($in[7] >> 1)) & 0xff);
	return strtoupper(bin2hex(join(array_map("chr", $out))));
}

function computeCtPartFromDesKeyChall($key, $chall){
	return strtoupper(substr(bin2hex(openssl_encrypt(hex2bin($chall), 'DES-ECB', hex2bin($key), OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, '')), 0, 16));
}

function bruteForcePT3FromCT3($ct3, $chall){
	$candidate = "";
	for($i = 0 ; $i < 0x10000 ; $i++){
		$candidate = strtoupper(str_pad(dechex($i), 4, '0', STR_PAD_LEFT));
		if(strcmp(computeCtPartFromDesKeyChall(ntlm2des($candidate), $chall), strval($ct3)) === 0) break;
	}
	return $candidate;
}

function reverseHIBPDB($inputFile, $outputFile){
	if($outputFile === "")
		$outputFile = $inputFile."-reversed";
	$handle1 = fopen($inputFile, "r") or die("Couldn't get input handle");
	$handle2 = fopen($outputFile, "w") or die("Couldn't get output handle");
	echo "\n[*] Start of hash reversal processing...\n";
	$start = time();
	if($handle1){
		while(!feof($handle1)){
			$line = explode(":",fgets($handle1));
			$line[0] = strrev($line[0]);
			fputs($handle2, implode(":", $line));
		}
		fclose($handle1);
		fclose($handle2);
	}
	echo "[+] Process completed in " . (time()-$start) . " second(s)!\n";
	exit;
}

function binarizeHIBPDB($inputFile, $outputFile){
	if($outputFile === "")
		$outputFile = $inputFile.".bin";
	$handle1 = fopen($inputFile, "r") or die("Couldn't get input handle");
	$handle2 = fopen($outputFile, "wb") or die("Couldn't get output handle");
	echo "\n[*] Starting the database binarization...\n";
	$start = time();
	if($handle1){
		while(!feof($handle1)){
			$line = explode(":",trim(fgets($handle1)));
			if(count($line) === 2){
				fwrite($handle2, hex2bin($line[0]));
				fwrite($handle2, pack("N", intval($line[1])));
			}
		}
		fclose($handle1);
		fclose($handle2);
	}
	echo "[+] Process completed in " . (time()-$start) . " second(s)!\n";
	exit;
}
?>
