<p align="center">
  <img src="https://shuck.sh/images/shucksh-192x192.png" alt="Shuck.sh"/>
</p>

# :closed_lock_with_key: ShuckNT : Shuck hash before trying to crack it | [Shuck.sh](https://shuck.sh)'s script

**ShuckNT** is the script of [Shuck.sh](https://shuck.sh) online service for on-premise use ([try it online!](https://shuck.sh/get-shucking.php)). It is design to dowgrade, convert, dissect and shuck authentication token based on [Data Encryption Standard (DES)](https://en.wikipedia.org/wiki/Data_Encryption_Standard).

Algorithms / formats supported :
- MSCHAPv2
- NET(NT)LM
- (LM|NT)HASH
- PPTP-VPN `$99$`
- All with any challenge value!

**ShuckNT** rely on [hash shucking](https://www.youtube.com/watch?v=OQD3qDYMyYQ&ab_channel=PasswordVillage) principle to optimize challenge-response cracking and exploitability.

> [Password shucking](https://www.scottbrady91.com/authentication/beware-of-password-shucking) is a method of stripping layers off an updated password hash, removing the benefits of its new password hashing algorithm and reverting it to its weaker algorithm. Password shucking can be used by an attacker against old rehashed passwords or pre-hash passwords, enabling them to strip away or "shuck" off the strong outer password hashing algorithm.

From a list of input tokens, **ShuckNT** provides :
- The NT-hash instantly ([pass-the-hash](https://en.wikipedia.org/wiki/Pass_the_hash) ready) through a smart-research in the [HaveIBeenPwned](https://haveibeenpwned.com/) latest database (if present);
- The [Crack.Sh](https://crack.sh/) ready-to-use optimized token, to pay less or nothing if NT-hash not found in HIBP-DB;
- Several converted formats to try to crack them via other tools ([hashcat](https://hashcat.net/), jtr, CloudCracker, etc.) :
  - **Hashcat mode 5500**: to crack NetNTLMv1 to plaintext (unpredictable result, depend on wordlists, masks, rules...);
  - **Hashcat mode 27000**: to shuck NetNTLMv1 to NT-hash (unpredictable result / depend on NT-wordlists...);
  - **Hashcat mode 14000**: to shuck NetNTLMv1 to DES-keys then NT-hash (100% result / time needed);
- All the details of the dissection of the challenge-response (PT1/2/3, K1/2/3, CT1/2/3, HIBP occurences/candidates, LMresp, NTresp, challenges, etc.).

## :mag: How it works?

Behind [Shuck.sh](https://shuck.sh)'s script **ShuckNT** is simply an efficient and optimized [binary-search](https://en.wikipedia.org/wiki/Binary_search_algorithm) for [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard)-keys collisions from a subset of NT-hashes candidate, whose last [two bytes are known](https://hashcat.net/forum/thread-5832.html), in custom-reversed-binary [HIBP](https://haveibeenpwned.com/)'s database.

During a security assessment (limited in time), if you capture ~100 [NetNTLMv1](https://crack.sh/netntlm/) (with or without ESS) via a tool such as [Responder](https://github.com/lgandx/Responder), the search for the corresponding NT-Hashes (if leaked on [HIBP](https://haveibeenpwned.com/)) only takes a few seconds via [Shuck.sh](https://shuck.sh)/**ShuckNT** (~10s).

[Shuck.sh](https://shuck.sh)'s script **ShuckNT** takes care of simplifying by converting the cryptographic algorithm to a weaker form (without ESS if possible, in a free format for [Crack.Sh](https://crack.sh/) or directly in NT-Hash format if leaked on [HIBP](https://haveibeenpwned.com/)). Thus a NetNTLMv1-ESS/SSP, PPTP VPN or MSCHAPv2 challenge (not-free and time-consuming on [Crack.Sh](https://crack.sh/)) can potentially be shucked instantly for free!

The initial idea of [Shuck.sh](https://shuck.sh)/ShuckNT was born from a desire to save time during security assessments for customers, not to rely on a third-party online service whose availability is not necessarily continuous and to be able to be locally autonomous.

## :hammer: Installation of ShuckNT / Preparing the HIBP database

The installation process consists of:

- Get the **ShuckNT** project;
- Prepare HaveIBeenPwned database (one time only, takes several minutes) (these steps are to be carried out under a Unix/Linux environment):
  - **Download** the latest version of the [HaveIBeenPwned database of NT-hashes ordered by hashes](https://haveibeenpwned.com/Passwords) (several GB) ([Mirror link](https://data.verifiedjoseph.com/dataset/pwned-passwords-version-8));
  - **Extract** this database via 7zip;
  - **Reverse** all the hashes of this database via ShuckNT script directly;
  - **Sort** all reversed-hashes;
  - **Convert** this new database into a binary format via ShuckNT script directly (or via the [HIBP_PasswordList_Slimmer](https://github.com/JoshuaMart/HIBP_PasswordList_Slimmer/) of my friend [@JoshuaMart](https://github.com/JoshuaMart) :));
- Enjoy **ShuckNT**!

Installation commands:
```
# Install dependencies
apt install p7zip-full php git

# Get ShuckNT tool
git clone https://github.com/yanncam/ShuckNT
cd ShuckNT

# Prepare HaveIBeenPwned database (one time only, takes several minutes)
## Download latest HIBP-DB (can take severals minutes...)
wget https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ntlm-ordered-by-hash-v8.7z
## Extract HIBP-DB (can take severals minutes...)
7z e pwned-passwords-ntlm-ordered-by-hash-v8.7z
## Reverse all hashes (can take severals minutes...)
php shucknt.php -r pwned-passwords-ntlm-ordered-by-hash-v8.txt -t pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed
## Sort all reversed-hashes (can take severals minutes...)
sort pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed -o pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed-sorted
## Convert to binary format (can take severals minutes...)
php shucknt.php -b pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed-sorted -t pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
## Free space to keep only pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
rm -f pwned-passwords-ntlm-ordered-by-hash-v8.7z
rm -f pwned-passwords-ntlm-ordered-by-hash-v8.txt
rm -f pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed
rm -f pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed-sorted

# Enjoy ShuckNT via commandline, or web http://[HOST]/shucknt.php
php shucknt.php -h
```

_The generation of the database in the format expected by ShuckNT is to be done under a Unix/Linux system. The use of ShuckNT with a valid database has been tested under Windows/Linux with PHP7/8+._

## :fire: Demonstration / Example / How to use?

ShuckNT is a standalone-PHP script without any dependencies. It can be used in **CLI command-line** or through a **Web-Browser**.

### CLI command-line standalone script

Help, arguments and syntax:

```
$ php shucknt.php -h
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

Use '-h' to print help.

usage: php shucknt.php  [-h] [-f tokens.txt] [-i 'tokenValue'] [-w wordlist.bin] [-o json|stdout|web] [-v]
                        [-r input_wordlist.txt] [-b input_wordlist_reversed_sorted.txt] [-r output_wordlist] [-j]

Arguments details:

        -h                      Print this help
        -f tokens.txt           Input tokens file, one per line.
        -i 'tokenValue'         Inline input token from stdin.
        -w wordlist.bin         Specific binary-reversed-sorted-wordlist to use.
        -o json|stdout|web      Commandline output in json, stdout or web format.
        -v                      Verbosity for stdout output format only.
        -r input_wordlist.txt   Input wordlist file to be reversed.
        -b input_wordlist.txt   Input reversed-sorted-wordlist file to be binarized.
        -r output_wordlist      Output file for reversal or binarization.
        -j                      Do not display header (for json output).

These are common ShuckNT commands used in various situations:

        # Shuck tokens from an input file to stdout with verbosity:
        php shucknt.php -f tokens.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin -v

        # Shuck token from stdin to json output:
        php shucknt.php -i '$99$1a7F1qr2HihoXfs/56u5XMdpDZ83N6hW/HI=' -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin -o json -j

        # Shuck token from stdin to light stdout (use default wordlist defined as constant in script):
        php shucknt.php -i 'ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788'

        # Reverse HIBPDB to output file:
        php shucknt.php -r pwned-passwords-ntlm-ordered-by-hash-v8.txt -t pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed

        # Binarize HIBPDB already reversed and sorted to output file:
        php shucknt.php -b pwned-passwords-ntlm-ordered-by-hash-v8.txt-reversed-sorted -t pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
```

Shuck instantly an authentication token **NetNTLMv1 with ESS/SSP** for its corresponding NT-hash, from stdin (with default HIBP-DB) and verbose output:
```
$ php shucknt.php -i 'ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788' -v
[...]
1 hashes-challenges analyzed in 0 seconds, with 1 NT-Hash instantly broken for pass-the-hash and 0 that can be broken via crack.sh for free.

[INPUT] ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788
        [USERNAME] ycam
        [DOMAIN] ad
        [LMRESP] DEADC0DEDEADC0DE00000000000000000000000000000000
        [NTRESP] 70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED
                [CT1] 70C249F75FB6D2C0
                [CT2] AC2C2D3808386CCA
                [CT3] B1514A2095C582ED
        [ESS] YES
                [CLIENTCHALL] 1122334455667788
                [SERVERCHALL] DEADC0DEDEADC0DE
        [CHALLENGE] C85086419358F950
        [NTHASH-SHUCKED] 93B3C62269D55DB9CA660BBB91E2BD0B
                [HIBP-CANDIDATES] 12778
                [HIBP-OCCURENCE] 15
                [PT1] 93B3C62269D55D
                [PT2] B9CA660BBB91E2
                [PT3] BD0B
                [K1] 93D9F1C5274F55BB
                [K2] B9E599C1BBDD47C5
                [K3] BD85C10101010101
        [CRACK.SH-TOKEN] $NETLM$C85086419358F950$70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED (20-300$)
        [FORMAT-NETNTLMV1-NO-ESS] ycam::ad::70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:C85086419358F950
        [FORMAT-MSCHAPV2] $MSCHAPv2$C85086419358F950$70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED$
        [FORMAT-NET(NT)LM] $NETLM$C85086419358F950$70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED
        [FORMAT-PPTP] $99$yFCGQZNY+VBwwkn3X7bSwKwsLTgIOGzKvQs=
```

Shuck instantly many authentication tokens from supported formats for their corresponding NT-hashes, from an input file (with specified HIBP-DB) and simple output:
```
$ php shucknt.php -f tokens-samples.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
[...]
10 hashes-challenges analyzed in 3 seconds, with 8 NT-Hash instantly broken for pass-the-hash and 1 that can be broken via crack.sh for free.

[INPUT] $99$1a7F1qr2HihoXfs/56u5XMdpDZ83N6hW/HI=
        [NTHASH-SHUCKED] DE26CCE0356891A4A020E7C4957AFC72

[INPUT] LMHASH:2B56DAEB658F9FE977BD3B61E7976684388EF712DB95C6F8
        [NTHASH-SHUCKED] C780C78872A102256E946B3AD238F661

[INPUT] NTHASH:D4ACBAA3CD626E2A074D76C7491D332F8FB8989968E88736
        [NTHASH-SHUCKED] C22B315C040AE6E0EFEE3518D830362B

[INPUT] ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788
        [NTHASH-SHUCKED] 93B3C62269D55DB9CA660BBB91E2BD0B

[INPUT] $NETNTLM$4803CB182E23B79A$BA4DA703C6A056727CC7B62FFA065970D5D400F18D02C6D1
        [NTHASH-SHUCKED] 8E2FDD50C6FB5D0E22E2455394D98D2A

[INPUT] user::domain.tld:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
        [NTHASH-SHUCKED] 8846F7EAEE8FB117AD06BDD830B7586C

[INPUT] $MSCHAPv2$1337133713371337$F93A1DB1C044133F52582EFDA5C31667EBBE6F8F2814E539$root
        [NTHASH-SHUCKED] 209C6174DA490CAEB422F3FA5A7AE634

[INPUT] $NETLM$FE2CFD84F6C7DEF8$852074A98A9B2AF70D59D449AD0F9B898B4A9455C7B90CE7
        [NTHASH-SHUCKED] 0A42BC909E226C6F8FFCBAA6AB0DA43D

[INPUT] $99$ESIzRFVmd4i8671kB52wcm9qK5VdJR7lJKU=
        [CRACK.SH-TOKEN] NTHASH:BCEBBD64079DB0726F6A2B955D251EE57D6DD8A109D77A0D (0$)

[INPUT] x::x:FEC7A34F78C17A9700000000000000000000000000000000:E875F0A28BD7729D071D7DF05272B0FB4549AE926FE36255:1122334455667788
        [CRACK.SH-TOKEN] $NETLM$1A6A5C911D8A4DF2$E875F0A28BD7729D071D7DF05272B0FB4549AE926FE36255 (20-300$)
```

Shuck tokens with JSON output only:
```
$ php shucknt.php -f tokens-samples.txt -o json -j
[...]
    {
        "type": "NetNTLMv1 (ESS\/SSP)",
        "description": "NetNTLMv1 (ESS\/SSP) type with C85086419358F950 as challenge",
        "token": "ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788",
        "user": "ycam",
        "domain": "ad",
        "lmresp": "DEADC0DEDEADC0DE00000000000000000000000000000000",
        "ntresp": "70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED",
        "ct1": "70C249F75FB6D2C0",
        "ct2": "AC2C2D3808386CCA",
        "ct3": "B1514A2095C582ED",
        "ess": true,
        "clientchallenge": "1122334455667788",
        "serverchallenge": "DEADC0DEDEADC0DE",
        "challenge": "C85086419358F950",
        "deskeys": {
            "k1": "93D9F1C5274F55BB",
            "k2": "B9E599C1BBDD47C5",
            "k3": "BD85C10101010101"
        },
        "nthash": "93B3C62269D55DB9CA660BBB91E2BD0B",
        "pt1": "93B3C62269D55D",
        "pt2": "B9CA660BBB91E2",
        "pt3": "BD0B",
        "reversePt3": "B0DB",
        "HIBPcountCandidates": 12778,
        "HIBPoccurence": 15,
        "crackshToken": "$NETLM$C85086419358F950$70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED (20-300$)",
        "h4m14000": "echo \"70C249F75FB6D2C0:C85086419358F950\">14000.hash;echo \"AC2C2D3808386CCA:C85086419358F950\">>14000.hash;hashcat -m 14000 -a 3 -1 charsets\/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1",
        "h4m5500": "echo \"ycam::ad::70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:C85086419358F950\">5500.hash;hashcat -m 5500 -a 3 5500.hash ?a?a?a?a?a --increment",
        "h4m27000": "echo \"ycam::ad::70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:C85086419358F950\">27000.hash;hashcat -m 27000 -a 0 27000.hash nthash-wordlist.txt"
    }
[...]
```

### Web-Browser standalone script

Host **ShuckNT** on a web server (Apache, Nginx, etc.) supporting PHP 7/8+:

<p align="center">
  <img src="https://shuck.sh/images/shucknt.png" alt="ShuckNTweb"/>
</p>

## :toolbox: To go deeper...

The online service [Shuck.sh](https://shuck.sh), which implements the **ShuckNT** tool, provides many [details](https://shuck.sh/#tech) and an [FAQ](https://shuck.sh/#faq).

A dynamic and on-the-fly [Generator](https://shuck.sh/generator.php) is present online, allowing from a clear text password or an NT-hash to observe mechanisms of the authentication token generation algorithm (NetNTLMv1(-ESS/SSP), MSCHAPv2, PPTP-VPN, etc.).

Finally, a dynamic and on-the-fly [Converter](https://shuck.sh/converter.php) is also present online, which allows from an authentication token (NetNTLMv1(-ESS/SSP), MSCHAPv2, PPTP-VPN, etc.) to show in detail its dissection, and even to obtain the corresponding NT-hash if DES keys K1 and K2 are provided (after [DES-KPA attack](https://hashcat.net/forum/thread-5832.html) for example).

## :beers: Credits

- Thanks to [Crack.sh](https://crack.sh) for their excellent online service, which remains essential!
- Thanks also to Troy Hunt of [HaveIBeenPwned](https://haveibeenpwned.com/) for continually raising awareness about password leaks.
- Thanks to the entire [Hashcat](https://hashcat.net/) community, for their exciting research, tools and techniques!
- Thanks to zarbibi, for the help when binary ops gave me a headache.
- GreetZ to all the Le££e team :)
