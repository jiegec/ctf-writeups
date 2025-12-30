# pwgen

```
Password policies aren't always great. That's why we generate passwords for our users based on a strong master password!
http://52.59.124.14:5003 
```

A hint is given:

```
pwgen source

    For pwgen you get the source by appending /?source. It now also tells you so on the page.

    September 4th, 11:24:24 PM 
```

The source code is:

```php
<?php
ini_set("error_reporting", 0);
ini_set("short_open_tag", "Off");

if(isset($_GET['source'])) {
    highlight_file(__FILE__);
}

include "flag.php";

$shuffle_count = abs(intval($_GET['nthpw']));

if($shuffle_count > 1000 or $shuffle_count < 1) {
    echo "Bad shuffle count! We won't have more than 1000 users anyway, but we can't tell you the master password!";
    echo "Take a look at /?source";
    die();
}

srand(0x1337); // the same user should always get the same password!

for($i = 0; $i < $shuffle_count; $i++) {
    $password = str_shuffle($FLAG);
}

if(isset($password)) {
    echo "Your password is: '$password'";
}

?>

<html>
    <head>
        <title>PWgen</title>
    </head>
    <body>
        <h1>PWgen</h1>
        <p>To view the source code, <a href="/?source">click here.</a>
    </body>
</html>

Bad shuffle count! We won't have more than 1000 users anyway, but we can't tell you the master password!Take a look at /?source
```

So we can get a shuffled flag via <http://52.59.124.14:5003/?nthpw=1>:

```
Your password is: '7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154'
PWgen

To view the source code, click here. 
```

To recover the flag, we create a string of the same length and shuffle it:

```php
<?php
$password = "";
for ($i = 32; $i <= 32 + 130 - 1; $i++) {
    $password .= chr($i);
}
echo "$password\n";

srand(0x1337);
$shuffled = str_shuffle($password);
echo "$shuffled\n";
?>
```

We then shuffle the characters back to get flag:

```shell
$ cat pwgen.py
f = open("pwgen.txt", "rb")
orig = f.readline()
shuf = f.readline()

cipher = b"7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154"
for i in range(130):
    print(chr(cipher[shuf.index(orig[i])]), end="")
print()
$ php pwgen.php > pwgen.txt
$ python3 pwgen.py
ENO{N3V3r_SHUFFLE_W1TH_STAT1C_S333D_OR_B4D_TH1NGS_WiLL_H4pp3n:-/_0d68ea85d88ba14eb6238776845542cf6fe560936f128404e8c14bd5544636f7}
```
