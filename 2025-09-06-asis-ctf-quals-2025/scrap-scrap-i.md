# ScrapScrap I

```
A web service, http://91.107.176.228:3000, that allows users to scrape websites, but only offers demo accounts that check whether you can be scraped.

If you want to enjoy the service 100%, find a way to get a user account.

Download the attachment!

Thanks to Worty as author! 😊
```

Reading the source code in the attachment, there is a page that contains the flag:

```
<% if (user.username != "superbot") { %>
	<p>Goodjob, the flag is: ASIS{FAKE_FLAG1}</p>
<% } else { %>
	<p>Welcome owner :heart:</p>
<% } %>
<h2>Scrapper</h2>
<form action="/scrap/run" method="post" class="card">
  <label>Website you want to scrap
    <input name="url" type="url" required placeholder="https://exemple.com" />
  </label>
  <button>Scrap scrap scrap !</button>
</form>
```

It can be rendered in:

```js
router.get('/', requireAuth, async (req, res) => {
  res.render('scrap');
});
```

And visited by <http://91.107.176.228:3000/scrap>.

Response:

```
That was the bypass of my first challenge, sorry for that, the flag is : ASIS{e550f23c48cd17e17ca0817b94aa690b}
```

Flag: `ASIS{e550f23c48cd17e17ca0817b94aa690b}`.
