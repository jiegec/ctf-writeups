# touch-grass-3

```
I asked for grass but got the runaround.

Run a mile in ten minutes for the flag! Android-only this year. Please be safe---participation is at your own risk. If you have any health conditions that may be exacerbated by running, do not take part. Don't forget that you can always hack this challenge instead.

The app collects some data (like location) for purposes of the challenge. Your location data will not be shared.
```

Reading the code in browser:

```js
class App {
  sessionState = null;
  flag = null;
  id = null;
  lat = null;
  lon = null;
  steps = 0;
  permission = 'bad';
  map;
  contentDiv;
  layers = [];
  saveStateChange;
  constructor(p, w, u, C) {
    p !== null &&
    (this.id = p.id, this.steps = p.steps),
    this.map = w,
    this.contentDiv = u,
    this.saveStateChange = C
  }
  rerender(p) {
    if (this.permission !== 'good') (this.permission = 'no-accelerometer') ? this.contentDiv.innerHTML = `
          Accelerometer not found. Are you on Chrome Android?
        
    ` : this.contentDiv.innerHTML = `
          Permissions required.
        
    `;
     else if (this.lat === null || this.lon === null) this.contentDiv.innerHTML = `
        Awaiting location data...
      
    `;
     else if (
      this.id === null ||
      this.sessionState === null ||
      this.sessionState.failed
    ) this.id === null ? this.contentDiv.innerHTML = `
          <button class="start-button">
            Start run
          </button>
        
    ` : this.sessionState === null ? this.contentDiv.innerHTML = `
          Logging in...
        
    ` : this.sessionState.failed &&
    (
      this.contentDiv.innerHTML = `
          <div class="failed">
            <div>
            
      ${ this.sessionState.reason }
            </div>
            <button class="restart-button">
              Restart run
            </button>
          </div>
        
      `
    );
     else {
      const w = path(this.sessionState, [
        this.lat,
        this.lon
      ]),
      u = Math.max(0, MAX_TIME * 1000 - (Date.now() - this.sessionState.start)),
      C = Math.floor(u / 60000),
      f = Math.floor(u % 60000 / 1000),
      M = (length(w) * 0.0006213712).toPrecision(3);
      this.contentDiv.innerHTML = `
        <div class="status">
          <div>
            Remaining time 
      ${ C }:${ f.toString().padStart(2, '0') }
          </div>
          <div>
            Total distance 
      ${ M } miles
          </div>
          <div>
            Travelled 
      ${ this.steps } steps
          </div>
          <button class="restart-button">
            Restart run
          </button>
        </div>
      
      `;
      const mt = this.drawMap(leafletSrcExports.polyline(w, {
        color: 'red',
        weight: 12
      }));
      p &&
      this.map.fitBounds(mt.getBounds())
    }
    this.flag !== null &&
    (this.contentDiv.innerHTML += this.flag),
    this.contentDiv.querySelector('.start-button') ?.addEventListener('click', async() => {
      await this.start()
    }),
    this.contentDiv.querySelector('.restart-button') ?.addEventListener(
      'click',
      async() => {
        this.saveStateChange(null),
        await new Promise(w => setTimeout(w, 100)),
        window.location.reload()
      }
    )
  }
  drawMap(p) {
    return this.layers.forEach(w => w.remove()),
    this.layers = [
      p
    ],
    p.addTo(this.map)
  }
  addSteps(p) {
    this.sessionState &&
    !this.sessionState.failed &&
    (this.steps += p, this.broadcastSave(), this.rerender())
  }
  setPosition(p, w) {
    this.lat = p,
    this.lon = w,
    this.rerender()
  }
  setPermission(p) {
    this.permission = p,
    this.rerender()
  }
  broadcastSave() {
    this.id !== null &&
    this.saveStateChange({
      id: this.id,
      steps: this.steps
    })
  }
  async start() {
    if (this.lat === null || this.lon === null) return;
    const authCheck = await fetch('/oauth-check');
    if (authCheck.status === 401) {
      window.location.href = '/oauth';
      return
    }
    const request = {
      lat: this.lat,
      lon: this.lon
    },
    res = await fetch(
      '/start',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(request)
      }
    );
    if (res.status === 401) {
      window.location.href = '/oauth';
      return
    }
    const data = await res.text(),
    response = eval(`(${ data })`);
    this.id = response.id,
    this.broadcastSave(),
    this.sessionState = response.state,
    this.steps = 0,
    this.rerender(!0)
  }
  async login() {
    if (
      this.id === null ||
      this.sessionState !== null ||
      this.lat === null ||
      this.lon === null
    ) return;
    const p = {
      id: this.id
    },
    u = await(
      await fetch(
        '/login',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(p)
        }
      )
    ).text(),
    C = JSON.parse(u);
    this.flag = C.flag ?? null,
    this.rerender(),
    await new Promise(f => setTimeout(f, 1000)),
    this.sessionState = C.state,
    this.rerender(!0),
    this.sync()
  }
  async sync() {
    if (
      this.id === null ||
      this.sessionState === null ||
      this.lat === null ||
      this.lon === null
    ) return;
    const p = {
      id: this.id,
      lat: this.lat,
      lon: this.lon
    },
    u = await(
      await fetch(
        '/update',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(p)
        }
      )
    ).text(),
    C = JSON.parse(u);
    this.sessionState = C.state,
    this.flag = C.flag ?? null,
    this.rerender()
  }
}
```

It periodically reports your location to the server, and the server gives the flag back. I do not have Android phone, so I just wrote a Python script to fake it.

Steps:

1. Login via `/oauth` and grab cookie from the website
2. Start a new run via `/start`
3. Periodically send location to the server via `/update`, not too fast, not too slow
4. Check the flag response

It appears that, after ~20 requests, the flag becomes:

```js
"\n  <img\n    style=\"display: none\"\n    id=\"asdf\"\n    src=x onerror=eval(atob('CiAgd2luZG93LmFwcC5zeW5jID0gYXN5bmMgZnVuY3Rpb24gKCkgewogICAgaWYgKHdpbmRvdy5hcHAuaWQgPT09IG51bGwpIHJldHVybgogICAgaWYgKHdpbmRvdy5hcHAubGF0ID09PSBudWxsIHx8IHRoaXMubG9uID09PSBudWxsKSByZXR1cm4KCiAgICBjb25zdCByZXF1ZXN0ID0gewogICAgICBpZDogdGhpcy5pZCwKICAgICAgbGF0OiB0aGlzLmxhdCwKICAgICAgbG9uOiB0aGlzLmxvbiwKICAgICAgc3RlcHM6IHRoaXMuc3RlcHMsCiAgICB9CgogICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goJy91cGRhdGUnLCB7CiAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICBoZWFkZXJzOiB7CiAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywKICAgICAgfSwKICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocmVxdWVzdCksCiAgICB9KQogICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy50ZXh0KCkKICAgIGNvbnN0IHJlc3BvbnNlID0gSlNPTi5wYXJzZShkYXRhKQogICAgdGhpcy5zZXNzaW9uU3RhdGUgPSByZXNwb25zZS5zdGF0ZQogICAgdGhpcy5mbGFnID0gcmVzcG9uc2UuZmxhZyA/PyBudWxsCiAgICB0aGlzLnJlcmVuZGVyKCkKICB9Cg=='))\n  >\n"
```

The decoded javascript is:

```js

  window.app.sync = async function () {
    if (window.app.id === null) return
    if (window.app.lat === null || this.lon === null) return

    const request = {
      id: this.id,
      lat: this.lat,
      lon: this.lon,
      steps: this.steps,
    }

    const res = await fetch('/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    })
    const data = await res.text()
    const response = JSON.parse(data)
    this.sessionState = response.state
    this.flag = response.flag ?? null
    this.rerender()
  }
```

Therefore, we need to add `steps` parameter if we see this. After ~290 requests, another new flag field appears:

```js
"\n  <img\n    style=\"display: none\"\n    id=\"asdf\"\n    src=x onerror=eval(atob('CiAgd2luZG93LmFwcC5zeW5jID0gYXN5bmMgZnVuY3Rpb24gKCkgewogICAgaWYgKHdpbmRvdy5hcHAuaWQgPT09IG51bGwpIHJldHVybgogICAgaWYgKHdpbmRvdy5hcHAubGF0ID09PSBudWxsIHx8IHRoaXMubG9uID09PSBudWxsKSByZXR1cm4KICAgIGlmICh0aGlzLnBob3RvID09PSBudWxsKSByZXR1cm4KCiAgICBjb25zdCByZXF1ZXN0ID0gewogICAgICBpZDogdGhpcy5pZCwKICAgICAgbGF0OiB0aGlzLmxhdCwKICAgICAgbG9uOiB0aGlzLmxvbiwKICAgICAgcGhvdG86IHRoaXMucGhvdG8sCiAgICB9CgogICAgdGhpcy5mbGFnID0gJ0xvYWRpbmcuLi4nCiAgICB0aGlzLnJlcmVuZGVyKCkKCiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgnL3VwZGF0ZScsIHsKICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgIGhlYWRlcnM6IHsKICAgICAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLAogICAgICB9LAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShyZXF1ZXN0KSwKICAgIH0pCiAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLnRleHQoKQogICAgY29uc3QgcmVzcG9uc2UgPSBKU09OLnBhcnNlKGRhdGEpCiAgICB0aGlzLnNlc3Npb25TdGF0ZSA9IHJlc3BvbnNlLnN0YXRlCiAgICB0aGlzLmZsYWcgPSByZXNwb25zZS5mbGFnID8/IG51bGwKICAgIHRoaXMucGhvdG8gPSBudWxsCiAgICB0aGlzLnJlcmVuZGVyKCkKICB9CgogIHdpbmRvdy5hcHAucmVyZW5kZXIgPSBhc3luYyBmdW5jdGlvbiAoKSB7CiAgICBpZiAoIXRoaXMuaW1hZ2VDYXB0dXJlKSB7CiAgICAgIHRoaXMuY29udGVudERpdi5pbm5lckhUTUwgPSBgCiAgICAgICAgPGJ1dHRvbiBpZD0icGhvdG8tYnV0dG9uIj5FbmFibGUgYmFjayBjYW1lcmE8L2J1dHRvbj4KICAgICAgICAke3RoaXMuZmxhZyA/PyAnJ30KICAgICAgYAoKICAgICAgdGhpcy5jb250ZW50RGl2CiAgICAgICAgLnF1ZXJ5U2VsZWN0b3IoJyNwaG90by1idXR0b24nKQogICAgICAgIC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICAgICAgICAgIGNvbnN0IHN0cmVhbSA9IGF3YWl0IG5hdmlnYXRvci5tZWRpYURldmljZXMuZ2V0VXNlck1lZGlhKHsKICAgICAgICAgICAgdmlkZW86IHsgZmFjaW5nTW9kZTogJ2Vudmlyb25tZW50JyB9LAogICAgICAgICAgfSkKICAgICAgICAgIHRoaXMuaW1hZ2VDYXB0dXJlID0gbmV3IEltYWdlQ2FwdHVyZSgKICAgICAgICAgICAgc3RyZWFtLmdldFZpZGVvVHJhY2tzKClbMF0sCiAgICAgICAgICApCiAgICAgICAgICB0aGlzLnJlcmVuZGVyKCkKICAgICAgICB9KQogICAgfSBlbHNlIHsKICAgICAgdGhpcy5jb250ZW50RGl2LmlubmVySFRNTCA9IGAKICAgICAgICA8YnV0dG9uIGlkPSJjYXB0dXJlLWJ1dHRvbiI+VGFrZSBwaG90byBmb3IgZmxhZzwvYnV0dG9uPgogICAgICAgIDxkaXY+CiAgICAgICAgICAgSU1QT1JUQU5UOiBhbnkgcGhvdG9zIHVwbG9hZGVkIHRvIHRoaXMgc2VydmljZSB3aWxsIGJlIHZpZXdlZCBieQogICAgICAgICAgIENURiBvcmdhbml6ZXJzIGFuZCBtYXkgYmUgc2hhcmVkIHdpdGggb3RoZXIgcGFydGljaXBhbnRzLiBBdm9pZAogICAgICAgICAgIHVwbG9hZGluZyBzZW5zaXRpdmUgb3IgcGVyc29uYWxseSBpZGVudGlmaWFibGUgaW5mb3JtYXRpb24uCiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJyPgogICAgICAgICR7dGhpcy5mbGFnID8/ICcnfQogICAgICBgCgogICAgICB0aGlzLmNvbnRlbnREaXYKICAgICAgICAucXVlcnlTZWxlY3RvcignI2NhcHR1cmUtYnV0dG9uJykKICAgICAgICAuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAoKSA9PiB7CiAgICAgICAgICBjb25zdCBibG9iID0gYXdhaXQgdGhpcy5pbWFnZUNhcHR1cmUudGFrZVBob3RvKHsKICAgICAgICAgICAgaW1hZ2VIZWlnaHQ6IDQ4MCwKICAgICAgICAgICAgaW1hZ2VXaWR0aDogNjQwLAogICAgICAgICAgfSkKICAgICAgICAgIGNvbnN0IHJlYWRlciA9IG5ldyBGaWxlUmVhZGVyKCkKICAgICAgICAgIHJlYWRlci5vbmxvYWRlbmQgPSAoKSA9PiB7CiAgICAgICAgICAgIHRoaXMucGhvdG8gPSByZWFkZXIucmVzdWx0CiAgICAgICAgICAgIHRoaXMuc3luYygpCiAgICAgICAgICB9CiAgICAgICAgICByZWFkZXIucmVhZEFzRGF0YVVSTChibG9iKQogICAgICAgIH0pCiAgICB9CiAgfQo='))\n  >\n"
```

Base64 decoded:

```js

  window.app.sync = async function () {
    if (window.app.id === null) return
    if (window.app.lat === null || this.lon === null) return
    if (this.photo === null) return

    const request = {
      id: this.id,
      lat: this.lat,
      lon: this.lon,
      photo: this.photo,
    }

    this.flag = 'Loading...'
    this.rerender()

    const res = await fetch('/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    })
    const data = await res.text()
    const response = JSON.parse(data)
    this.sessionState = response.state
    this.flag = response.flag ?? null
    this.photo = null
    this.rerender()
  }

  window.app.rerender = async function () {
    if (!this.imageCapture) {
      this.contentDiv.innerHTML = `
        <button id="photo-button">Enable back camera</button>
        ${this.flag ?? ''}
      `

      this.contentDiv
        .querySelector('#photo-button')
        .addEventListener('click', async () => {
          const stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment' },
          })
          this.imageCapture = new ImageCapture(
            stream.getVideoTracks()[0],
          )
          this.rerender()
        })
    } else {
      this.contentDiv.innerHTML = `
        <button id="capture-button">Take photo for flag</button>
        <div>
           IMPORTANT: any photos uploaded to this service will be viewed by
           CTF organizers and may be shared with other participants. Avoid
           uploading sensitive or personally identifiable information.
        </div>
        <br>
        ${this.flag ?? ''}
      `

      this.contentDiv
        .querySelector('#capture-button')
        .addEventListener('click', async () => {
          const blob = await this.imageCapture.takePhoto({
            imageHeight: 480,
            imageWidth: 640,
          })
          const reader = new FileReader()
          reader.onloadend = () => {
            this.photo = reader.result
            this.sync()
          }
          reader.readAsDataURL(blob)
        })
    }
  }
```

This time, we need to pass a data url as the photo field. After that, we are able to get the real flag.

The attack script (the cookie value and the photo need to be replaced):

```python
import requests
import time
import base64

r = requests.post(
    "https://touch-grass-3.ctfi.ng/start",
    headers={
        # visit https://touch-grass-3.ctfi.ng/oauth and get cookie from browser
        "Cookie": "connect.sid=REDACTED"
    },
    json={"lat": 0.0, "lon": 0.0},
)
print(r.text)
resp = r.json()
id = resp["id"]

log = open("log", "w")

has_steps = False
has_photo = False
for i in range(10000):
    json = {
        "id": id,
        "lat": 5 * i / 100000,  # speed
        "lon": 0.0,
    }
    if has_steps and not has_photo:
        # avoid "Not enough/many steps."
        json["steps"] = i * 10
    elif has_photo:
        # some photo
        json["photo"] = "data:image/jpeg;base64,REDACTED"
    r = requests.post(
        "https://touch-grass-3.ctfi.ng/update",
        headers={
            # visit https://touch-grass-3.ctfi.ng/oauth and get cookie from browser
            "Cookie": "connect.sid=REDACTED"
        },
        json=json,
    )

    print(i, has_steps, has_photo)
    print(r.text, file=log)
    log.flush()
    resp = r.json()
    if "flag" in resp and "atob" in resp["flag"]:
        b64 = resp["flag"].split("'")[1]
        decoded = base64.b64decode(b64)
        if b"photo" in decoded:
            has_photo = True
        elif b"steps" in decoded:
            has_steps = True
        else:
            print(resp["flag"])
    time.sleep(0.2)
```

Get flag: `corctf{e8be77aaf9c6ac78876c}`.
