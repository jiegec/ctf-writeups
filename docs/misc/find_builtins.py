import re

for obj in [(), [], {}, ""]:
    classes = obj.__class__.__subclasses__()
    for i, c in enumerate(classes):
        for attr in dir(c):
            try:
                if "__builtins__" in getattr(c, attr).__globals__:
                    print(repr(obj), i, attr, c)
            except:
                pass
