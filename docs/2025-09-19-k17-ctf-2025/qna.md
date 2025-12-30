# qna

```
What does dna even stand for??

Note: The flag format for this challenge is CTF{.*}
```

Decompile via IDA Free, there is a condition that validates input:

```c
if ( v47 == NUITKA_BOOL_TRUE )
{
  v70 = LOOKUP_BUILTIN(v46);
  if ( !v70 )
    __assert_fail((const char *)&stru_486B4A.native_thread_id + 2, "module.__main__.c", 0xA35u, "modulecode___main__");
  p_ob_base = module_var_accessor___main___c((PyThreadState *)module);
  if ( !p_ob_base )
  {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(0, v45, (PyObject *)&exception_state);
    if ( !HAS_EXCEPTION_STATE(&exception_state) )
      __assert_fail("HAS_EXCEPTION_STATE(&exception_state)", "module.__main__.c", 0xA3Cu, "modulecode___main__");
    goto LABEL_28;
  }
  v71 = module_var_accessor___main___flag((PyThreadState *)module);
  if ( !v71 )
  {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR((PyThreadState *)p_ob_base, 0, (PyObject *)&exception_state);
    if ( !HAS_EXCEPTION_STATE(&exception_state) )
      __assert_fail("HAS_EXCEPTION_STATE(&exception_state)", "module.__main__.c", 0xA4Au, "modulecode___main__");
    goto LABEL_28;
  }
  v9->m_frame.f_lineno = 26;
  p_ob_base = CALL_FUNCTION_WITH_SINGLE_ARG(
                (PyThreadState *)v71,
                &module->m_frame.ob_base,
                exception_state.exception_value);
  if ( p_ob_base )
  {
    v9->m_frame.f_lineno = 26;
    v72 = CALL_FUNCTION_WITH_SINGLE_ARG(
            (PyThreadState *)v71,
            &module->m_frame.ob_base,
            exception_state.exception_value);
    if ( (int)p_ob_base->ob_refcnt >= 0 )
    {
      v73 = p_ob_base->ob_refcnt - 1;
      p_ob_base->ob_refcnt = v73;
      if ( !v73 )
        Py_Dealloc(p_ob_base, v70);
    }
    if ( v72 )
    {
      if ( (int)v72->ob_refcnt >= 0 )
      {
        v74 = v72->ob_refcnt - 1;
        v72->ob_refcnt = v74;
        if ( !v74 )
          Py_Dealloc(v72, v70);
      }
      goto LABEL_83;
    }
    if ( !module->m_interpreter_frame.f_globals )
      __assert_fail("HAS_ERROR_OCCURRED(tstate)", "module.__main__.c", 0xA62u, "modulecode___main__");
  }
  else if ( !module->m_interpreter_frame.f_globals )
  {
    __assert_fail("HAS_ERROR_OCCURRED(tstate)", "module.__main__.c", 0xA55u, "modulecode___main__");
  }
  goto LABEL_193;
}
```

We simply replaces the `if ( v47 == NUITKA_BOOL_TRUE )` to `if (1)` in assmbly. Then, we can enter anything to get flag:

```shell
$ ./chall.bin.patched
Its simple really...you give me the right input, I give you the right flag!
aaa57b4305611fcade963172655334cbe2fe6135

Input > 123456
CTF{nu1tk4_m41war3_i3_k0oL}
```

Flag: `CTF{nu1tk4_m41war3_i3_k0oL}`.
