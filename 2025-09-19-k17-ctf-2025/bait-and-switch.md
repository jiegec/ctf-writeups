# bait and switch

```
This store promised me a free gift if I downloaded their app, but it's not working >:(
```

There is a page to redeem gift, it says we should input 1337 as redeem code, however the string validator requires it to have length less than or equal to 3 (decompiled in IDA):

```c
// main.makeGiftPage.func2
retval_B440A0 __golang main_makeGiftPage_func2(__int64 a1, __int64 a2)
{
  errors_errorString *p_errors_errorString; // rax
  retval_B440A0 result; // 0:rax.8,8:rbx.8,16:^20.8

  *(_QWORD *)result._r2 = a1;
  if ( a2 <= 3 )
  {
    result._r0 = 0;
    result._r1 = 0;
  }
  else
  {
    p_errors_errorString = (errors_errorString *)runtime_newobject(&RTYPE_errors_errorString);
    p_errors_errorString->s.len = 30;
    p_errors_errorString->s.ptr = "Code must be between 0 and 999";
    result._r1 = p_errors_errorString;
    result._r0 = go_itab__ptr_errors_errorString_comma_error;
  }
  return result;
}
```

The process to find it:

1. from `main_main`, visit `main_makeGiftPage`
2. from `main_makeGiftPage`, find the string validator:

```c
p__2_fyne_StringValidator = (_2_fyne_StringValidator *)runtime_newobject(&RTYPE__2_fyne_StringValidator);
(*p__2_fyne_StringValidator)[0] = (PTR_fyne_StringValidator)off_D90DF8;
(*p__2_fyne_StringValidator)[1] = (PTR_fyne_StringValidator)off_D90E00;
```

3. the second field points to the function we mentioned above:

```c
p__2_fyne_StringValidator = (_2_fyne_StringValidator *)runtime_newobject(&RTYPE__2_fyne_StringValidator);
(*p__2_fyne_StringValidator)[0] = (PTR_fyne_StringValidator)off_D90DF8;
(*p__2_fyne_StringValidator)[1] = (PTR_fyne_StringValidator)off_D90E00;
```

We can patch the `a2 <= 3` check by replacing `jle` (opcode 0x7e) with `jg` (opcode 0x7f). Then, we can redeem the code using 1337:

![](./bait-and-switch.png)

Flag: `K17{i_d0n't_th1nk_fi$h_lik3_w@sabi}`.
