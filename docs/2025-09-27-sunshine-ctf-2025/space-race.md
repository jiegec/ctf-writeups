# Space Race
```
NASA was so excited to send their new unmanned rover out to pick up some stranded astronauts that they forgot to actually write the software to control it. Can you take a look at the onboard ECU software and see if you can find a way to establish communications?

If worse comes to worst, maybe they CAN BUS the astronauts back....

    the server binary has been updated to not be stripped

nc chal.sunshinectf.games 25102 
```

Decompile in IDA:

```c
while ( 1 )
{
  v58 = bufio__ptr_Reader_ReadBytes(&b, 0xAu);
  if ( v58._r1.tab )
    break;
  v32 = v58._r0.cap;
  v31 = v58._r0.len;
  v40.array = v58._r0.array;
  p_main_ControlMsg = (main_ControlMsg *)runtime_newobject((runtime__type_1 *)&RTYPE_main_ControlMsg);
  v = (main_ControlMsg_0 *)p_main_ControlMsg;
  p_main_ControlMsg->T.ptr = 0;
  p_main_ControlMsg->Frame.ptr = 0;
  v66.len = v31;
  v66.cap = v32;
  v66.array = v40.array;
  v67 = main_trim(v66);
  v55._type = (runtime__type_0 *)&RTYPE__ptr_main_ControlMsg;
  v55.data = v;
  if ( !(unsigned __int64)encoding_json_Unmarshal(v67, v55).tab )
  {
    str = v->T.str;
    if ( v->T.len == 3 && *(_WORD *)str == 0x6163 && str[2] == 110 )
    {
      v65.len = v->Frame.len;
      if ( v65.len )
      {
        v65.str = v->Frame.str;
        v68 = runtime_stringtoslicebyte((runtime_tmpBuf *)buf, v65);
        raw_array = v68.array;
        v30 = v68.cap;
        v9 = (unsigned __int128)encoding_hex_Decode(v68, v68);
        if ( (unsigned __int64)v9 > v30 )
          runtime_panicSliceAcap();
        if ( !*((_QWORD *)&v9 + 1) && (__int64)v9 >= 3 )
        {
          v10 = raw_array;
          v11 = *(_WORD *)raw_array;
          v12 = raw_array[2] & 0xF;
          if ( (unsigned __int64)v12 <= 8 && (__int64)v9 >= v12 + 3 )
          {
            if ( (unsigned __int64)(v12 + 3) < 3 )
              runtime_panicSliceB();
            v13 = rover;
            v14 = ((__int64)(3 - v30) >> 63) & 3;
            v15 = &raw_array[v14];
            if ( _InterlockedCompareExchange((volatile signed __int32 *)&rover->mu, 1, 0) )
            {
              dlc = v12;
              v36 = v14;
              v40.len = (int)&v10[v14];
              v29 = v11;
              sync__ptr_Mutex_lockSlow(&v13->mu);
              v13 = rover;
              v14 = v36;
              v10 = raw_array;
              v11 = v29;
              v12 = dlc;
              v15 = (uint8 *)v40.len;
            }
            v16 = __ROL2__(v11, 8) & 0x7FF;
            if ( v16 > 0x202u )
            {
              switch ( v16 )
              {
                case 0x203u:
                  v13->vel = v13->vel * 0.65;
                  v13->msg.len = 6;
                  if ( *(_DWORD *)&runtime_writeBarrier.enabled )
                    goto LABEL_58;
                  v13->msg.str = (uint8 *)"Brake!";
                  break;
                case 0x204u:
                  v13->steerPct = 0;
                  v13->heading = v13->heading * 0.9;
                  v13->msg.len = 14;
                  if ( !*(_DWORD *)&runtime_writeBarrier.enabled )
                  {
                    v13->msg.str = (uint8 *)"Stabilizers on";
                    break;
                  }
L_58:
                  runtime_gcWriteBarrierDX();
                  break;
                case 0x205u:
                  if ( v13->status.len != 2 || *(_WORD *)v13->status.str != 27503 )
                  {
                    v13->s = 0.0;
                    v13->x = 0.0;
                    v13->vel = 0.0;
                    *(_OWORD *)&v13->throttlePct = 0;
                    v13->status.len = 2;
                    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
                      runtime_gcWriteBarrierDX();
                    else
                      v13->status.str = (uint8 *)"ok";
                    v13->msg.len = 14;
                    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
                      runtime_gcWriteBarrierSI();
                    else
                      v13->msg.str = (uint8 *)"Reset to start";
                  }
                  break;
                default:
L_73:
                  a = 0;
                  v23 = runtime_convT16(v16);
                  *(_QWORD *)&a = &RTYPE_uint16;
                  *((_QWORD *)&a + 1) = v23;
                  v61.str = (uint8 *)"Unknown CAN 0x%03X";
                  v61.len = 18;
                  v64.len = 1;
                  v64.cap = 1;
                  v64.array = (interface__0 *)&a;
                  v24 = fmt_Sprintf(v61, v64);
                  v13 = rover;
                  rover->msg.len = v24.len;
                  if ( *(_DWORD *)&runtime_writeBarrier.enabled )
                    runtime_gcWriteBarrier();
                  else
                    v13->msg.str = v24.str;
                  break;
              }
            }
            else if ( v16 == 513 )
            {
              if ( v12 >= 1 )
              {
                v17 = v10[v14];
                if ( v17 > 100 )
                  v17 = 100;
                v13->throttlePct = v17;
                a = 0;
                v18 = runtime_convT64(v13->throttlePct);
                *(_QWORD *)&a = &RTYPE_int;
                *((_QWORD *)&a + 1) = v18;
                v59.str = (uint8 *)"Throttle %d%%";
                v59.len = 13;
                v62.len = 1;
                v62.cap = 1;
                v62.array = (interface__0 *)&a;
                v19 = fmt_Sprintf(v59, v62);
                v13 = rover;
                rover->msg.len = v19.len;
                if ( *(_DWORD *)&runtime_writeBarrier.enabled )
                  runtime_gcWriteBarrier();
                else
                  v13->msg.str = v19.str;
              }
            }
            else
            {
              if ( v16 != 514 )
                goto LABEL_73;
              if ( v12 >= 1 )
              {
                v20 = (char)*v15;
                if ( v20 >= -100 )
                {
                  if ( v20 > 100 )
                    v20 = 100;
                }
                else
                {
                  v20 = -100;
                }
                v13->steerPct = v20;
                a = 0;
                v21 = runtime_convT64(v13->steerPct);
                *(_QWORD *)&a = &RTYPE_int;
                *((_QWORD *)&a + 1) = v21;
                v60.str = (uint8 *)"Steer %d%%";
                v60.len = 10;
                v63.len = 1;
                v63.cap = 1;
                v63.array = (interface__0 *)&a;
                v22 = fmt_Sprintf(v60, v63);
                v13 = rover;
                rover->msg.len = v22.len;
                if ( *(_DWORD *)&runtime_writeBarrier.enabled )
                  runtime_gcWriteBarrier();
                else
                  v13->msg.str = v22.str;
              }
            }
            v25 = _InterlockedExchangeAdd((volatile signed __int32 *)&v13->mu, 0xFFFFFFFF);
            if ( v25 != 1 )
              sync__ptr_Mutex_unlockSlow(&v13->mu, v25 - 1);
          }
        }
      }
    }
  }
}
```

The JSON format to sent is shown in `client.py`:

```
TODO: Implement the controls for the rover client!

{"t":"can","frame":"0123456789abcdef"}
```

Reading the code, we know that the frame format is:

1. two bytes of opcode
2. one byte of payload length
3. variable length of payload

Possible opcodes:

1. 0202: steer with one argument, -100 to 100
2. 0203: brake
3. 0204: stablizer
4. 0201: throttle with one argument, 0 to 100

We map these opcodes to keyboard input:

```python
elif e.key == pygame.K_LEFT:
    # -100
    net.sock.send((json.dumps({
        "t": "can",
        "frame": "0202019c"
    }) + "\n").encode())
elif e.key == pygame.K_RIGHT:
    # +100
    net.sock.send((json.dumps({
        "t": "can",
        "frame": "02020164"
    }) + "\n").encode())
elif e.key == pygame.K_b:
    # brake
    net.sock.send((json.dumps({
        "t": "can",
        "frame": "020300"
    }) + "\n").encode())
elif e.key == pygame.K_s:
    # stablizer
    net.sock.send((json.dumps({
        "t": "can",
        "frame": "020400"
    }) + "\n").encode())
elif e.key == pygame.K_r:
    # throttle
    net.sock.send((json.dumps({
        "t": "can",
        "frame": "02010164"
    }) + "\n").encode())
print(e.key)
```

Then we can play the game by pressing `r` and then `Left/Right` to avoid crashing into the obstacles. After winning, the flag is shown.

Flag: `sun{r3d_r0v3r_c0m3_0v3r}`.
