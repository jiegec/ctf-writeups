# The Payload

```
With the malware extracted, Holmes inspects its logic. The strain spreads silently across the entire network. Its goal? Not destruction-but something more persistent…friends. NOTE: The downloaded file is active malware. Take the necessary precautions when attempting this challenge.
```

## Question #1

```
During execution, the malware initializes the COM library on its main thread. Based on the imported functions, which DLL is responsible for providing this functionality? (filename.ext)
```

List imported functions:

```shell
$ objdump -x AetherDesk-v74-77.exe
        DLL Name: ole32.dll
        vma:     Ordinal  Hint  Member-Name  Bound-To
        00005358  <none>  002b  CoCreateInstance
        00005360  <none>  0091  CoUninitialize
        00005368  <none>  0060  CoInitialize
        00005370  <none>  01c1  OleRun
```

## Question #2

```
Which GUID is used by the binary to instantiate the object containing the data and code for execution? (********-****-****-****-************)
```

Open the binary in IDA:

```
Instance = CoCreateInstance(&rclsid, 0, 0x17u, &riid, (LPVOID *)pUnknown);

.rdata:0000000140005A48 ; const IID rclsid
.rdata:0000000140005A48 rclsid          IID <0DABCD999h, 1234h, 4567h, <89h, 0ABh, 12h, 34h, 56h, 78h, 90h, \
.rdata:0000000140005A48                                         ; DATA XREF: sub_140001310+446↑o
.rdata:0000000140005A48                                         ; main+5B↑o
.rdata:0000000140005A48                      0FFh>>
```

The GUID is `DABCD999-1234-4567-89AB-1234567890FF`.

Binary Ninja can print the guid for you in decompiled code:

```
140001ca2        HRESULT hr_1 = CoCreateInstance(
140001ca2            rclsid: &_GUID_dabcd999_1234_4567_89ab_1234567890ff, pUnkOuter: 0, 
140001ca2            dwClsContext: 0x17, riid: &_GUID_00000000_0000_0000_c000_000000000046, 
140001ca2            ppv: &pAddrInfo_1)
```

## Question #3

```
Which .NET framework feature is the attacker using to bridge calls between a managed .NET class and an unmanaged native binary? (string)
```

Search online:

1. P/Invoke
2. C++/CLI
3. Com Interop

The third one is the answer.

## Question #4

```
Which Opcode in the disassembly is responsible for calling the first function from the managed code? (** ** **)
```

Call COM function:

```
(*(void (__fastcall **)(__int64, __int64 *))(*(_QWORD *)v5 + 104LL))(v5, &v73);
```

Corresponding instruction:

```
.text:0000000140001D23                 call    qword ptr [rax+68h]
```

Hex:

`ff 50 68`

## Question #5

```
Identify the multiplication and addition constants used by the binary's key generation algorithm for decryption. (*, **h)
```

Decompile in Binary Ninja:

```c
140001d75                if (__isa_available < 6)
140001d75                {
140001f17                    do
140001f17                    {
140001f09                        *(uint8_t*)(&var_1f8 + i) = (uint8_t)i * 7 + 0x42;
140001f10                        i += 1;
140001f17                    } while (i < 0x20);
140001d75                }
140001d75                else
140001d75                {
140001d7b                    int32_t __xmm@00000000000000010000000000000000_1[0x4] =
140001d7b                        __xmm@00000000000000010000000000000000;
```

Answer: `7, 42h`.

## Question #6

```
Which Opcode in the disassembly is responsible for calling the decryption logic from the managed code? (** ** **)
```

Call COM function:

```
  v54 = (*(__int64 (__fastcall **)(__int64, _QWORD, _QWORD, PCSTR *))(*(_QWORD *)v50 + 88LL))(
          v50,
          *(_QWORD *)v53,
          *v51,
          &pNodeName);
```

Corresponding instruction:

```
.text:00000001400020F6                 call    qword ptr [rax+58h]
```

Hex:

`ff 50 58`

## Question #7

```
Which Win32 API is being utilized by the binary to resolve the killswitch domain name? (string)
```

List imported functions:

```shell
$ objdump -x AetherDesk-v74-77.exe
        DLL Name: WS2_32.dll
        vma:     Ordinal  Hint  Member-Name  Bound-To
        00005208  <none>  00a5  freeaddrinfo
        00005210    116  <none> <none>
        00005218  <none>  00a6  getaddrinfo
        00005220    115  <none> <none>
```

## Question #8

```
Which network-related API does the binary use to gather details about each shared resource on a server? (string)
```

List imported functions:

```shell
$ objdump -x AetherDesk-v74-77.exe
        DLL Name: NETAPI32.dll
        vma:     Ordinal  Hint  Member-Name  Bound-To
        00005160  <none>  0052  NetApiBufferFree
        00005168  <none>  00e0  NetShareEnum
```

## Question #9

```
Which Opcode is responsible for running the encrypted payload? (** ** **)
```

In `ScanAndSpread`:

```
14000197a                    (*(uint64_t*)(*(uint64_t*)rbx_3 + 0x60))(rbx_3, rax_11, 
14000197a                        *(uint64_t*)rsi_4, *(uint64_t*)rdi_3);
140001987                    rsi_4[2] -= 1;
```

Assembly:

```
14000197a  ff5060             call    qword [rax+0x60]
```

`ff 50 60`

## Question #10

```
Find → Block → Flag: Identify the killswitch domain, spawn the Docker to block it, and claim the flag. (HTB{*******_**********_********_*****})
```

The key generation function:

```c
140001f17                    do
140001f17                    {
140001f09                        *(uint8_t*)(&var_1f8 + i) = (uint8_t)i * 7 + 0x42;
140001f10                        i += 1;
140001f17                    } while (i < 0x20);
```

Encrypted payload:

```c
1400020cc                        *(uint64_t*)r15_1 =
1400020cc                            _com_util::ConvertStringToBSTR("KXgmYHMADxsV8uHiuPPB3w==");
```

Decrypt:

```python
import base64

data = base64.b64decode("KXgmYHMADxsV8uHiuPPB3w==")

key = bytearray()
for i in range(32):
    key.append((i * 7 + 0x42) & 0xFF)

print(bytes([x ^ y for x, y in zip(key, data)]))
```

Output:

```
k1v7-echosim.net
```

Block the domain in the provided docker and get flag:

`HTB{Eternal_Companions_Reunited_Again}`.
