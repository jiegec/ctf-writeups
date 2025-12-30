# 谍影重重 6.0

合作者：@Yasar @NanoApe

附件内是一个 pcap 文件，里面有很多个 UDP，Payload 格式经过分析，大致如下：

1. 0-4 字节：每次加一，packet number
2. 4-8 字节：每次加 160，已发送的字节数，sequence number
3. 8-12 字节：未知，同 UDP 端口下不变
4. 12-172 字节：Payload

@Yasar 发现 Payload 是音频数据的浮点数格式，把每个 UDP 的 payload 提取出来，转成 wav 文件：

```python
import numpy as np
import wave

# get data from pcap omitted

arr_u8 = np.frombuffer(data, dtype=np.uint8)

MU_LAW_BIAS = 0x84
def mulaw_decode_byte(mu):
    mu = ~mu & 0xFF
    sign = mu & 0x80
    exponent = (mu >> 4) & 0x07
    mantissa = mu & 0x0F
    magnitude = ((mantissa << 1) + 1) << (exponent + 2)
    magnitude = magnitude - MU_LAW_BIAS
    sample = -magnitude if sign else magnitude
    return np.int16(max(-32768, min(32767, sample << 2)))

arr_mulaw_decoded = np.array([mulaw_decode_byte(int(b)) for b in arr_u8], dtype=np.int16)
with wave.open('ulaw_decoded_8k_s16.wav', 'wb') as wf:
    wf.setnchannels(1)
    wf.setsampwidth(2)
    wf.setframerate(8000)
    wf.writeframes(arr_mulaw_decoded.tobytes())
```

如此可以得到 1000+ 个 wav 文件。由于内容太多，所以丢给 ASR 进行语音识别：

```python
# based on https://github.com/jiegec/video2srt
import argparse
import os
import base64
from re import S
from time import sleep

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.asr.v20190614 import asr_client, models

parser = argparse.ArgumentParser(
    description='Recognize audio')
parser.add_argument('audios', metavar='AUDIO', type=str, nargs='+',
                    help='path to audio files')
parser.add_argument('--secret-id', type=str,
                    help='secret id')
parser.add_argument('--secret-key', type=str,
                    help='secret key')

args = parser.parse_args()
for audio in args.audios:
    print('Processing {}'.format(audio))
    base, ext = os.path.splitext(audio)
    srt = '{}.srt'.format(base)
    json = '{}.json'.format(base)

    # Step 1: upload to tencent cloud
    print('Upload to tencent cloud')
    cred = credential.Credential(args.secret_id, args.secret_key)
    client = asr_client.AsrClient(cred, "ap-shanghai")

    data = open(audio, 'rb').read()

    req = models.CreateRecTaskRequest()
    req.EngineModelType = "16k_zh"
    req.ChannelNum = 1
    req.ResTextFormat = 2
    req.SourceType = 1
    req.ConvertNumMode = 3
    req.FilterModal = 1
    req.Data = base64.b64encode(data).decode('utf-8')
    resp = client.CreateRecTask(req)

    task_id = resp.Data.TaskId

    # Step 2: retrieve result
    while True:
        print('Wait for result')
        req = models.DescribeTaskStatusRequest()
        req.TaskId = task_id
        resp = client.DescribeTaskStatus(req)
        if resp.Data.StatusStr == "success":
            print(f'Save json result to {json}')
            open(json, 'w').write(resp.to_json_string())
            break
        sleep(5)

    # Step 3: save to srt
    print(f'Save subtitle to {srt}')
    result = resp.Data.Result
    counter = 1
    with open(srt, 'w') as f:
        for line in result.split('\n'):
            if len(line) == 0:
                break
            parts = line.split(']')
            times = parts[0].split(',')
            time_from = times[0][1:]
            time_to = times[1][:-1]

            print(counter, file=f)
            print('0:{} --> 0:{}'.format(time_from, time_to), file=f)
            print(']'.join(parts[1:]).strip(), file=f)
            print('', file=f)

            counter += 1
```

在结果里，找到一段强网杯 2025 相关的字符串：

```srt
==> ulaw_decoded_8k_s16_40259.srt <==
1
0:0:0.000 --> 0:0:5.14
第9届全网杯2025震撼来袭，你准备好了吗？

2
0:0:19.800 --> 0:0:44.70
四六我不您解后一条命令，6514663451427161661421466040145664160141451426071146466014214371606514214470。
啥玩意儿
```

@NanoApe 指出，这是一系列的 ascii 码，转成 8 进制后拼接的结果：

1. `5` -> 53 (dec) -> 65 (oct)
2. `f` -> 102 (dec) -> 146 (oct)

因此对应的字符串是 5f3eb916bf08e610aeb09f60bc955bd8。可以得到一段 mp3，经过语音识别：

```
表兄近日可好，上回托您带的甘四担秋茶，家母嘱咐务必在辰时正过三刻前送到，切记用金丝锦盒装妥，此处潮气重，莫让干货瘦了霉，若赶得及时可赶得菊花开前便可让铺子开张，

一切安好，我会按照要求准备好抽查我该送到何地，

送至双鲤湖西岸，南山茶铺放右边第二个橱柜莫放错，

我已知悉你在那边可还安好，

一切安好，希望你我二人早日相见，

指日可待。茶叶送到了，但是晚了时日，茶铺看来只能另寻良辰吉日了，你在那边千莫保重
```

@NanoApe 根据 `双鲤湖西岸南山茶铺`，查到 1949 年 10 月金门战役的历史事件，结合已有信息：

1. 年份：1949，金门战役
2. 月份：10，金门战役
3. 日期：24，廿四
4. 小时：8，辰时
5. 分钟：45，三刻

最终得到：`1949年10月24日8时45分于双鲤湖西岸南山茶铺`。
