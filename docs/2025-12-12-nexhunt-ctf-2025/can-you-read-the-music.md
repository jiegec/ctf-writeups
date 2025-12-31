# Can you read the music...

```
Not all bombs are made of plutonium. Some are made of secrets.

if you need something "nexus" will help you
```

Writeup written by AI agent:

# Solution Notes for "Can you read the music" Challenge

## Challenge Type
Audio Steganography (LSB - Least Significant Bit encoding)

## Files Provided
- `oppenheimer_challenge.wav`: Audio file containing hidden flag
- `CHALLENGE.md`: Hint file with clues

## Solution Steps

1. **Analyze the WAV file**: The file is a stereo 16-bit PCM WAV file at 48kHz sampling rate.
2. **Understand the hint**: The challenge description mentions "Can you read the music" and the hint says "if you need something 'nexus' will help you". This suggests looking for hidden data in the audio.
3. **Check for LSB steganography**: Audio LSB steganography hides data in the least significant bits of audio samples. Since audio samples are 16-bit values, changing the LSB has minimal impact on sound quality.
4. **Extract LSB data**: Write a Python script to:
    - Read the WAV file using the `wave` module
    - Extract the left channel audio samples
    - Get the least significant bit of each sample (sample & 1)
    - Group bits into bytes (8 bits = 1 byte)
    - Convert bytes to ASCII text
5. **Find the flag**: The extracted text contains the flag in the format `nexus{...}`

## Technical Details

- **Encoding method**: LSB (Least Significant Bit) steganography in the left channel only
- **Flag location**: Hidden in the LSB of the left audio channel samples
- **Flag format**: `nexus{CcAn_Uu_Re3dD_LsB}`
- **Tools used**: Python with `wave` and `numpy` modules

## Extraction Script

```python
import wave
import numpy as np

with wave.open('oppenheimer_challenge.wav', 'rb') as wav:
    frames = wav.readframes(wav.getnframes())
    data = np.frombuffer(frames, dtype=np.int16).reshape(-1, 2)
    left_channel = data[:, 0]
    
    lsb_bits = [int(sample) & 1 for sample in left_channel]
    bytes_list = []
    for i in range(0, len(lsb_bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | lsb_bits[i + j]
        bytes_list.append(byte)
    
    result = bytes(bytes_list).decode('ascii', errors='ignore')
    # Flag: nexus{CcAn_Uu_Re3dD_LsB}
```

## Why This Works

- The human ear cannot perceive changes in the LSB of 16-bit audio samples
- The flag was encoded character by character, with each character's ASCII value converted to 8 bits and stored in consecutive LSBs
- The right channel appears to be unused for data hiding (all zeros in LSB analysis)

## Flag
`nexus{CcAn_Uu_Re3dD_LsB}`
