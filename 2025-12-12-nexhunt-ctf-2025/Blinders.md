# Blinders

```
the picture is not just a picture

Author : chouaib boudouh
```

Writeup written by AI agent:

# Solution for Blinders CTF Challenge

## Challenge Analysis
The challenge provides a PNG image file `output.png` with the hint "the picture is not just a picture". The challenge name "Blinders" suggests steganography or hidden data.

## Solution Steps

1. **PNG Analysis**: The PNG file appears normal at first glance (1280x853 RGBA image).

2. **Steganography Detection**: Standard stego tools and LSB analysis didn't immediately reveal the flag.

3. **Proper PNG Decoding**: Writing a proper PNG decoder revealed that the image uses filter type 4 (Paeth filter) for most scanlines.

4. **LSB Steganography Extraction**: After properly decoding the PNG (applying inverse filters), extracting the Least Significant Bit (LSB) from each color channel revealed hidden messages:

   - **Red channel LSB**: `nexus{fake_flag_123}`
   - **Green channel LSB**: `nexus{lmao_not_the_flag}`
   - **Blue channel LSB**: `nexus{dummy_text_zzz}`
   - **Alpha channel LSB**: `nexus{yea_u_didi_v2er_wekcj7}`

5. **Flag Identification**: The alpha channel contains what appears to be the real flag: `nexus{yea_u_didi_v2er_wekcj7}`

## Technical Details

- The hidden data was stored in the LSB (least significant bit) of each pixel channel
- All four channels (R, G, B, A) contained different messages
- The alpha channel message appears to be the legitimate flag
- Proper PNG decoding (including inverse filtering) was necessary to extract the correct LSB data

## Tools Used
- Custom Python PNG decoder with proper filter handling
- LSB extraction from decoded pixel data
- Hex decoding of extracted binary data

## Flag
`nexus{yea_u_didi_v2er_wekcj7}`