# Painted Black

Find Visual Basic source code in Microsoft Word:

```vb
Sub PaintItBlack()
    Dim selectedText As String
    Dim encryptedText As String
    Dim key As String
    Dim xorChar, keyPos
    
    selectedText = Selection.Text
    key = Replace(LCase(Application.UserName), " ", "")
    encryptedText = ""
    
    For i = 1 To Len(selectedText)
        keyPos = i Mod Len(key) + 1
        xorChar = Asc(Mid(selectedText, i, 1)) Xor Asc(Mid(key, keyPos, 1)) Xor &H7B
        encryptedText = encryptedText & Chr(xorChar)
    Next i
    
    Selection.Text = encryptedText
    Selection.Shading.BackgroundPatternColor = wdColorBlack
    Selection.Font.ColorIndex = wdBlack
End Sub
```

The user name can be found in word: `Olivia Renshaw`. Decrypt using python:

```python
enc = "q~luaj*-:\"#j!rs4v,k| <u-9'$wity8\x7f$9!.q"
key = "oliviarenshaw"
for i in range(len(enc)):
    print(chr(ord(enc[i]) ^ ord(key[(i + 1) % len(key)]) ^ 0x7b), end='')
```

Solved!
