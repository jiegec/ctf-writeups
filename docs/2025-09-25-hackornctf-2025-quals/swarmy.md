# SwArmy

```
Sigurd Petter Ludvig { Sexa Trea Nolla Caesar Tvåa Filip Ett Caesar Nolla Erik Erik Ett Bertil Åtta David Sju David Adam Femma Sju Caesar Filip Åtta Nia Trea Sexa Adam Erik Sju Erik Sju Åtta Tvåa Sju Fyra Adam Bertil Adam Nolla Bertil Filip David Sju Sexa Femma Filip Erik Ett Nolla Adam Tvåa Nolla David Filip Erik Femma Åtta Nolla Filip Nia Erik Erik Caesar Caesar }
```

Some words correspond to Swedish numbers. Others correspond to their initials:

```python
text = "Sigurd Petter Ludvig { Sexa Trea Nolla Caesar Tvåa Filip Ett Caesar Nolla Erik Erik Ett Bertil Åtta David Sju David Adam Femma Sju Caesar Filip Åtta Nia Trea Sexa Adam Erik Sju Erik Sju Åtta Tvåa Sju Fyra Adam Bertil Adam Nolla Bertil Filip David Sju Sexa Femma Filip Erik Ett Nolla Adam Tvåa Nolla David Filip Erik Femma Åtta Nolla Filip Nia Erik Erik Caesar Caesar }"
numbers = {
    "Nolla": 0,
    "Ett": 1,
    "Tvåa": 2,
    "Trea": 3,
    "Femma": 5,
    "Fyra": 4,
    "Sexa": 6,
    "Sju": 7,
    "Åtta": 8,
    "Nia": 9,
}
for part in text.split():
    if part in numbers:
        print(numbers[part], end="")
    elif part.isalpha():
        print(part[0], end="")
    else:
        print(part, end="")
```

Flag: `SPL{630C2F1C0EE1B8D7DA57CF8936AE7E78274ABA0BFD765FE10A20DFE580F9EECC}`.
