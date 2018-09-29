R = IntegerModRing(257)
string = "THUCTF{}"
num = 6
left = []
for ch in string:
    row = [1]
    for i in range(0, num):
        row.insert(0, row[0]*ord(ch))
    left.append(row)
A = matrix(R, left)
b = matrix(R, [0xca, 0x6d, 0x11, 0x06, 0xca, 0xde, 0xb7, 0x46]).transpose()
res = A.solve_right(b)
print res
all = []
for ch in range(20, 127):
    row = [1]
    for i in range(0, num):
        row.insert(0, row[0]*ch)
    all.append(row)
all_matrix = matrix(R, all)
res2 = all_matrix*res
for ch in range(20, 127):
    print '%c: %02x' % (ch, res2[ch-20][0])
