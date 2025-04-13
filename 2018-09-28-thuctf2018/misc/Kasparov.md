Kasparov 300 points
================

题意
-------------

Another chess game, try to win this time.

nc host ip

解题步骤
-------------

首先，枚举来破译一个四位的 SHA256 PoW。接着，需要和对方限时下赢 20 把。经测试，对方 AI 水平十分低，但是时间十分短，手动赢 20 把难以及时完成。于是写脚本，采用已有的 Stockfish AI 与之对战。对战脚本如下（[chess.py](chess.py)）：

```
from __future__ import print_function
import hashlib
import socket
import time
import chess
import chess.uci
from itertools import groupby
def work():
    engine = chess.uci.popen_engine("stockfish")
    output = open('output.txt', 'w')
    print('begin round')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('202.112.51.234', 4004))
    data = s.recv(1024)
    output.write(data)
    salt = data[12:28]
    target = data[32:-1]
    arr = range(ord('a'),ord('z'))+range(ord('A'),ord('Z')) + range(ord('0'), ord('9'))
    for i in arr:
        for j in arr:
            for k in arr:
                for l in arr:
                    test = str(chr(i)) + chr(j) + chr(k) + chr(l)
                    if hashlib.sha256(test+salt).hexdigest() == target:
                        print(test, test.encode('hex'))
                        s.sendall(test+'\n')
                        won = 0
                        fd = s.makefile()
                        while True:
                            line = fd.readline()
                            output.write(line)
                            output.flush()
                            print(line, end='')
                            if 'THUCTF{' in line:
                                print(line)
                                exit(0)
                            if line == 'game starts\n' or line == 'input your move(like e2e4):\n':
                                board_str = ''
                                board_rows = []
                                flag = False
                                for i in range(0, 8):
                                    board_row = fd.readline()
                                    if 'THUCTF{' in board_row:
                                        print(board_row)
                                        exit(0)
                                    output.write(board_row)
                                    output.flush()
                                    if board_row == 'you win\n':
                                        won += 1
                                        print('won %d' % won)
                                        flag = True
                                        break
                                    row = board_row.replace(' ','').replace('\n','')
                                    board_rows.append(''.join(key*len(list(group)) if key.isalpha() else str(len(list(group))) for key, group in groupby(row)))
                                if flag:
                                    continue
                                board_str = '/'.join(board_rows)+' w KQkq - 0 1'
                                #print(board_str)
                                board = chess.Board(board_str)
                                engine.position(board)
                                move, _ = engine.go(movetime=100)
                                s.sendall(move.uci() + '\n')
                                print(move.uci())
                        return

while True:
    work()
```

得到 `flag` ：

```
THUCTF{y0u_are_Chess_m@ster}
```
