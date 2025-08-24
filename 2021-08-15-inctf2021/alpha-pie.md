# Alpha Pie

这是一个交互题，服务器会发送 9 个题目，每个题目就是从棋盘 A 通过若干次上下左右移动棋子，达到棋盘 B 的样子：

```
Welcome to Alpha pie game!!!
Rules:
1. To complete one level you have match the left matrix to the right one by moiving each letter to their position in the right matrix
2. Moving to only adjecent column or row is possible.
3. Diagonal movements are not possible
4. negative numbers are not allowed in the input
5. The input format should be 'current-x-cord,current-y-cord,to-x-cord,to-y-cord'.
   eg : 0,0,0,1 (Will move letter at position 0,0 to position 0,1 if a letters is present at 0,0 and no letter is present at 0,1).
7. Number of moves will be limited for each level.
8. The game has a time limit of 'n' minutes.
9. You will lose the game if you enter certain number of invalid moves
10. After you pass 9 levels you will ge the flag.
   Good luck ! Enjoy the game 👍

Press 'y' to start: y
Level-1
Max number of moves allowed: 5
+-------+  +-------+
| 0 | x |  | a | 0 |
| 0 | a |  | x | 0 |
+-------+  +-------+
Current moves : 0
Enter move in the format 'current-x-cord,current-y-cord,to-x-cord,to-y-cord ' :
```

基于 pwntools 编写了一个自动读取解析棋盘的代码，考虑到 Python 写算法比较麻烦，这部分用 C++ 实现。没有保证最优解，只是逐个字母 BFS 找最短路径，然后加了一些启发式。

alpha_pie.py:

```python
from pwn import *
import os
import subprocess

context.log_level = 'debug'
conn = remote('misc.challenge.bi0s.in',1337)
conn.recvuntil('start:')
conn.sendline('y')
for level in range(9):
	conn.recvuntil("Level")
	data = conn.recvuntil("Enter move").decode('utf-8')
	begin = False
	size = 0
	matrix_from = []
	matrix_to = []
	row = 0
	allowed = 0
	words = set()
	pos_from = {}
	pos_to = {}
	for line in data.split("\n"):
		line = line.strip()
		if 'allowed:' in line:
			allowed = int(line.split(':')[1].strip())
		if line.startswith('+-'):
			if not begin:
				begin = True
				size = (line[1:].find('+') + 1) // 4
				matrix_from = [[[]] * size for i in range(size)]
				matrix_to = [[[]] * size for i in range(size)]

		if line.startswith('|'):
			parts = [s.strip() for s in line.split('|')]
			parts = list(filter(lambda s: len(s) > 0, parts))
			assert len(parts) == 2 * size
			for i in range(size):
				matrix_from[row][i] = parts[i]
				words.add(parts[i])
				if parts[i] != '0':
					pos_from[parts[i]] = (row, i)
			for i in range(size):
				matrix_to[row][i] = parts[i+size]
				words.add(parts[i+size])
				if parts[i+size] != '0':
					pos_to[parts[i+size]] = (row, i)
			row = row + 1

	words.remove('0')

	with open('input', 'w') as f:
		f.write('{}\n'.format(size))
		f.write('{}\n'.format(allowed))
		f.write('{}\n'.format(len(words)))
		for key in words:
			from_x, from_y = pos_from[key]
			to_x, to_y = pos_to[key]
			f.write('{} {} {} {}\n'.format(from_x, from_y, to_x, to_y))

	res = subprocess.check_output(['./solve'], timeout=1)
	lines = res.decode('utf-8').split("\n")
	lines = list(filter(lambda s: len(s) > 0, lines))
	for line in lines[:-1]:
		conn.sendline(line.strip())
		data = conn.recvuntil("Enter move")
	conn.sendline(lines[-1].strip())
conn.interactive()
```

solve.cpp:

{% raw %}
```cpp
#include <assert.h>
#include <queue>
#include <stdio.h>
#include <string.h>
#include <utility>

const int MAX_N = 1024;

struct Position {
  int from_x;
  int from_y;
  int to_x;
  int to_y;
} pos[MAX_N];

int size;
int allowed;
int n;
int keyboard[MAX_N][MAX_N];
bool visit[MAX_N][MAX_N];
int dist[MAX_N][MAX_N];

int dir[4][2] = {{-1, 0}, {1, 0}, {0, -1}, {0, 1}};

void bfs(int from_x, int from_y, int to_x, int to_y) {
  memset(visit, 0, sizeof(visit));
  memset(dist, 0, sizeof(dist));
  if (from_x == to_x && from_y == to_y) {
    return;
  }
  visit[from_x][from_y] = true;
  std::queue<std::pair<int, int>> q;
  q.push(std::make_pair(from_x, from_y));
  while (!q.empty()) {
    std::pair<int, int> cur = q.front();
    int cur_x = cur.first;
    int cur_y = cur.second;
    q.pop();
    if (cur_x == to_x && cur_y == to_y) {
      break;
    }
    for (int i = 0; i < 4; i++) {
      int new_x = cur_x + dir[i][0];
      int new_y = cur_y + dir[i][1];
      if (new_x >= 0 && new_x < size && new_y >= 0 && new_y < size &&
          !visit[new_x][new_y] && keyboard[new_x][new_y] == 0) {
        visit[new_x][new_y] = true;
        dist[new_x][new_y] = dist[cur_x][cur_y] + 1;
        q.push(std::make_pair(new_x, new_y));
      }
    }
  }

  std::vector<std::pair<int, int>> moves;
  int cur_x = to_x, cur_y = to_y;
  while (cur_x != from_x || cur_y != from_y) {
    moves.push_back(std::make_pair(cur_x, cur_y));
    for (int i = 0; i < 4; i++) {
      int new_x = cur_x + dir[i][0];
      int new_y = cur_y + dir[i][1];
      if (new_x >= 0 && new_x < size && new_y >= 0 && new_y < size &&
          dist[new_x][new_y] == dist[cur_x][cur_y] - 1 && visit[new_x][new_y]) {
        cur_x = new_x;
        cur_y = new_y;
        break;
      }
    }
  }
  moves.push_back(std::make_pair(cur_x, cur_y));

  for (int i = moves.size() - 1; i >= 1; i--) {
    int cur_x = moves[i].first;
    int cur_y = moves[i].second;
    int next_x = moves[i - 1].first;
    int next_y = moves[i - 1].second;
    printf("%d,%d,%d,%d\n", cur_x, cur_y, next_x, next_y);
  }

  // move
  keyboard[to_x][to_y] = keyboard[from_x][from_y];
  keyboard[from_x][from_y] = 0;
}

int main(int argc, char *argv[]) {
  FILE *fp = fopen("input", "r");
  assert(fp);
  fscanf(fp, "%d%d%d", &size, &allowed, &n);
  memset(keyboard, 0, sizeof(keyboard));
  for (int i = 0; i < n; i++) {
    fscanf(fp, "%d%d%d%d", &pos[i].from_x, &pos[i].from_y, &pos[i].to_x,
           &pos[i].to_y);
    keyboard[pos[i].from_x][pos[i].from_y] = i + 1;
  }

  bool vis[MAX_N];
  memset(vis, 0, sizeof(vis));
  // handle these first
  for (int i = 0; i < n; i++) {
    if ((pos[i].from_x == 0 && pos[i].from_y == 0) ||
        (pos[i].from_x == 0 && pos[i].from_y == size - 1) ||
        (pos[i].from_x == size - 1 && pos[i].from_y == size - 1) ||
        (pos[i].from_x == size - 1 && pos[i].from_y == size - 1) ||
        (pos[i].to_x == 0 && pos[i].to_y == 0) ||
        (pos[i].to_x == 0 && pos[i].to_y == size - 1) ||
        (pos[i].to_x == size - 1 && pos[i].to_y == size - 1) ||
        (pos[i].to_x == size - 1 && pos[i].to_y == size - 1)) {
      bfs(pos[i].from_x, pos[i].from_y, pos[i].to_x, pos[i].to_y);
      vis[i] = true;
    }
  }
  for (int i = 0; i < n; i++) {
    if (!vis[i]) {
      bfs(pos[i].from_x, pos[i].from_y, pos[i].to_x, pos[i].to_y);
    }
  }
  return 0;
}
```
{% endraw %}

运行结束之后就可以看到 flag：

`inctf{G00d_Job_e33ac7bae54893252e60c0187e793ef5d13d7dfa85fafa7984f8753b591247b9}`
