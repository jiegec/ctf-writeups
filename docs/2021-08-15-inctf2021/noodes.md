# flagchecker

这题主要是 SuperFashi 做的，我提供了一些思路的协助。

也是一道逆向题。有两个进程：父进程用 inotify 监控一个目录，然后子进程按照输入的字符串进行文件操作；最后看父进程观测到的 inotify 事件是否是预期的。子进程可以进行的操作有：

1. 打开一个文件，fd 入栈
2. fd 出栈并 fclose
3. fwrite 栈顶
4. 删除文件
5. chmod 文件
6. 删除文件夹
7. 创建文件夹
8. 结束

首先要找到预期的文件访问历史，说成人话，就是：

```
delete file tT
delete file 1B
close file HX
chmod dir oQ
...
chmod file rl
delete file f1
delete dir yO
chmod file RN
write file Bl
write file Lx
write file Pd
write file JH
write file 1V
close file Bl
close file Lx
close file Xt
close file 93
close file uj
close file Cx
close file Pd
close file JH
close file Xl
close file EZ
close file 1V
close file KP
```

如果按照栈的访问过程，最后这一段是不可能实现的：写 Bl 写 Lx 最后又是关 Bl 关 Lx，不合常理。

于是想到是不是因为 fwrite 有缓存，试了一下，果然：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buffer[] = "test";
  FILE *a = fopen("a", "a+");
  fwrite(buffer, 1, sizeof(buffer), a);
  FILE *b = fopen("b", "a+");
  fwrite(buffer, 1, sizeof(buffer), b);
  return 0;
}
```

```shell
$ strace ./test
openat(AT_FDCWD, "a", O_RDWR|O_CREAT|O_APPEND, 0666) = 3
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=33735, ...}, AT_EMPTY_PATH) = 0
openat(AT_FDCWD, "b", O_RDWR|O_CREAT|O_APPEND, 0666) = 4
newfstatat(4, "", {st_mode=S_IFREG|0644, st_size=16445, ...}, AT_EMPTY_PATH) = 0
write(4, "test\0", 5)                   = 5
write(3, "test\0", 5)                   = 5
exit_group(0)                           = ?
```

可以看到，操作顺序是 打开 a，打开 b，写 b，写 a。这意味着，如果 fwrite 没有达到一定的 buffer（测了一下，是 4096 个字节），那么它不会 flush，当 main 退出的时候，libc 会找到所有打开的 FILE *，然后按照打开顺序的逆序进行 flush。注意，这个 flush 是在用户态实现的。但是，怎么保证写 b 写 a 以后关 b 关 a 这个顺序呢？如果在用户态里面，调用 fclose，那么 close 之前也会立马 flush，不能达到目标的顺序。

于是，我自己测试了一下，看看如果用户态程序不关，让系统关，会怎么样：

```shell
$ inotifywait -m a b
Setting up watches.
Watches established.
# run in another shell
$ ./test
# back to inotifywait
a OPEN 
b OPEN 
b MODIFY 
a MODIFY 
b CLOSE_WRITE,CLOSE 
a CLOSE_WRITE,CLOSE
```

惊喜地发现，OS 回收进程的时候，也是按照打开顺序的逆序进行 close。这样的话，回到题目，我们就找到了解决办法：在 fwrite Bl Lx 等等以后，让子进程正常退出，这个时候 libc 会 flush 掉 fwrite 的内容，从而生成 write Bl write Lx 的记录；然后，OS 回收进程，关掉文件，就会生成 close Bl close Lx 的记录。这样就把这题解决了。