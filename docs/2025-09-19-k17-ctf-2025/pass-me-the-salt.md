# pass me the salt

```
Pretty pleaseeeeee 🥺🥺🥺
nc challenge.secso.cc 7002 
```

Attachment:

```python
from hashlib import sha1
import os

logins = {}
salts = {}

def create_account(login, pwd):
    if login in logins.keys():
        return False
    
    salt = os.urandom(16)
    salted_pwd = salt + (pwd).encode()
    passw = sha1(salted_pwd).hexdigest()
    
    logins[login] = passw
    salts[login] = salt

    return True

def check_login(login, pwd):
    if login not in logins:
        return False

    salt = salts[login]
    salted_pwd = salt + bytes.fromhex(pwd)

    passw = sha1(salted_pwd).hexdigest()
    return passw == logins[login]

def change_password(login, new_pass):
    if login not in logins:
        return
    
    print(f"Current password: {logins[login]}")

    logins[login] = new_pass

if __name__ == "__main__":
    create_account("admin", "admin".encode().hex())

    while True:
        option = input("1. Create Account\n2. Login\n3. Change Password\n(1, 2, 3)> ")
        if option == "1":
            login = input("Login: ")
            pwd = input("Password: ")
            if create_account(login, pwd.encode().hex()):
                print("Account created!")
            else:
                print("Could not create account.")
        elif option == "2":
            login = input("Login: ")
            pwd = input("Password: ")

            if not check_login(login, pwd):
                print("Invalid login or password.")
                continue

            if login == "admin":
                if pwd != "admin".encode().hex():
                    print(f"Congratulations! Here is your flag: {os.getenv("FLAG")}")
                else:
                    print("Your flag is in another castle...")
            else:
                print(f"Login successful as {login}!")
        elif option == "3":
            login = input("Login: ")
            new_pass = input("New password: ")

            change_password(login, new_pass)
            print("Password changed!")
        else:
            print("Invalid option.")
```

## DeepSeek

Ask DeepSeek to solve it:

To solve this CTF challenge, the goal is to log in as the "admin" user with a password that is not the default hex-encoded "admin" (which is '61646d696e') but still passes the authentication check. The vulnerability arises from a mismatch in how passwords are handled during account creation and login. 

During account creation, the password is first hex-encoded and then encoded to bytes before being combined with the salt and hashed. For example, the admin account is created with the password "admin", which becomes '61646d696e' when hex-encoded. Then, in `create_account`, this hex string is encoded to bytes (b'61646d696e') before hashing.

During login, the password input is expected to be a hex string, which is converted to bytes using `bytes.fromhex()`. To authenticate successfully, the bytes produced by `bytes.fromhex(pwd)` must match the bytes used during account creation. For the admin account, this means `bytes.fromhex(pwd)` must equal b'61646d696e'.

The hex representation of b'61646d696e' is '36313634366436393665'. Therefore, by logging in with the password '36313634366436393665', the authentication will succeed because it correctly reconstructs the bytes used during the hash computation. Additionally, since this password is not equal to '61646d696e', the condition in the login check for admin will be satisfied, and the flag will be printed.

### Steps to Retrieve the Flag:

1. Run the provided Python script.
2. Select option "2" to login.
3. Enter "admin" as the login.
4. Enter "36313634366436393665" as the password.
5. The flag will be displayed.

This approach exploits the password handling inconsistency to achieve successful authentication without needing to change the password or know the salt.

Follow the steps:

```shell
$ nc challenge.secso.cc 7002
1. Create Account
2. Login
3. Change Password
(1, 2, 3)> 2
Login: admin
Password: 36313634366436393665
Congratulations! Here is your flag: K17CTF{s4Lt_4nD_p3pper_is_ov3rr4t3d}
1. Create Account
2. Login
3. Change Password
(1, 2, 3)>
```

Flag: `K17CTF{s4Lt_4nD_p3pper_is_ov3rr4t3d}`.
