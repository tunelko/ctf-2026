# Perceptions — Web (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Web
**Difficulty:** Beginner
**Author:** x03e
**Flag:** `0xfun{p3rsp3c71v3.15.k3y}`

---

## Description

> Take a look at the blog I created! It has a neat backend and, interestingly, seems to use fewer ports.

## Reconnaissance

The server (`hypercorn-h11`, ASGI Python) redirects to a blog with several pages. The key clues are in the content:

**"My Server"**: *"It used to have a few ports open to run different things but now that I have Perceptions I only need one port for everything."* → The server multiplexes HTTP and SSH on the same port.

**"What I'm Working On"**: *"It will be integrated with the Linux login system."* → Linux authentication (SSH).

**"Secret Post"**: Contains a hidden HTML comment:
```html
<!-- Use my name and 'UlLOPNeEak9rFfmL' to log in -->
```

The endpoint `/name` returns **Charlie**.

## Exploitation

### 1. Obtain credentials

- **Username**: `Charlie` (from `/name`)
- **Password**: `UlLOPNeEak9rFfmL` (from the HTML comment in Secret Post)

### 2. SSH on the same port

The Perceptions server multiplexes protocols. SSH works on the same port as HTTP:

```bash
sshpass -p 'UlLOPNeEak9rFfmL' ssh -p 54059 Charlie@chall.0xfun.org
```

### 3. Navigate the custom shell

The login opens "Charlie's Fun Zone", a restricted shell with `ls`, `cd` and `cat`:

```
/ $ ls
README.txt  secret_flag_333  4C6Y4NEBVLATCF6EX5PA2ISZ  ...

/ $ cd secret_flag_333
/secret_flag_333 $ ls
flag.txt

/secret_flag_333 $ cat flag.txt
0xfun{p3rsp3c71v3.15.k3y}
```

## Summary

1. Explore the blog → find password in HTML comment
2. Identify that SSH runs on the same port (clue: "fewer ports")
3. Connect via SSH with Charlie's credentials
4. Navigate the custom shell filesystem to `secret_flag_333/flag.txt`
