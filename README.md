# Another Python toolkit for interacting with [HaveIBeenPwnd][1]

- Implemented in lightweight Python 3, with no dependencies outside the standard library.
- Importable as a module for your own extensions.
- CLI for checking personal details (in bulk) from your own files.
- Allows compressed (gzip) text files as input.
- Honors the rate-limiting policy of the API for breached account queries.

## Checking Password Lists

This module provides two modes of handling password lists:

- Plain text form, actual passwords in a text file, one per line.
- SHA1 hashed form, i.e. a file full of hashes, one per line.

### Scanning a plain-text password list

```
$> python3 -m pwned --password ./sample/passwords_local.txt  ./sample/passwords.txt 
# Checking provided password lists for compromises...
Password #0 in ./sample/passwords.txt is compromised 4200 times. (exa...ple)
Password #1 in ./sample/passwords.txt is compromised 3645804 times. (pas...ord)
Password #2 in ./sample/passwords.txt is compromised 51259 times. (P@s...0rd)
Password #3 in ./sample/passwords_local.txt is compromised 8 times. (8t3...qu7)

```

### Scanning a SHA1 hash list

```
$> python3 -m pwned --hashed --password ./sample/passwords_hashed.txt 
# Checking provided password lists for compromises...
Password #0 in ./sample/passwords_hashed.txt is compromised 2401761 times. (e38...a3d)
```

## Checking Email Lists

**NOTE** This is actually not yet functional. In my first pass at developing it, I apparently got blacklisted by the rate-limiting and other infrastructure `HaveIBeenPwned` leverages.

It's intended to work about like this...

```
$> python3 -m pwned --email ./sample/emails.txt 
# Checking provided email lists for compromised accounts...
Email #0 [test@example.com]  in ./sample/emails.txt is compromised 2401761 times.
```

Due to the rate-limiting policy on the API, this module also waits ~1.5s between each query for breached accounts by email address.

As soon as the blacklist status has been lifted, I'll resume work on this functionality.

[1]: http://haveibeenpwned.com