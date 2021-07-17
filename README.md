![](./assets/smartbrute.png)

## Description

The smart password spraying and bruteforcing tool for Active Directory Domain Services.

This project is released in alpha version. It has not been tested in many real life environments for now.

This tool as well as its code base was inspired by [sprayhound](https://github.com/Hackndo/sprayhound), [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec), [kerbrute](https://github.com/ropnop/kerbrute), [pykerbrute](https://github.com/3gstudent/pyKerbrute), [impacket](https://github.com/SecureAuthCorp/impacket), ...

## Core features

What can this tool do:

  - Fetch user list, bad password count for each account, global lockout policy (domain), granular lockout policies (password settings objects) and make sure to NOT lock any accounts. PSOs can be applied to groups, the tool lists all members from those groups (direct members or not) and creates a list users to test : lockout policy for that account.  
  - NTLM over SMB shows if user is local admin to the target or not
  - A valid authentication will be used to query domain information using LDAP to find out if owned accounts are part of sensitive groups
  - It can interact with neo4j
  - Bruteforce can be operated on :
    + NTLM over SMB
    + NTLM over LDAP
    + Kerberos (pre-authentication) over TCP
    + Kerberos (pre-authentication) over UDP
  - When attacking Kerberos, etype can be set to :
    + RC
    + AES128
    + AES256  
  - LDAP information can be recovered using LDAP
  - Bruteforce can be stopped when a valid account is found (with `--stop-on-success` option)
  - Bruteforce can be operated line per line when supplying lists for both usernames and passwords/hashes
  - Bruteforce can be operated with a user/password/hash or list of those
  - In smart mode, bruteforce can be skipped to only show fetched users and password policies

## Usage

![](./assets/graph_help.png)

```
$ smartbrute -h
usage: smartbrute.py [-h] [-v] [-q] [--set-as-owned] [-nh NEO4J_HOST] [-nP NEO4J_PORT] [-nu NEO4J_USER] [-np NEO4J_PASSWORD] {brute,smart} ...

The smart password spraying and bruteforcing tool for Active Directory Domain Services.

positional arguments:
  {brute,smart}         this is a required argument and tells smartbrute in which mode to run. smart mode will enumerate users and policies and avoid locking out accounts given valid domain credentials. brute
                        mode is dumb and only bruteforces.
    brute               bruteforce mode
    smart               smart mode

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity level (-v for verbose, -vv for debug)
  -q, --quiet           show no information at all

neo4j option:
  --set-as-owned        Set valid users as owned in neo4j
  -nh NEO4J_HOST, --neo4j-host NEO4J_HOST
                        neo4j database address (default: 127.0.0.1)
  -nP NEO4J_PORT, --neo4j-port NEO4J_PORT
                        neo4j database port (default:7687)
  -nu NEO4J_USER, --neo4j-user NEO4J_USER
                        neo4j username (default: neo4j)
  -np NEO4J_PASSWORD, --neo4j-password NEO4J_PASSWORD
                        neo4j password (default: neo4j)
```
## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## References
- https://www.thehacker.recipes/active-directory-domain-services/movement/credentials/bruteforcing/password-spraying
- https://www.thehacker.recipes/active-directory-domain-services/movement/kerberos/pre-auth-bruteforce
