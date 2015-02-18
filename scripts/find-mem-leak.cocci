@@
expression x, y;
statement S;
@@
  x = polarssl_malloc(...);
  y = polarssl_malloc(...);
  ...
* if (x == NULL || y == NULL)
    S

@@
expression x, y;
statement S;
@@
  if (
*   (x = polarssl_malloc(...)) == NULL
    ||
*   (y = polarssl_malloc(...)) == NULL
  )
    S
