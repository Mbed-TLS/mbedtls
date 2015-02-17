@@
expression x, y;
statement S;
@@
  x = polarssl_malloc(...);
  y = polarssl_malloc(...);
  ...
* if (x == NULL || y == NULL)
    S
