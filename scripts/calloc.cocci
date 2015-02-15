@malloc_mul@
expression m, n;
@@
- polarssl_malloc(m * n)
+ polarssl_calloc(m, n)

@define depends on malloc_mul@
@@
  #define polarssl_malloc malloc
+ #define polarssl_calloc calloc
