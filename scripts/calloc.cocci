@malloc_mul@
expression m, n;
@@
- polarssl_malloc(m * n)
+ polarssl_calloc(m, n)

@malloc_sizeof@
type T;
@@
- polarssl_malloc(sizeof(T))
+ polarssl_calloc(1, sizeof(T))

@definition@
@@
  #define polarssl_calloc calloc

@define depends on !definition && (malloc_mul || malloc_sizeof)@
@@
  #define polarssl_malloc malloc
+ #define polarssl_calloc calloc
