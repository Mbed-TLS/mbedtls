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

@malloc_constant@
constant C;
@@
- polarssl_malloc(C)
+ polarssl_calloc(1, C)

@malloc_var@
identifier x;
@@
- polarssl_malloc(x)
+ polarssl_calloc(1, x)

@definition@
@@
  #define polarssl_calloc calloc

@define depends on !definition &&
  (malloc_mul || malloc_sizeof || malloc_constant || malloc_var)@
@@
  #define polarssl_malloc malloc
+ #define polarssl_calloc calloc
