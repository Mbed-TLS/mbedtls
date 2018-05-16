
__attribute__((constructor(65534))) static void __e_acsl_mem_init(void)
{
    __e_acsl_memory_init((int *)0,(char ***)0,8UL);
}

 __attribute__((destructor(65534))) static void __e_acsl_mem_clean(void)
{
    __e_acsl_memory_clean();
}
