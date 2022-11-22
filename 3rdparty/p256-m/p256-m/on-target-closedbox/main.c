/* Show some progress, as the tests are much slower on target */
#define TEST_VERBOSE
/* Using #include rather than a symlink has two purposes:
 * 1. make further #include directive from the included file suceed;
 * 2. allow to tune compile options here rather than on the command line. */
#include "../test-closedbox.c"
