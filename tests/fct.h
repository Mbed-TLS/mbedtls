/*
====================================================================
Copyright (c) 2008 Ian Blumel.  All rights reserved.

FCT (Fast C Test) Unit Testing Framework

Copyright (c) 2008, Ian Blumel (ian.blumel@gmail.com)
All rights reserved.

This license is based on the BSD License.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    
    * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

    * Neither the name of, Ian Blumel, nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
====================================================================

File: fct.h
*/

#if !defined(FCT_INCLUDED__IMB)
#define FCT_INCLUDED__IMB

#define FCT_VERSION_STR   "1.0.2"
#define FCT_VERSION_MAJOR 1
#define FCT_VERSION_MINOR 0
#define FCT_VERSION_MICRO 2

/* Define this to remove unneeded WIN32 warnings. We will undefine this at
the end of the file so as not to interfere with your build. */
#if defined(WIN32) && !defined(_CRT_SECURE_NO_WARNINGS)
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <float.h>
#include <math.h>

#define FCT_MAX_NAME           256
#define FCT_MAX_LOG_LINE       256

#define nbool_t int
#define FCT_TRUE   1
#define FCT_FALSE  0

/* Forward declarations. The following forward declarations are required
because there is a inter-relationship between certain objects that 
just can not be untwined. */
typedef struct _fct_logger_i fct_logger_i;
typedef struct _fct_standard_logger_t fct_standard_logger_t;
typedef struct _fct_minimal_logger_t fct_minimal_logger_t;
typedef struct _fctchk_t fctchk_t;
typedef struct _fct_test_t fct_test_t;
typedef struct _fct_ts_t fct_ts_t;
typedef struct _fctkern_t fctkern_t;

/* Forward declare some functions used throughout. */
static fct_standard_logger_t *
fct_standard_logger__new(void);

static void
fct_logger__del(fct_logger_i *logger);

static void
fct_logger__on_cndtn(fct_logger_i *self, fctchk_t const *chk);

static void
fct_logger__on_test_start(fct_logger_i *logger, fct_test_t const *test);

static void
fct_logger__on_test_end(fct_logger_i *logger, fct_test_t const *test);

static void
fct_logger__on_test_suite_start(fct_logger_i *logger, fct_ts_t const *ts);

static void
fct_logger__on_test_suite_end(fct_logger_i *logger, fct_ts_t const *ts);

static void
fct_logger__on_fct_start(fct_logger_i *logger, fctkern_t const *kern);

static void
fct_logger__on_fct_end(fct_logger_i *logger, fctkern_t const *kern);



/* Explicitly indicate a no-op */
#define fct_pass()    

#define fct_unused(x)   ((void) (x));

/* This is just a little trick to let me put comments inside of macros. I
really only want to bother with this when we are "unwinding" the macros
for debugging purposes. */
#if defined(FCT_CONF_UNWIND)
#	define _fct_cmt(string)		{char*_=string;} 
#else
#	define _fct_cmt(string)
#endif

/* 
-------------------------------------------------------- 
UTILITIES
-------------------------------------------------------- 
*/

/* Utility for truncated, safe string copies. */
static void
fct_safe_str_cpy(char *dst, char const *src, size_t num)
{
   assert( dst != NULL );
   assert( src != NULL );
   assert( num > 0 );
   strncpy(dst, src, num);
   dst[num-1] = '\0';
}

/* Isolate the snprintf implemenation. */
int 
fct_snprintf(char *buffer, size_t buffer_len, char *format, ...)
{
   int count =0;
   va_list args;
   va_start(args, format);
   count =vsnprintf(buffer, buffer_len, format, args);
   va_end(args);
   return count;
}

/* A very, very simple "filter". This just compares the supplied prefix 
against the test_str, to see if they both have the same starting 
characters. If they do we return true, otherwise we return false. If the
prefix is a blank string or NULL, then it will return FCT_TRUE.*/
static nbool_t
fct_filter_pass(char const *prefix, char const *test_str)
{
   nbool_t is_match = FCT_FALSE;
   char const *prefix_p;
   char const *test_str_p;

   /* If you got nothing to test against, why test? */
   assert( test_str != NULL );

   /* When the prefix is NULL or blank, we always return FCT_TRUE. */
   if ( prefix == NULL  || prefix[0] == '\0' ) 
   { 
      return FCT_TRUE;
   }
     
   /* Iterate through both character arrays at the same time. We are
   going to play a game and see if we can beat the house. */
   for ( prefix_p = prefix, test_str_p = test_str; 
         *prefix_p != '\0' && *test_str_p != '\0'; 
         ++prefix_p, ++test_str_p )
   {
      is_match = *prefix_p == *test_str_p;
      if ( !is_match ) 
      {
         break;   /* Quit the first time we don't match. */
      }
   }
   
   /* If the iterator for the test_str is pointing at the null char, and
   the iterator for the prefix string is not, then the prefix string is 
   larger than the actual test string, and therefore we failed to pass the
   filter. */
   if ( *test_str_p == '\0' && *prefix_p != '\0' )
   {
      return FCT_FALSE;
   }

   /* is_match will be set to the either FCT_TRUE if we kicked of the loop
   early because our filter ran out of characters or FCT_FALSE if we 
   encountered a mismatch before our filter ran out of characters. */
   return is_match;
}

/* Returns true if two reals are equal. */
nbool_t 
fct_real_eq(double v1, double v2)
{
   return (nbool_t)(fabs(v1 - v2) < DBL_EPSILON);
}

/* 
-------------------------------------------------------- 
TIMER
-------------------------------------------------------- 
*/

typedef struct _fct_timer_t fct_timer_t;
struct _fct_timer_t {
    clock_t start;
    clock_t stop;
    double duration;
};


static void
fct_timer__init(fct_timer_t *timer) {
    assert(timer != NULL);
    memset(timer, 0, sizeof(fct_timer_t));
}


static void
fct_timer__start(fct_timer_t *timer) {
    assert(timer != NULL);
    timer->start = clock();
}


static void
fct_timer__stop(fct_timer_t *timer) {
    assert(timer != NULL);
    timer->stop = clock();
    timer->duration = (double) (timer->stop - timer->start) / CLOCKS_PER_SEC;
}


/* Returns the time in seconds. */
static double
fct_timer__duration(fct_timer_t *timer) {
    assert( timer != NULL );
    return timer->duration;   
}


/* 
-------------------------------------------------------- 
GENERIC LIST
-------------------------------------------------------- 
*/

/* For now we will just keep it at a linear growth rate. */
#define FCT_LIST_GROWTH_FACTOR   2

/* Starting size for the list, to keep it simple we will start
at a reasonable size. */
#define FCT_LIST_START_SIZE      2

/* Helper macros for quickly iterating through a list. You should be able
to do something like,

  NLIST_FOREACH_BGN(fct_logger_i*, logger, my_list)
  {
     fct_logger__on_blah(logger);
  }
  NLIST_FOREACH_END();

*/
#define NLIST_FOREACH_BGN(Type, Var, List)\
{\
   if ( List != NULL ) {\
      size_t item_i##Var;\
      size_t num_items##Var = nlist__size(List);\
      for( item_i##Var =0; item_i##Var != num_items##Var; ++item_i##Var )\
      {\
         Type Var = (Type) nlist__at((List), item_i##Var);

#define NLIST_FOREACH_END() }}}

/* Used to manage a list of loggers. This works mostly like
the STL vector, where the array grows as more items are 
appended. */
typedef struct _nlist_t nlist_t;
struct _nlist_t
{ 
   /* Item's are stored as pointers to void. */
   void **itm_list;
   
   /* Indicates the number of element's in the array. */
   size_t avail_itm_num;

   /* Indicates the number of actually elements in the array. */
   size_t used_itm_num;
};

static nlist_t *
nlist_new(void)
{
   nlist_t *list = (nlist_t*)calloc(1, sizeof(nlist_t));
   assert( list != NULL && "memory check");

   list->itm_list = (void**)malloc(sizeof(void*)*FCT_LIST_START_SIZE);
   assert( list->itm_list != NULL && "memory check");

   list->avail_itm_num =FCT_LIST_START_SIZE;
   list->used_itm_num =0;
   return list;
}

typedef void (*on_del_t)(void*);

/* Cleans up list, and applies `on_del` to each item in the list. 
If on_del is NULL, it will not be applied. If `list` is NULL this
function does nothing. */
static void
nlist__del(nlist_t *list, on_del_t on_del)
{
   size_t itm_i =0;

   if ( list == NULL ) { return; }

   /* Walk through the list applying the destroy function, if it was 
   defined. */
   if ( on_del != NULL )
   {
      for ( itm_i =0; itm_i != list->used_itm_num; ++itm_i )
      {
         on_del(list->itm_list[itm_i]);
      }
   }

   free(list->itm_list);
   free(list);
}


/* Returns the number of elements within the list. */
static size_t
nlist__size(nlist_t const *list)
{
   assert( list != NULL );
   return list->used_itm_num;
}


/* Returns the item at idx, asserts otherwise. */
static void*
nlist__at(nlist_t const *list, size_t idx)
{
   assert( list != NULL );
   assert( idx < list->used_itm_num );
   return list->itm_list[idx];
}


static void
nlist__append(nlist_t *list, void *itm)
{
   assert( list != NULL );
   assert( list->itm_list != NULL );
   assert( list->avail_itm_num != 0 );

   /* If we ran out of room, then the last increment should be equal to the
   available space, in this case we need to grow a little more. */
   if ( list->used_itm_num == list->avail_itm_num )
   {
      list->avail_itm_num = list->avail_itm_num*FCT_LIST_GROWTH_FACTOR;
      list->itm_list = (void**)realloc(
         list->itm_list, sizeof(void*)*list->avail_itm_num
         );
      assert( list->itm_list != NULL && "memory check");
   }

   list->itm_list[list->used_itm_num] = itm;
   ++(list->used_itm_num);
}



/*
-----------------------------------------------------------
A SINGLE CHECK
-----------------------------------------------------------
This defines a single check. It indicates what the check was,
and where it occurred. A "Test" object will have-a bunch
of "checks".
*/

struct _fctchk_t {
   /* This string that represents the condition. */
   char cndtn[FCT_MAX_LOG_LINE];

   /* These indicate where the condition occurred. */
   char file[FCT_MAX_LOG_LINE];

   int lineno;

   nbool_t is_pass;
};

#define fctchk__is_pass(_CHK_) ((_CHK_)->is_pass)
#define fctchk__file(_CHK_)    ((_CHK_)->file)
#define fctchk__lineno(_CHK_)  ((_CHK_)->lineno)
#define fctchk__cndtn(_CHK_)   ((_CHK_)->cndtn)


static fctchk_t*
fctchk_new(char const *cndtn, char const *file, int lineno, nbool_t is_pass)
{
   fctchk_t *chk = NULL;

   assert( cndtn != NULL );
   assert( file != NULL );
   assert( lineno > 0 );
   
   chk = (fctchk_t*)calloc(1, sizeof(fctchk_t));
   assert( chk != NULL && "out of memory");
   if ( chk == NULL ) { return NULL; }

   fct_safe_str_cpy(chk->cndtn, cndtn, FCT_MAX_LOG_LINE);
   fct_safe_str_cpy(chk->file, file, FCT_MAX_LOG_LINE);
   chk->lineno = lineno;

   chk->is_pass =is_pass;

   return chk;
}


/* Cleans up a "check" object. If the `chk` is NULL, this function does 
nothing. */
static void
fctchk__del(fctchk_t *chk)
{
   if ( chk == NULL ) { return; }
   free( chk );
}


/*
-----------------------------------------------------------
A TEST
-----------------------------------------------------------
A suite will have-a list of tests. Where each test will have-a
list of failed and passed checks.
*/

struct _fct_test_t {
   /* List of failed and passed "checks" (fctchk_t). Two seperate
   lists make it faster to determine how many checks passed and how
   many checks failed. */
   nlist_t *failed_chks;
   nlist_t *passed_chks;

   /* The name of the test case. */
   char name[FCT_MAX_NAME];
};

#define fct_test__name(_TEST_) ((_TEST_)->name)

static fct_test_t*
fct_test_new(char const *name) {
   fct_test_t *test =NULL;

   test = (fct_test_t*)malloc(sizeof(fct_test_t));
   assert( test != NULL && "out of memory");
   
   fct_safe_str_cpy(test->name, name, FCT_MAX_NAME);
     
   test->failed_chks = nlist_new();
   test->passed_chks = nlist_new();
   assert( test->failed_chks != NULL && "out of memory");
   assert( test->passed_chks != NULL && "out of memory");

   return test;
}


static nbool_t
fct_test__is_pass(fct_test_t const *test)
{
   assert( test != NULL );
   return nlist__size(test->failed_chks) == 0;   
}


static void
fct_test__add(fct_test_t *test, fctchk_t *chk)
{

   assert( test != NULL );
   assert( chk != NULL );

   if ( fctchk__is_pass(chk) )
   {
      nlist__append(test->passed_chks, (void*)chk);
   }
   else
   {
      nlist__append(test->failed_chks, (void*)chk);
   }
}

/* Returns the number of checks made throughout the test. */
static int
fct_test__chk_cnt(fct_test_t const *test)
{
   assert( test != NULL );
   return nlist__size(test->failed_chks) + nlist__size(test->passed_chks);
}


static void
fct_test__del(fct_test_t *test)
{
   if (test == NULL ) { return; }
   nlist__del(test->passed_chks, (on_del_t)fctchk__del);
   nlist__del(test->failed_chks, (on_del_t)fctchk__del);
   free(test);
}


/* 
-----------------------------------------------------------
TEST SUITE (TS)
-----------------------------------------------------------
*/


/* The different types of 'modes' that a test suite can be in.

While the test suite is iterating through all the tests, its "State"
can change from "setup mode", to "test mode" to "tear down" mode. 
These help to indicate what mode are currently in. Think of it as a 
basic FSM.

            if the count was 0                               end
           +--------->---------------------> ending_mode-----+
           |                                       ^
           ^                                       |
start      |                              [if no more tests]
  |        |                                       |      
  +-count_mode -> setup_mode -> test_mode -> teardown_mode
                      ^                           |                         
                      +-----------<---------------+ 
*/    
enum ts_mode {
   ts_mode_cnt,         /* To setup when done counting. */
   ts_mode_setup,       /* To test when done setup. */
   ts_mode_teardown,    /* To ending mode, when no more tests. */
   ts_mode_test,        /* To tear down mode. */
   ts_mode_ending,      /* To ... */
   ts_mode_end          /* .. The End. */
};

/* Types of modes the test could be in. */
typedef enum {
   fct_test_status_SUCCESS,
   fct_test_status_FAILURE
} fct_test_status;


struct _fct_ts_t {
   /* For counting our 'current' test number, and the total number of 
   tests. */
   int  curr_test_num;
   int  total_test_num;

   /* Keeps track of the current state of the object while it is walking
   through its "FSM" */
   enum ts_mode mode;

   /* The name of the test suite. */
   char name[FCT_MAX_NAME];

   /* List of tests that where executed within the test suite. */
   nlist_t *test_list;
};


#define fct_ts__is_setup_mode(ts)     ((ts)->mode == ts_mode_setup)
#define fct_ts__is_teardown_mode(ts)  ((ts)->mode == ts_mode_teardown)
#define fct_ts__is_test_mode(ts)      ((ts)->mode == ts_mode_test)
#define fct_ts__is_ending_mode(ts)    ((ts)->mode == ts_mode_ending)
#define fct_ts__is_end(ts)            ((ts)->mode == ts_mode_end)
#define fct_ts__is_cnt_mode(ts)       ((ts)->mode == ts_mode_cnt)
#define fct_ts__name(ts)              ((ts)->name)


static fct_ts_t *
fct_ts_new(char const *name) {
   fct_ts_t *ts =NULL;
   ts = (fct_ts_t*)calloc(1, sizeof(fct_ts_t));
   assert( ts != NULL );

   fct_safe_str_cpy(ts->name, name, FCT_MAX_NAME);
   ts->mode = ts_mode_cnt;

   ts->test_list = nlist_new();
   assert( ts->test_list != NULL && "no memory");

   return ts;
}

static void
fct_ts__del(fct_ts_t *ts) {
   if ( ts == NULL ) { return; }
   free(ts);
}

/* Flag a test suite as complete. It will no longer accept any more tests. */
#define fct_ts__end(_TS_)  ((_TS_)->mode == ts_mode_end)


static nbool_t
fct_ts__is_more_tests(fct_ts_t const *ts) {
   assert( ts != NULL );
   assert( !fct_ts__is_end(ts) );
   return ts->curr_test_num < ts->total_test_num;
}


/* Indicates that we have started a test case. */
static void
fct_ts__test_begin(fct_ts_t *ts) {
   assert( !fct_ts__is_end(ts) );
   ++(ts->curr_test_num);
}


/* Takes OWNERSHIP of a test object, and warehouses it for later stat
generation. */
static void
fct_ts__add_test(fct_ts_t *ts, fct_test_t *test) {
   assert( ts != NULL && "invalid arg");
   assert( test != NULL && "invalid arg");
   assert( !fct_ts__is_end(ts) );
   nlist__append(ts->test_list, test);
}


static void
fct_ts__test_end(fct_ts_t *ts) {
   assert( ts != NULL );
   assert( fct_ts__is_test_mode(ts) && "not in test mode, can't end!" );

   /* After a test has completed, move to teardown mode. */
   ts->mode = ts_mode_teardown;
}


/* Increments the internal count by 1. */
static void
fct_ts__inc_total_test_num(fct_ts_t *ts)
{
   assert( ts != NULL );
   assert( fct_ts__is_cnt_mode(ts) );
   assert( !fct_ts__is_end(ts) );
   ++(ts->total_test_num);
}


/* Flags the end of the setup, which implies we are going to move into
setup mode. You must be already in setup mode for this to work! */
static void
fct_ts__setup_end(fct_ts_t *ts)
{
   assert( fct_ts__is_setup_mode(ts) );
   assert( !fct_ts__is_end(ts) );
   ts->mode = ts_mode_test;
}


/* This cndtn is set when we have iterated through all the tests, and
there was nothing more to do. */
static void
fct_ts__ending(fct_ts_t *ts)
{
   // We can only go from 'test-mode' to 'end-down' mode.
   assert( fct_ts__is_test_mode(ts) );
   assert( !fct_ts__is_end(ts) );
   ts->mode = ts_mode_ending;
}


/* Flags the end of the teardown, which implies we are going to move
into setup mode (for the next 'iteration'). */
static void
fct_ts__teardown_end(fct_ts_t *ts)
{
    assert( fct_ts__is_teardown_mode(ts) );
    assert( !fct_ts__is_end(ts) );
    /* We have to decide if we should keep on testing by moving into tear down 
    mode or if we have reached the real end and should be moving into the 
    ending mode. */
    if ( fct_ts__is_more_tests(ts) ) {
        ts->mode = ts_mode_setup;
    }
    else {
        ts->mode = ts_mode_ending;
    }
}


/* Flags the end of the counting, and proceeding to the first setup. 
Consider the special case when a test suite has NO tests in it, in
that case we will have a current count that is zero, in which case
we can skip right to 'ending'. */
static void
fct_ts__cnt_end(fct_ts_t *ts)
{
   assert( ts != NULL );
   assert( fct_ts__is_cnt_mode(ts) );
   assert( !fct_ts__is_end(ts) );
   if (ts->total_test_num == 0  ) {
      ts->mode = ts_mode_ending;
   }
   else {
      ts->mode = ts_mode_setup;
   }
}


static nbool_t
fct_ts__is_test_cnt(fct_ts_t const *ts, int test_num)
{
   assert( ts != NULL );
   assert( 0 <= test_num );
   assert( test_num < ts->total_test_num );
   assert( !fct_ts__is_end(ts) );

   /* As we roll through the tests we increment the count. With this
   count we can decide if we need to execute a test or not. */
   return test_num == ts->curr_test_num;
}


/* Returns the # of tests on the FCT TS object. This is the actual
# of tests executed. */
static int
fct_ts__tst_cnt(fct_ts_t const *ts)
{
   assert( ts != NULL );
   assert( !fct_ts__is_end(ts) );
   return nlist__size(ts->test_list);
}


/* Returns the # of tests in the TS object that passed. */
static int
fct_ts__tst_cnt_passed(fct_ts_t const *ts)
{
   int tally =0;

   assert( ts != NULL );
   assert( !fct_ts__is_end(ts) );

   NLIST_FOREACH_BGN(fct_test_t*, test, ts->test_list)
   {
      if ( fct_test__is_pass(test) )
      {
         tally += 1;
      }
   }
   NLIST_FOREACH_END();
   return tally;
}


/* Returns the # of checks made throughout a test suite. */
static int
fct_ts__chk_cnt(fct_ts_t const *ts)
{
   int tally =0;

   assert( ts != NULL );
   
   NLIST_FOREACH_BGN(fct_test_t *, test, ts->test_list)
   {
      tally += fct_test__chk_cnt(test);
   }
   NLIST_FOREACH_END();
   return tally;
}


/* 
-------------------------------------------------------- 
FCT KERNAL
-------------------------------------------------------- 

The "fctkern" is a singleton that is defined throughout the 
system. 
*/

struct _fctkern_t {
   /* This is an list of loggers that can be used in the fct system. 
   You/ can attach _MAX_LOGGERS to any framework. */
   nlist_t *logger_list;

   /* This is a list of prefix's that can be used to determine if a 
   test is should be run or not. */
   nlist_t *prefix_list;

   /* This is a list of test suites that where generated throughout the
   testing process. */
   nlist_t *ts_list;
};


/* Returns the number of filters defined for the fct kernal. */
#define fctkern__filter_cnt(_NK_) (nlist__size((_NK_)->prefix_list))


static void
fctkern__add_logger(fctkern_t *fct, fct_logger_i *logger_owns)
{
   assert(fct != NULL && "invalid arg");
   assert(logger_owns != NULL && "invalid arg");
   nlist__append(fct->logger_list, logger_owns);
   assert( fct->logger_list != NULL && "memory check");
}

/* Appends a prefix filter that is used to determine if a test can
be executed or not. If the test starts with the same characters as
the prefix, then it should be "runnable". The prefix filter must be
a non-NULL, non-Blank string. */
static void
fctkern__add_prefix_filter(fctkern_t const *fct, char const *prefix_filter)
{
   char *filter =NULL;
   int filter_len =0;

   assert( fct != NULL && "invalid arg" );
   assert( prefix_filter != NULL && "invalid arg" );
   assert( strlen(prefix_filter) > 0 && "invalid arg" );

   /* First we make a copy of the prefix, then we store it away
   in our little list. */
   filter_len = strlen(prefix_filter);
   filter = (char*)malloc(sizeof(char)*(filter_len+1));
   strncpy(filter, prefix_filter, filter_len);
   filter[filter_len] = '\0';

   nlist__append(fct->prefix_list, (void*)filter);
}


/* Parses the command line and sets up the framework. The argc and argv 
should be directly from the program's  main. */
static void
fctkern_init(fctkern_t *nk, int argc, char *argv[])
{
   fct_logger_i *standard_logger = NULL;
   int arg_i =0;

   assert( nk != NULL );

   memset(nk, 0, sizeof(fctkern_t));

   nk->logger_list = nlist_new();
   nk->prefix_list = nlist_new();
   nk->ts_list = nlist_new();

   /* Low-budget memory check for now. */
   assert( nk->logger_list != NULL );
   assert( nk->prefix_list != NULL );
   assert( nk->ts_list != NULL );

   standard_logger = (fct_logger_i*) fct_standard_logger__new();
   assert( standard_logger != NULL && "no memory!");

   fctkern__add_logger(nk, standard_logger);   
   standard_logger = NULL;   /* Owned by the nk list. */

   /* Our basic parser. For now we just take each 'argv' and assume
   that it is a prefix filter. Notice we start at argument 1, since
   we don't care about the *name* of the program. */
   for ( arg_i =1; arg_i < argc; ++arg_i )
   {
      fctkern__add_prefix_filter(nk, argv[arg_i]);
   }
}


/* Takes OWNERSHIP of the test suite after we have finished executing
its contents. This way we can build up all kinds of summaries at the end
of a run. */
static void
fctkern__add_ts(fctkern_t *nk, fct_ts_t *ts) {
   assert( nk != NULL );
   assert( ts != NULL );
   nlist__append(nk->ts_list, ts);
}



/* Returns FCT_TRUE if the supplied test_name passes the filters set on
this test suite. If there are no filters, we return FCT_TRUE always. */
static nbool_t
fctkern__pass_filter(fctkern_t *nk, char const *test_name) {
   int prefix_i =0;
   int prefix_list_size =0;

   assert( nk != NULL && "invalid arg");
   assert( test_name != NULL );
   assert( strlen(test_name) > 0 );

   prefix_list_size = fctkern__filter_cnt(nk);
   
   /* If there is no filter list, then we return FCT_TRUE always. */
   if ( prefix_list_size == 0 ) {
      return FCT_TRUE;
   }   

   /* Iterate through the prefix filter list, and see if we have
   anything that does not pass. All we require is ONE item that
   passes the test in order for us to succeed here. */
   for ( prefix_i = 0; prefix_i != prefix_list_size; ++prefix_i ) {
      char const *prefix = (char const*)nlist__at(nk->prefix_list, prefix_i);
      nbool_t pass = fct_filter_pass(prefix, test_name);
      if ( pass ) {
         return FCT_TRUE;
      }
   }

   /* Otherwise, we never managed to find a prefix that satisfied the 
   supplied test name. Therefore we have failed to pass to the filter 
   list test. */
   return FCT_FALSE;
}


/* Returns the number of tests that were performed. */
static int
fctkern__tst_cnt(fctkern_t const *nk)
{
   int tally =0;
   assert( nk != NULL );

   NLIST_FOREACH_BGN(fct_ts_t *, ts, nk->ts_list)
   {
      tally += fct_ts__tst_cnt(ts);
   }
   NLIST_FOREACH_END();
   return tally;
}

/* Returns the number of tests that passed. */
static int
fctkern__tst_cnt_passed(fctkern_t const *nk)
{
   int tally =0;
   assert( nk != NULL );

   NLIST_FOREACH_BGN(fct_ts_t*, ts, nk->ts_list)
   {
      tally += fct_ts__tst_cnt_passed(ts);
   }
   NLIST_FOREACH_END();

   return tally;
}


/* Returns the number of tests that failed. */
static int
fctkern__tst_cnt_failed(fctkern_t const *nk)
{
   /* Keep it simple for now and just do a little math. */
   int total =0;
   int passed =0;
   int failed =0;

   assert( nk != NULL );

   total = fctkern__tst_cnt(nk);
   passed = fctkern__tst_cnt_passed(nk);

   failed = total - passed;

   return failed;
}


/* Returns the number of checks made throughout the entire test. */
static int
fctkern__chk_cnt(fctkern_t const *nk)
{
   int tally =0;
   assert( nk != NULL );

   NLIST_FOREACH_BGN(fct_ts_t *, ts, nk->ts_list)
   {
      tally += fct_ts__chk_cnt(ts);
   }
   NLIST_FOREACH_END();
   return tally;
}


/* Indicates the very end of all the tests. */
static void
fctkern__end(fctkern_t *fct)
{
   fct_unused(fct);
}


/* Cleans up the contents of a fctkern. NULL does nothing. */
static void
fctkern__final(fctkern_t *fct) 
{
   if ( fct == NULL ) { return; }

   nlist__del(fct->logger_list, (on_del_t)fct_logger__del);

   /* The prefix list is a list of malloc'd strings. */
   nlist__del(fct->prefix_list, (on_del_t)free);

   nlist__del(fct->ts_list, (on_del_t)fct_ts__del);
}


static void
fctkern__log_suite_start(fctkern_t *kern, fct_ts_t const *ts)
{
   assert( kern != NULL );
   assert( ts != NULL );
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_test_suite_start(logger, ts);
   }
   NLIST_FOREACH_END();
}


static void
fctkern__log_suite_end(fctkern_t *kern, fct_ts_t const *ts)
{
   assert( kern != NULL );
   assert( ts != NULL );
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_test_suite_end(logger, ts);
   }
   NLIST_FOREACH_END();
}


static void
fctkern__log_chk(fctkern_t *kern, fctchk_t const *chk)
{
   assert( kern != NULL );
   assert( chk != NULL );
  
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_cndtn(logger, chk);
   }
   NLIST_FOREACH_END();
}


/* Called whenever a test is started. */
static void
fctkern__log_test_start(fctkern_t *kern, fct_test_t const *test)
{
   assert( kern != NULL );
   assert( test != NULL );
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_test_start(logger, test);
   }
   NLIST_FOREACH_END();
}


static void
fctkern__log_test_end(fctkern_t *kern, fct_test_t const *test)
{
   assert( kern != NULL );
   assert( test != NULL );
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_test_end(logger, test);
   }
   NLIST_FOREACH_END();
}


static void
fctkern__log_start(fctkern_t *kern)
{
   assert( kern != NULL );
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_fct_start(logger, kern);
   }
   NLIST_FOREACH_END();
}


static void
fctkern__log_end(fctkern_t *kern)
{
   assert( kern != NULL );
   NLIST_FOREACH_BGN(fct_logger_i*, logger, kern->logger_list)
   {
      fct_logger__on_fct_end(logger, kern);
   }
   NLIST_FOREACH_END();
}


/*
-----------------------------------------------------------
LOGGER INTERFACE

Defines an interface to a logging system. A logger 
must define the following functions in order to hook 
into the logging system.

See the "Standard Logger" and "Minimal Logger" as examples
of the implementation.
-----------------------------------------------------------
*/

typedef void (*fct_logger_on_cndtn_fn)(fct_logger_i *self, 
                                       fctchk_t const *chk);
#define _fct_logger_head \
   fct_logger_on_cndtn_fn on_cndtn;\
   void (*on_test_start)(fct_logger_i *logger, fct_test_t const *test);\
   void (*on_test_end)(fct_logger_i *logger, fct_test_t const *test);\
   void (*on_test_suite_start)(fct_logger_i *logger, fct_ts_t const *ts);\
   void (*on_test_suite_end)(fct_logger_i *logger, fct_ts_t const *ts);\
   void (*on_fct_start)(fct_logger_i *logger, fctkern_t const *kern);\
   void (*on_fct_end)(fct_logger_i *logger, fctkern_t const *kern);\
   void (*on_delete)(fct_logger_i *logger)\

struct _fct_logger_i {
   _fct_logger_head;
};


/* Initializes the elements of a logger interface so they are at their 
standard values. */
static void
fct_logger__init(fct_logger_i *logger)
{
   assert( logger != NULL );
   logger->on_cndtn =NULL;
   logger->on_test_start =NULL;
   logger->on_test_end =NULL;
   logger->on_test_suite_start =NULL;
   logger->on_test_suite_end =NULL;
   logger->on_fct_start =NULL;
   logger->on_fct_end =NULL;
   logger->on_delete =NULL;
}


static void
fct_logger__del(fct_logger_i *logger)
{
   if ( logger == NULL ) { return; }
   if ( logger->on_delete) { logger->on_delete(logger); }
}


static void
fct_logger__on_test_start(fct_logger_i *logger, fct_test_t const *test)
{
   assert( logger != NULL && "invalid arg");
   assert( test != NULL && "invalid arg");

   if ( logger->on_test_start != NULL )
   {
      logger->on_test_start(logger, test);
   }
}


static void
fct_logger__on_test_end(fct_logger_i *logger, fct_test_t const *test)
{
   assert( logger != NULL && "invalid arg");
   assert( test != NULL && "invalid arg");

   if ( logger->on_test_end != NULL )
   {
      logger->on_test_end(logger, test);
   }
}


static void
fct_logger__on_test_suite_start(fct_logger_i *logger, fct_ts_t const *ts)
{
   assert( logger != NULL && "invalid arg");
   assert( ts != NULL && "invalid arg");

   if ( logger->on_test_suite_start != NULL )
   {
      logger->on_test_suite_start(logger, ts);
   }
}


static void
fct_logger__on_test_suite_end(fct_logger_i *logger, fct_ts_t const *ts)
{
   assert( logger != NULL && "invalid arg");
   assert( ts != NULL && "invalid arg");

   if ( logger->on_test_suite_end != NULL )
   {
      logger->on_test_suite_end(logger, ts);
   }
}


static void
fct_logger__on_cndtn(fct_logger_i *logger, fctchk_t const *chk)
{
   assert( logger != NULL && "invalid arg");
   assert( chk != NULL && "invalid arg");

   if ( logger->on_cndtn ) 
   {
      logger->on_cndtn(logger, chk);
   }
}                        


/* When we start all our tests. */
static void
fct_logger__on_fct_start(fct_logger_i *logger, fctkern_t const *kern)
{
   assert( logger != NULL );
   assert( kern != NULL );

   if ( logger->on_fct_start != NULL ) 
   {
      logger->on_fct_start(logger, kern);
   }
}


/* When we have reached the end of ALL of our testing. */
static void
fct_logger__on_fct_end(fct_logger_i *logger, fctkern_t const *kern)
{
   assert( logger != NULL );
   assert( kern != NULL );

   if ( logger->on_fct_end )
   {
      logger->on_fct_end(logger, kern);
   }
}



/*
-----------------------------------------------------------
MINIMAL LOGGER
-----------------------------------------------------------
*/

/* Minimal logger, reports the minimum amount of information needed
to determine "something is happening". */
struct _fct_minimal_logger_t {
   _fct_logger_head;
};


static void 
fct_minimal_logger__on_cndtn(fct_logger_i *self, fctchk_t const *chk)
{
   fct_unused(self);   
   printf(fctchk__is_pass(chk) ? "." : "!");
}


static void
fct_minimal_logger__del(fct_logger_i *self)
{
   free(self);
}


static fct_minimal_logger_t *
fct_minimal_logger__new(void)
{
   fct_minimal_logger_t *self = (fct_minimal_logger_t*)\
				calloc(1,sizeof(fct_minimal_logger_t));
   if ( self == NULL ) { return NULL; }

   fct_logger__init((fct_logger_i*)self);

   self->on_cndtn = fct_minimal_logger__on_cndtn;
   self->on_delete = fct_minimal_logger__del;
   return self;
}


/*
-----------------------------------------------------------
STANDARD LOGGER
-----------------------------------------------------------
*/

struct _fct_standard_logger_t {
   _fct_logger_head;

   /* Start time. For now we use the low-accuracy time_t version. */
   fct_timer_t timer;

   /* A list of char*'s that needs to be cleaned up. */
   nlist_t *failed_cndtns_list;
};


/* When a failure occurrs, we will record the details so we can display
them when the log "finishes" up. */
static void
fct_standard_logger__on_cndtn(fct_logger_i *logger_, fctchk_t const *chk)
{
   fct_standard_logger_t *logger = (fct_standard_logger_t*)logger_;
   
   assert( logger != NULL );
   assert( chk != NULL );

   /* Only record failures. */
   if ( !fctchk__is_pass(chk) )
   {
      /* For now we will truncate the string to some set amount, later
      we can work out a dynamic string object. */
      char *str = (char*)malloc(sizeof(char)*FCT_MAX_LOG_LINE);
      assert( str != NULL );
      
      fct_snprintf(
         str, 
         FCT_MAX_LOG_LINE, 
         "%s(%d): %s", 
         fctchk__file(chk),
         fctchk__lineno(chk),
         fctchk__cndtn(chk)
         );

      /* Append it to the listing ... */
      nlist__append(logger->failed_cndtns_list, (void*)str);
   }  
}


static void
fct_standard_logger__on_test_start(fct_logger_i *logger_, 
                                   fct_test_t const *test)
{
   fct_unused(logger_);
   printf("%s ... ", fct_test__name(test));
}


static void
fct_standard_logger__on_test_end(fct_logger_i *logger_, 
                                   fct_test_t const *test)
{
   nbool_t is_pass;
   fct_unused(logger_);

   is_pass = fct_test__is_pass(test);
   printf("%s\n", (is_pass) ? "PASS" : "FAIL" );
}


static void
fct_standard_logger__on_test_suite_start(fct_logger_i *logger_, 
                                         fct_ts_t const *ts)
{
   fct_unused(logger_);
   fct_unused(ts);
}


static void
fct_standard_logger__on_test_suite_end(fct_logger_i *logger_, 
                                         fct_ts_t const *ts)
{
   fct_unused(logger_);
   fct_unused(ts);
}


static void
fct_standard_logger__on_fct_start(fct_logger_i *logger_, 
                                  fctkern_t const *nk)
{
   fct_standard_logger_t *logger = (fct_standard_logger_t*)logger_;
   fct_unused(nk);
   fct_timer__start(&(logger->timer));
}


static void
fct_standard_logger__on_fct_end(fct_logger_i *logger_, fctkern_t const *nk)
{
   fct_standard_logger_t *logger = (fct_standard_logger_t*)logger_;
   nbool_t is_success =1;
   double elasped_time =0;
   int num_tests =0;
   int num_passed =0;

   fct_timer__stop(&(logger->timer));
     
   is_success = nlist__size(logger->failed_cndtns_list) ==0;

   if (  !is_success )
   {
      printf("\n--------------------------------------------------------\n");
      printf("FAILED TESTS\n\n");

      NLIST_FOREACH_BGN(char *, cndtn_str, logger->failed_cndtns_list)
      {
         printf("%s\n", cndtn_str);
      }
      NLIST_FOREACH_END();

      printf("\n");
   }

   printf("\n--------------------------------------------------------\n");

   num_tests = fctkern__tst_cnt(nk);
   num_passed = fctkern__tst_cnt_passed(nk);

   printf(
      "%s (%d/%d tests", 
      (is_success) ? "PASSED" : "FAILED",
      num_passed,
      num_tests
   );

   elasped_time = fct_timer__duration(&(logger->timer));
   if ( elasped_time > 0.0000001 )
   {
      printf(" in %.6fs)\n", elasped_time);
   }
   else
   {
      /* Don't bother displaying the time to execute. */
      printf(")\n");
   }
}


static void
fct_standard_logger__del(fct_logger_i *logger_)
{
   fct_standard_logger_t *logger = (fct_standard_logger_t*)logger_;

   NLIST_FOREACH_BGN(char *, cndtn_str, logger->failed_cndtns_list)
   {
      free(cndtn_str);
   }
   NLIST_FOREACH_END();

   free(logger);
   logger_ =NULL;
}


fct_standard_logger_t *
fct_standard_logger__new(void)
{
   fct_standard_logger_t *logger = (fct_standard_logger_t *)calloc(
		   1, sizeof(fct_standard_logger_t)
		   );
   if ( logger == NULL ) 
   { 
      return NULL; 
   }
   fct_logger__init((fct_logger_i*)logger);
   logger->on_cndtn = fct_standard_logger__on_cndtn;
   logger->on_test_start = fct_standard_logger__on_test_start;
   logger->on_test_end = fct_standard_logger__on_test_end;
   logger->on_test_suite_start = fct_standard_logger__on_test_suite_start;
   logger->on_test_suite_end = fct_standard_logger__on_test_suite_end;
   logger->on_fct_start = fct_standard_logger__on_fct_start;
   logger->on_fct_end = fct_standard_logger__on_fct_end;
   logger->on_delete = fct_standard_logger__del;

   logger->failed_cndtns_list = nlist_new();
   assert( logger->failed_cndtns_list != NULL );
   
   fct_timer__init(&(logger->timer));

   return logger;
}



/*
------------------------------------------------------------
MAGIC MACROS
------------------------------------------------------------
*/

#define FCT_BGN() \
int \
main(int argc, char *argv[])\
{\
   fctkern_t fctkern__;\
   fctkern_init(&fctkern__, argc, argv);\
   fctkern__log_start(&fctkern__);


#define FCT_END()\
   {\
      int num_failed__ =0;\
      num_failed__ = fctkern__tst_cnt_failed((&fctkern__));\
      fctkern__log_end(&fctkern__);\
      fctkern__end(&fctkern__);\
      fctkern__final(&fctkern__);\
      return num_failed__;\
   }\
}

#define FCT_FIXTURE_SUITE_BGN(_NAME_) \
   {\
      fct_ts_t *ts__ = fct_ts_new( #_NAME_ );\
      fctkern__log_suite_start((&fctkern__), ts__);\
      for (;;)\
      {\
         int fct_test_num__ = -1;\
         _fct_cmt("Strict compiler warnings will complain in 'blank' suites.")\
         _fct_cmt("so we are going to do a 'noop' to trick them.")\
         fct_test_num__ = fct_test_num__;\
         if ( fct_ts__is_ending_mode(ts__) )\
         {\
            _fct_cmt("flag the test suite as complete.");\
            fct_ts__end(ts__);\
            break;\
         }


/*  Closes off a "Fixture" test suite. */
#define FCT_FIXTURE_SUITE_END() \
         if ( fct_ts__is_cnt_mode(ts__) )\
         {\
            fct_ts__cnt_end(ts__);\
         }\
      }\
      fctkern__add_ts((&fctkern__), ts__);\
      fctkern__log_suite_end((&fctkern__), ts__);\
      ts__ = NULL;\
   }



#define FCT_SETUP_BGN()\
   if ( fct_ts__is_setup_mode(ts__) ) {

#define FCT_SETUP_END() \
   fct_ts__setup_end(ts__); }

#define FCT_TEARDOWN_BGN() \
   if ( fct_ts__is_teardown_mode(ts__) ) {\

#define FCT_TEARDOWN_END() \
   fct_ts__teardown_end(ts__); \
   continue; \
   }

/* Lets you create a test suite, where maybe you don't want a fixture. We
do it by 'stubbing' out the setup/teardown logic. */
#define FCT_SUITE_BGN(Name) \
   FCT_FIXTURE_SUITE_BGN(Name) {\
   FCT_SETUP_BGN() {_fct_cmt("stubbed"); } FCT_SETUP_END()\
   FCT_TEARDOWN_BGN() {_fct_cmt("stubbed");} FCT_TEARDOWN_END()\

#define FCT_SUITE_END() } FCT_FIXTURE_SUITE_END()

/* Depending on whether or not we are counting the tests, we will have to 
first determine if the test is the "current" count. Then we have to determine
if we can pass the filter. Finally we will execute everything so that when a 
check fails, we can "break" out to the end of the test. */
#define FCT_TEST_BGN(_NAME_) \
         {\
            char const *test_name__ = #_NAME_;\
            ++fct_test_num__;\
            if ( fct_ts__is_cnt_mode(ts__) )\
            {\
               fct_ts__inc_total_test_num(ts__);\
            }\
            else if ( fct_ts__is_test_mode(ts__) \
                      && fct_ts__is_test_cnt(ts__, fct_test_num__) )\
            {\
               int is_pass__;\
               is_pass__ = FCT_FALSE;\
               fct_ts__test_begin(ts__);\
               if ( fctkern__pass_filter(&fctkern__,  test_name__ ) )\
               {\
                  fct_test_t *test__ = fct_test_new( test_name__ );\
                  fctkern__log_test_start(&fctkern__, test__);\
                  for (;;) \
                  {

#define FCT_TEST_END() \
                     break;\
                  }\
               fct_ts__add_test(ts__, test__);\
               fctkern__log_test_end(&fctkern__, test__);\
               }\
               fct_ts__test_end(ts__);\
               continue;\
            }\
         }



/*
---------------------------------------------------------
CHECKING MACROS
---------------------------------------------------------- 

For now we only have the one "positive" check macro. In the future I plan
to add more macros that check for different types of common conditions.
*/

#define fct_chk(_CNDTN_) \
   {\
      fctchk_t *chk =NULL;\
      is_pass__ = (_CNDTN_);\
      chk = fctchk_new(#_CNDTN_, __FILE__, __LINE__, is_pass__);\
      fct_test__add(test__, chk);\
      fctkern__log_chk(&fctkern__, chk);\
      if ( !is_pass__ ) { break; }\
   }


/*
---------------------------------------------------------
GUT CHECK MACROS
---------------------------------------------------------- 

The following macros are used to help check the "guts" of
the FCT, and to confirm that it all works according to spec.
*/

/* Generates a message to STDERR and exits the application with a 
non-zero number. */
#define _FCT_GUTCHK(_CNDTN_) \
   if ( !(_CNDTN_) ) {\
      fprintf(stderr, "gutchk fail: '"  #_CNDTN_ "' was not true.\n");\
      exit(1);\
   }\
   else {\
      fprintf(stdout, "gutchk pass:  '" #_CNDTN_ "'\n");\
   }
      

/*
---------------------------------------------------------
CLOSING STATEMENTS
---------------------------------------------------------- 
*/

/* This is defined at the start of the file. We are undefining it
here so it doesn't conflict with existing. */
#if defined(WIN32)
#   undef _CRT_SECURE_NO_WARNINGS
#endif

#endif /* !FCT_INCLUDED__IMB */
