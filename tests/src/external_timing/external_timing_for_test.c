/** \file external_timing_for_test.c
 *
 * \brief Helper functions to test an alternate timing implementation.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <timing_alt.h>
#if defined(MBEDTLS_TIMING_ALT)

#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__QNXNTO__) && \
    !defined(__HAIKU__) && !defined(__midipix__)
#error "This module only works on Unix and Windows, see MBEDTLS_TIMING_C in config.h"
#endif

/* *INDENT-OFF* */
#ifndef asm
#define asm __asm
#endif
/* *INDENT-ON* */

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#include <windows.h>
#include <process.h>

struct _hr_time {
    LARGE_INTEGER start;
};

#else

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
/* time.h should be included independently of MBEDTLS_HAVE_TIME. If the
 * platform matches the ifdefs above, it will be used. */
#include <time.h>
#include <sys/time.h>
struct _hr_time {
    struct timeval start;
};
#endif /* _WIN32 && !EFIX64 && !EFI32 */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    (defined(_MSC_VER) && defined(_M_IX86)) || defined(__WATCOMC__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tsc;
    __asm   rdtsc
    __asm   mov[tsc], eax
    return tsc;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          ( _MSC_VER && _M_IX86 ) || __WATCOMC__ */

/* some versions of mingw-64 have 32-bit longs even on x84_64 */
#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__i386__) || (                       \
    (defined(__amd64__) || defined(__x86_64__)) && __SIZEOF_LONG__ == 4))

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return lo;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __i386__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__amd64__) || defined(__x86_64__))

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return lo | (hi << 32);
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __amd64__ || __x86_64__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__powerpc__) || defined(__ppc__))

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tbl, tbu0, tbu1;

    do {
        asm volatile ("mftbu %0" : "=r" (tbu0));
        asm volatile ("mftb  %0" : "=r" (tbl));
        asm volatile ("mftbu %0" : "=r" (tbu1));
    } while (tbu0 != tbu1);

    return tbl;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __powerpc__ || __ppc__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc64__)

#if defined(__OpenBSD__)
#warning OpenBSD does not allow access to tick register using software version instead
#else
#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tick;
    asm volatile ("rdpr %%tick, %0;" : "=&r" (tick));
    return tick;
}
#endif /* __OpenBSD__ */
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc__) && !defined(__sparc64__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tick;
    asm volatile (".byte 0x83, 0x41, 0x00, 0x00");
    asm volatile ("mov   %%g1, %0" : "=r" (tick));
    return tick;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc__ && !__sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__alpha__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long cc;
    asm volatile ("rpcc %0" : "=r" (cc));
    return cc & 0xFFFFFFFF;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __alpha__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__ia64__)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long itc;
    asm volatile ("mov %0 = ar.itc" : "=r" (itc));
    return itc;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __ia64__ */

#if !defined(HAVE_HARDCLOCK) && defined(_MSC_VER) && \
    !defined(EFIX64) && !defined(EFI32)

#define HAVE_HARDCLOCK

unsigned long mbedtls_timing_hardclock(void)
{
    LARGE_INTEGER offset;

    QueryPerformanceCounter(&offset);

    return (unsigned long) (offset.QuadPart);
}
#endif /* !HAVE_HARDCLOCK && _MSC_VER && !EFIX64 && !EFI32 */

#if !defined(HAVE_HARDCLOCK)

#define HAVE_HARDCLOCK

static int hardclock_init = 0;
static struct timeval tv_init;

unsigned long mbedtls_timing_hardclock(void)
{
    struct timeval tv_cur;

    if (hardclock_init == 0) {
        gettimeofday(&tv_init, NULL);
        hardclock_init = 1;
    }

    gettimeofday(&tv_cur, NULL);
    return (tv_cur.tv_sec  - tv_init.tv_sec) * 1000000U
           + (tv_cur.tv_usec - tv_init.tv_usec);
}
#endif /* !HAVE_HARDCLOCK */

volatile int mbedtls_timing_alarmed = 0;

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset)
{
    struct _hr_time *t = (struct _hr_time *) val;

    if (reset) {
        QueryPerformanceCounter(&t->start);
        return 0;
    } else {
        unsigned long delta;
        LARGE_INTEGER now, hfreq;
        QueryPerformanceCounter(&now);
        QueryPerformanceFrequency(&hfreq);
        delta = (unsigned long) ((now.QuadPart - t->start.QuadPart) * 1000ul
                                 / hfreq.QuadPart);
        return delta;
    }
}

/* It's OK to use a global because alarm() is supposed to be global anyway */
static DWORD alarmMs;

static void TimerProc(void *TimerContext)
{
    (void) TimerContext;
    Sleep(alarmMs);
    mbedtls_timing_alarmed = 1;
    /* _endthread will be called implicitly on return
     * That ensures execution of thread function's epilogue */
}

void mbedtls_set_alarm(int seconds)
{
    if (seconds == 0) {
        /* No need to create a thread for this simple case.
         * Also, this shorcut is more reliable at least on MinGW32 */
        mbedtls_timing_alarmed = 1;
        return;
    }

    mbedtls_timing_alarmed = 0;
    alarmMs = seconds * 1000;
    (void) _beginthread(TimerProc, 0, NULL);
}

#else /* _WIN32 && !EFIX64 && !EFI32 */

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset)
{
    struct _hr_time *t = (struct _hr_time *) val;

    if (reset) {
        gettimeofday(&t->start, NULL);
        return 0;
    } else {
        unsigned long delta;
        struct timeval now;
        gettimeofday(&now, NULL);
        delta = (now.tv_sec  - t->start.tv_sec) * 1000ul
                + (now.tv_usec - t->start.tv_usec) / 1000;
        return delta;
    }
}

static void sighandler(int signum)
{
    mbedtls_timing_alarmed = 1;
    signal(signum, sighandler);
}

void mbedtls_set_alarm(int seconds)
{
    mbedtls_timing_alarmed = 0;
    signal(SIGALRM, sighandler);
    alarm(seconds);
    if (seconds == 0) {
        /* alarm(0) cancelled any previous pending alarm, but the
           handler won't fire, so raise the flag straight away. */
        mbedtls_timing_alarmed = 1;
    }
}

#endif /* _WIN32 && !EFIX64 && !EFI32 */

/*
 * Set delays to watch
 */
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if (fin_ms != 0) {
        (void) mbedtls_timing_get_timer(&ctx->timer, 1);
    }
}

/*
 * Get number of delays expired
 */
int mbedtls_timing_get_delay(void *data)
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if (ctx->fin_ms == 0) {
        return -1;
    }

    elapsed_ms = mbedtls_timing_get_timer(&ctx->timer, 0);

    if (elapsed_ms >= ctx->fin_ms) {
        return 2;
    }

    if (elapsed_ms >= ctx->int_ms) {
        return 1;
    }

    return 0;
}

#endif /* MBEDTLS_TIMING_ALT */
