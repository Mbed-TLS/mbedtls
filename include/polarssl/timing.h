/**
 * \file timing.h
 */
#ifndef XYSSL_TIMING_H
#define XYSSL_TIMING_H

/**
 * \brief          timer structure
 */
struct hr_time
{
    unsigned char opaque[32];
};

#ifdef __cplusplus
extern "C" {
#endif

extern int alarmed;

/**
 * \brief          Return the CPU cycle counter value
 */
unsigned long hardclock( void );

/**
 * \brief          Return the elapsed time in milliseconds
 *
 * \param val      points to a timer structure
 * \param reset    if set to 1, the timer is restarted
 */
unsigned long get_timer( struct hr_time *val, int reset );

/**
 * \brief          Setup an alarm clock
 *
 * \param seconds  delay before the "alarmed" flag is set
 */
void set_alarm( int seconds );

/**
 * \brief          Sleep for a certain amount of time
 */
void m_sleep( int milliseconds );

#ifdef __cplusplus
}
#endif

#endif /* timing.h */
