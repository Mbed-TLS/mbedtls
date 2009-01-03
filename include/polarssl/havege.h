/**
 * \file havege.h
 */
#ifndef XYSSL_HAVEGE_H
#define XYSSL_HAVEGE_H

#define COLLECT_SIZE 1024

/**
 * \brief          HAVEGE state structure
 */
typedef struct
{
    int PT1, PT2, offset[2];
    int pool[COLLECT_SIZE];
    int WALK[8192];
}
havege_state;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          HAVEGE initialization
 *
 * \param hs       HAVEGE state to be initialized
 */
void havege_init( havege_state *hs );

/**
 * \brief          HAVEGE rand function
 *
 * \param rng_st   points to an HAVEGE state
 *
 * \return         A random int
 */
int havege_rand( void *p_rng );

#ifdef __cplusplus
}
#endif

#endif /* havege.h */
