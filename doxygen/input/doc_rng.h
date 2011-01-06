/**
 * @file
 * Random number generator (RNG) module documentation file.
 */

/**
 * @addtogroup rng_module Random number generator (RNG) module
 * 
 * The Random number generator (RNG) module provides random number
 * generation, see \c havege_rand(). It uses the HAVEGE (HArdware Volatile 
 * Entropy Gathering and Expansion) software heuristic which is claimed 
 * to be an unpredictable or empirically strong* random number generation.
 *
 * \* Meaning that there seems to be no practical algorithm that can guess
 * the next bit with a probability larger than 1/2 in an output sequence.
 *
 * This module can be used to generate random numbers.
 */
