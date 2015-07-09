/**
 * \file ke_wrap.h
 *
 * \brief Key exchange wrappers.
 *
 */

#ifndef POLARSSL_KE_WRAP_H
#define POLARSSL_KE_WRAP_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "ke.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(POLARSSL_DHM_C)
extern const ke_info_t dhm_info2;
#endif

#if defined(POLARSSL_ECDH_C)
extern const ke_info_t ecdh_info2;
extern const ke_info_t ecdhe_info2;
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_KE_WRAP_H */

