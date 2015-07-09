/**
 * \file ke.h
 *
 * \brief Generic key exchange wrapper
 *
 */
#ifndef POLARSSL_KE_H
#define POLARSSL_KE_H

#include <stddef.h> /* for size_t */

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#define POLARSSL_ERR_KE_ERR             -0xa780  /**< Errors.  */
#define POLARSSL_ERR_KE_NOKEIF_INSTANCE -0xa781  /**< No keif instance  */
#define POLARSSL_ERR_KE_NOCTX_PROVIDED  -0xa782  /**< No ke context */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_KE_NONE=0,
    POLARSSL_KE_DHM,
    POLARSSL_KE_EC, /* Need to specify which curve to use */
    POLARSSL_KE_ECDH,
    POLARSSL_KE_ECDHE,
} ke_type_t;

/**
 * Key exchange information. Allows key exchange functions to be called
 * in a generic way.
 */
typedef struct {
    ke_type_t type;

    const char *name;

    void *(*ctx_alloc)( void );
    void (*ctx_free)( void *ctx );

    int (*gen_public)( void *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );

    int (*compute_shared)( void *ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng );

    int (*set_params)( void *ctx, const void *params );

    int (*read_ske_params)( void *ctx, int *rlen, const unsigned char *buf,
                            size_t blen );

    int (*read_public)( void *ctx, const unsigned char *buf, size_t blen );

    int (*read_from_self_pk_ctx)( void *ctx, const void *pk_ctx );

    int (*read_from_peer_pk_ctx)( void *ctx, const void *pk_ctx );

    size_t (*getsize_ske_params)( const void *ctx );

    int (*write_ske_params)( size_t *olen, unsigned char *buf, size_t blen,
                             const void *ctx );

    size_t (*getsize_public)( const void *ctx );

    int (*write_public)( size_t *olen, unsigned char *buf, size_t blen,
                         const void *ctx );

    size_t (*getsize_premaster)( const void *ctx );

    int (*write_premaster)( size_t *olen, unsigned char *buf, size_t blen,
                            const void *ctx );
} ke_info_t;


/**
 * Generic key exchange context.
 */
typedef struct {
    /** Information/functions about the associated key exchange */
    const ke_info_t *ke_info;

    /** Key-exchange-specific context */
    void *ke_ctx;
} ke_context_t;


#define KE_CONTEXT_T_INIT { \
    NULL, /* ke_info */ \
    NULL, /* ke_ctx */ \
}

/**
 * \brief           Returns the KE information associated with the
 *                  given KE type.
 *
 * \param ke_type   type of KE to search for.
 *
 * \return          The KE information associated with ke_type or
 *                  NULL if not found.
 */
const ke_info_t *ke_info_from_type( ke_type_t ke_type );

/**
 * \brief               Initialize a ke_context (as NONE)
 */
void ke_init( ke_context_t *ctx );

/**
 * \brief               Free and clear the KE-specific context of ctx.
 *                      Freeing ctx itself remains the responsibility of the
 *                      caller.
 */
void ke_free( ke_context_t *ctx );

/**
 * \brief          Initialises and fills the KE context structure
 *                 with the appropriate values.
 *
 * \param ctx      context to initialise. May not be NULL. The
 *                 digest-specific context (ctx->ke_ctx) must be NULL. It will
 *                 be allocated, and must be freed using ke_free_ctx() later.
 * \param ke_info  KE to use.
 *
 * \returns        \c 0 on success, \c POLARSSL_ERR_KE_ERR on
 *                 parameter failure, \c POLARSSL_ERR_KE_ERR if
 *                 allocation of the KE context failed.
 */
int ke_init_ctx( ke_context_t *ctx, const ke_info_t *ke_info );

/**
 * \brief           Returns the size of the premaster secret.
 *
 * \param ctx       using KE info only: ke_ctx->ke_info
 *
 * \return          size of the premaster secret.
 */
size_t ke_getsize_premaster( const ke_context_t *ctx );

/**
 * \brief           Returns the type of the KE output.
 *
 * \param ctx       using KE info only: ke_ctx->ke_info
 *
 * \return          type of the KE output.
 */
ke_type_t ke_get_type( const ke_context_t *ctx );

/**
 * \brief           Returns the name of the KE.
 *
 * \param ctx       using KE info only: ke_ctx->ke_info
 *
 * \return          name of the KE.
 */
const char *ke_get_name( const ke_context_t *ctx );

int ke_gen_public( ke_context_t *ctx,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng );

int ke_compute_shared( ke_context_t *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );

int ke_set_params( ke_context_t *ctx, const void *params );

int ke_read_ske_params( ke_context_t *ctx, int *rlen,
                        const unsigned char *buf, size_t blen );

int ke_read_public( ke_context_t *ctx, const unsigned char *buf, size_t blen );

/**
 * A "pk_ctx" represents an interface with a certificate
 * which is initialized in pk_parse_subpubkey() in library/pkparse.c
 */
int ke_read_from_self_pk_ctx( ke_context_t *ctx, const void *pk_ctx );

int ke_read_from_peer_pk_ctx( ke_context_t *ctx, const void *pk_ctx );

size_t ke_getsize_ske_params( const ke_context_t *ctx );

int ke_write_ske_params( const ke_context_t *ctx, size_t *olen,
                         unsigned char *buf, size_t blen );

size_t ke_getsize_public( const ke_context_t *ctx );

int ke_write_public( const ke_context_t *ctx, size_t *olen,
                     unsigned char *buf, size_t blen );

int ke_write_premaster( const ke_context_t *ctx, size_t *olen,
                        unsigned char *buf, size_t blen );

#ifdef __cplusplus
}
#endif

#endif  /* POLARSSL_KE_H */
