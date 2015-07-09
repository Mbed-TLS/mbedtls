/**
 * \file ke_wrap.c
 *
 * \brief Generic key exchange wrapper
 *
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <stddef.h>

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdlib.h>
#define polarssl_printf     printf
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include "polarssl/ke_wrap.h"

#if defined(POLARSSL_KEIF_C)

#include "polarssl/ke.h"

#if defined(POLARSSL_DHM_C)

#include "polarssl/dhm.h"

/*
 * BEGIN Our wrapper interfaces for DH key exchange
 */

static int wdhm_gen_public( void *_ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng )
{
    dhm_context *ctx = (dhm_context *) _ctx;
    static unsigned char tmp_buffer[1536]; /* XXX: We assume that 1536 is always greater than 3*mpi_size(P) */
    int ret = 0;

    if( NULL == ctx || 0 == ctx->len )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    ret = dhm_make_public( ctx, (int) ctx->len, tmp_buffer, ctx->len,
                           f_rng, p_rng );

    return( ret );
}

static int wdhm_compute_shared( void *_ctx,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng )
{
    dhm_context *ctx = (dhm_context *) _ctx;
    static unsigned char tmp_buffer[1536];
    size_t buffer_len = 1536;
    int ret = 0;

    ret = dhm_calc_secret( ctx, tmp_buffer, &buffer_len, f_rng, p_rng );

    return( ret );
}

typedef struct { mpi P; mpi G; } wdh_params;

static int __wdhm_set_params( void *_ctx, const void *_params )
{
    dhm_context *ctx = (dhm_context *) _ctx;
    int ret = 0;
    const wdh_params *params = (const wdh_params *) _params;

    if( NULL == ctx || NULL == params )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    MPI_CHK( mpi_copy( &ctx->P, &params->P ) );
    MPI_CHK( mpi_copy( &ctx->G, &params->G ) );
    ctx->len = mpi_size( &ctx->P );

cleanup:
    return( ret );
}

static int wdhm_set_params( void *_ctx, const void *_params )
{
    int ret;
    struct { mpi P; mpi G; } _pa;

    mpi_init( &_pa.P );
    mpi_init( &_pa.G );

    if( _params == NULL )
    {
        ret = mpi_read_string( &_pa.P, 16, POLARSSL_DHM_RFC5114_MODP_1024_P );
        if( ret != 0 ) return( ret );
        ret = mpi_read_string( &_pa.G, 16, POLARSSL_DHM_RFC5114_MODP_1024_G );
        if( ret != 0 ) return( ret );
        _params = (void *) &_pa;
    }

    ret = __wdhm_set_params( _ctx, _params );

    mpi_free( &_pa.P );
    mpi_free( &_pa.G );

    return( ret );
}

static int _check_p_range( const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *) _ctx;

    if( ctx->len < 64 || ctx->len > 512 )
        return( -1 );   // FIXME XXX TODO What is -1?
                        // Do we need to define error code?

    return( 0 );
}

static int wdhm_read_params( void *_ctx, int *rlen,
                             const unsigned char *buf, size_t blen )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    const unsigned char *p = buf;
    int ret = 0;
    const unsigned char *end = p + blen;

    ret = dhm_read_params( ctx, (unsigned char **) &p, end );

    *rlen = p - buf;

    if( ret != 0 )
        return( ret );

    ret = _check_p_range(ctx);

    if( ret != 0 )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    return( ret );
}

static int wdhm_read_public( void *_ctx, const unsigned char *buf, size_t blen )
{
    dhm_context *ctx = (dhm_context *) _ctx;
    int ret = 0;
    size_t n;

    if( blen < 2 )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    n = ( buf[0] << 8 ) | buf[1];
    buf += 2;

    if( blen < 2 + n )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    ret = dhm_read_public(ctx, buf, n);
    if( ret != 0 )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    if( blen != 2 + n )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    return( ret );
}

/*
 * PolarSSL does not support the DHM non-ephemeral keyexchange...

int wdhm_read_from_self_pk_ctx( dhm_context *ctx, const void *_pk_ctx ) {
    ((void)ctx);
    ((void)_pk_ctx);
    return -1;
}
int wdhm_read_from_peer_pk_ctx( dhm_context *ctx, const void *_pk_ctx ) {
    ((void)ctx);
    ((void)_pk_ctx);
    return -1;
}

 */

static size_t wdhm_getsize_params( const void *_ctx )
{
    dhm_context *ctx = (dhm_context *) _ctx;

    return( 3 * 2 + mpi_size( &ctx->P ) +
                    mpi_size( &ctx->G ) +
                    mpi_size( &ctx->GX ) );
}

static int wdhm_write_params( size_t *olen, unsigned char *buf, size_t blen,
                              const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *) _ctx;
    int ret = 0;
    unsigned char *p = buf;
    size_t n1, n2, n3;

    if( ctx == NULL || blen < wdhm_getsize_params( ctx ) )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

#define DHM_MPI_EXPORT( X, n )                  \
    MPI_CHK( mpi_write_binary( X, p + 2, n ) ); \
    *p++ = (unsigned char)( n >> 8 );           \
    *p++ = (unsigned char)( n      ); p += n;

    n1 = mpi_size( &ctx->P  );
    n2 = mpi_size( &ctx->G  );
    n3 = mpi_size( &ctx->GX );

    DHM_MPI_EXPORT( &ctx->P , n1 );
    DHM_MPI_EXPORT( &ctx->G , n2 );
    DHM_MPI_EXPORT( &ctx->GX, n3 );

    *olen = p - buf;

cleanup:
    if( ret != 0 )
        return( POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED + ret );

    return( 0 );
}

static size_t wdhm_getsize_public( const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *) _ctx;
    return( ctx->len + 2 );
}

static int wdhm_write_public( size_t *olen, unsigned char *buf, size_t blen,
                              const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *) _ctx;
    int ret = 0;

    if( ctx == NULL || blen < ctx->len )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    MPI_CHK( mpi_write_binary( &ctx->GX, buf + 2, ctx->len ) );
    buf[0] = (unsigned char) ( ctx->len >> 8 );
    buf[1] = (unsigned char) ( ctx->len      );
    *olen = ctx->len + 2;

cleanup:
    if( ret != 0 )
        return( POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED + ret );

    return( 0 );
}

static size_t wdhm_getsize_premaster( const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *) _ctx;
    return( ctx->len );
}

static int wdhm_write_premaster( size_t *olen, unsigned char *buf, size_t blen,
                                 const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *) _ctx;
    int ret = 0;

    if( ctx == NULL || blen < ctx->len )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    MPI_CHK( mpi_write_binary( &ctx->K, buf, ctx->len ) );
    *olen = ctx->len;

cleanup:
    if( ret != 0 )
        return( POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED + ret );

    return( 0 );
}

static void *dhm_alloc2( void )
{
    dhm_context *ctx = polarssl_malloc( sizeof( dhm_context ) );

    if( ctx == NULL )
        return( NULL );

    dhm_init( ctx );
    return( ctx );
}

static void dhm_free2( void *ctx )
{
    dhm_free( (dhm_context *) ctx );
    polarssl_free( ctx );
}

const ke_info_t dhm_info2 = {
    POLARSSL_KE_DHM,
    "DHM_KE_IF",
    dhm_alloc2,
    dhm_free2,
    wdhm_gen_public,
    wdhm_compute_shared,
    wdhm_set_params,
    wdhm_read_params,
    wdhm_read_public,
    NULL,
    NULL,
    wdhm_getsize_params,
    wdhm_write_params,
    wdhm_getsize_public,
    wdhm_write_public,
    wdhm_getsize_premaster,
    wdhm_write_premaster,
};

/*
 * END Our wrapper interfaces for DH key exchange
 */

#endif /* defined(POLARSSL_DHM_C) */

#if defined(POLARSSL_ECDH_C)

#include "polarssl/ecdh.h"

typedef enum { ECDH_UNKNOWN, ECDH_SERVER, ECDH_CLIENT } ecdh_role;

typedef struct { ecdh_context ctx; ecdh_role role; } wecdh_ctx;

/*
 * BEGIN Our wrapper interfaces for ECDH key exchange
 */

static int wecdh_gen_public( void *_ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    wecdh_ctx *ctx = (wecdh_ctx *) _ctx;
    int ret = 0;

    if( ctx == NULL || ctx->ctx.grp.pbits == 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ctx->role == ECDH_SERVER )
        return( 0 );

    ret = ecdh_gen_public( &ctx->ctx.grp, &ctx->ctx.d, &ctx->ctx.Q,
                           f_rng, p_rng );

    return( ret );
}

static int wecdh_compute_shared( void *_ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng )
{
    ecdh_context *ctx = (ecdh_context *) _ctx;
    int ret = 0;

    if( ctx == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ret = ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp, &ctx->d,
                               f_rng, p_rng );

    return( ret );

}

static int _check_server_ecdh_params( const ecdh_context *ctx )
{
    const ecp_curve_info *curve_info;

    curve_info = ecp_curve_info_from_grp_id( ctx->grp.id );
    if( curve_info == NULL )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    }

#if defined(POLARSSL_SSL_ECP_SET_CURVES)
    {
        const ecp_group_id *gid;
        for( gid = ecp_curve_list(); *gid != POLARSSL_ECP_DP_NONE; gid++ )
            if( *gid == ctx->grp.id )
                break;
        if( *gid == POLARSSL_ECP_DP_NONE )
            return( -1 );
    }
#else
    if( ctx->grp.nbits < 163 ||
        ctx->grp.nbits > 521 )
        return( -1 );
#endif

    return( 0 );
}

typedef struct { int point_format; ecp_group_id group_id; } wecdh_params;

static int __wecdh_set_params( void *_ctx, const void *_params )
{
    ecdh_context *ctx = (ecdh_context *) _ctx;
    int ret = 0;
    const wecdh_params *params = (const wecdh_params *) _params;

    if( ctx == NULL || params == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ctx->point_format = params->point_format;

    ret = ecp_use_known_dp( &ctx->grp, params->group_id );
    if( ret != 0 )
        return( ret );

    ret = _check_server_ecdh_params(ctx);
    if( ret != 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    return( ret );
}

static int wecdh_set_params( void *_ctx, const void *_params )
{
    wecdh_ctx *ctx = (wecdh_ctx *) _ctx;
    wecdh_params pp = {
        POLARSSL_ECP_PF_UNCOMPRESSED,
        POLARSSL_ECP_DP_SECP256R1
    };

    if( NULL == _params )
        _params = (const void *) &pp;

    if( ctx->role != ECDH_UNKNOWN )
        return( 0 ); /* read params from certificate */

    return( __wecdh_set_params( _ctx, _params ) );
}

static int wecdh_read_params( void *_ctx, int *rlen,
                              const unsigned char *buf, size_t blen )
{
    ecdh_context *ctx = (ecdh_context *) _ctx;
    const unsigned char *p = buf;
    int ret = 0;
    const unsigned char *end = p + blen;

    ret = ecdh_read_params(ctx, &p, end);

    *rlen = p - buf;

    return( ret );
}

static int wecdh_read_public( void *_ctx,
                              const unsigned char *buf, size_t blen )
{
    ecdh_context *ctx = (ecdh_context *) _ctx;
    int ret = 0;

    ret = ecdh_read_public( ctx, buf, blen );

    return( ret );
}

static int wecdh_read_from_self_pk_ctx( void *_ctx, const void *_pk_ctx )
{
    wecdh_ctx *wctx = (wecdh_ctx*) _ctx;
    ecdh_context *ctx = (ecdh_context *) _ctx;
    const ecp_keypair *key = (const ecp_keypair *) _pk_ctx;
    int ret = -1;

    if( wctx->role == ECDH_CLIENT )
        return( 0 );

    wctx->role = ECDH_SERVER;

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    if( ( ret = ecp_copy( &ctx->Q, &key->Q ) ) != 0 )
        return( ret );

    ret = mpi_copy( &ctx->d, &key->d );
    if( ret != 0 )
        return( ret );

    ret = _check_server_ecdh_params( ctx );
    if( ret != 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    return( ret );
}

static int wecdh_read_from_peer_pk_ctx( void *_ctx, const void *_pk_ctx )
{
    wecdh_ctx *wctx = (wecdh_ctx*) _ctx;
    ecdh_context *ctx = (ecdh_context *) _ctx;
    const ecp_keypair *key = (const ecp_keypair *) _pk_ctx;
    int ret = -1;

    if( wctx->role == ECDH_UNKNOWN )
        wctx->role = ECDH_CLIENT;

    if( wctx->role == ECDH_SERVER )
        return( 0 );

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    ret = ecp_copy( &ctx->Qp, &key->Q );
    if( ret != 0 )
        return( ret );

    ret = _check_server_ecdh_params( ctx );
    if( ret != 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    return( ret );
}

static size_t wecdh_getsize_public( const void *_ctx )
{
    const ecdh_context *ctx = (const ecdh_context *) _ctx;
    const ecp_group grp = ctx->grp;
    const ecp_point Q = ctx->Q;
    int point_format = ctx->point_format;
    size_t point_length = mpi_size(&grp.P);
    size_t _ = -1;

    /*
     * ecp_point_write_binary uses _ bytes to write a ECP point
     */
    if( 0 == mpi_cmp_int( &Q.Z, 0 ) )
        _ = 1;
    else if( point_format == POLARSSL_ECP_PF_UNCOMPRESSED )
        _ = 2 * point_length + 1;
    else if( point_format == POLARSSL_ECP_PF_COMPRESSED )
        _ = point_length + 1;

    /*
     * ecp_tls_write_point uses an additional 1 byte to write length
     */
    return( 1 + _ );
}

static size_t wecdh_getsize_params( const void *_ctx )
{
    const ecdh_context *ctx = (const ecdh_context *) _ctx;

    /* In addition to the public parameter (an EC point),
     * ecp_tls_write_group uses 3 bytes */
    return( 3 + wecdh_getsize_public( ctx ) );
}

static int wecdh_write_params( size_t *olen, unsigned char *buf, size_t blen,
                               const void *_ctx )
{
    const ecdh_context *ctx = (const ecdh_context *) _ctx;
    int ret = 0;
    size_t grp_len, pt_len;

    if( ctx == NULL || blen < wecdh_getsize_params( ctx ) )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if ( ( ret = ecp_tls_write_group( &ctx->grp, &grp_len, buf, blen ) ) != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    ret = ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                               &pt_len, buf, blen );

    *olen = grp_len + pt_len;

    return( ret );
}

static int wecdh_write_public( size_t *olen, unsigned char *buf, size_t blen,
                               const void *_ctx )
{
    const ecdh_context *ctx = (const ecdh_context *) _ctx;
    int ret = 0;

    if( ctx == NULL || blen < wecdh_getsize_public( ctx ) )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ret = ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                               olen, buf, blen );

    return( ret );
}

static size_t wecdh_getsize_premaster( const void *_ctx )
{
    const ecdh_context *ctx = (const ecdh_context *) _ctx;
    return( mpi_size( &ctx->z ) );
}

static int wecdh_write_premaster( size_t *olen, unsigned char *buf,
                                  size_t blen, const void *_ctx )
{
    const ecdh_context *ctx = (const ecdh_context *) _ctx;
    int ret = 0;

    if( ctx == NULL || blen < mpi_size( &ctx->z ) )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    *olen = ctx->grp.pbits / 8 + ( ( ctx->grp.pbits % 8 ) != 0 );
    ret = mpi_write_binary( &ctx->z, buf, *olen );

    return( ret );
}

static void *m_ecdh_alloc( void )
{
    wecdh_ctx *ctx = (wecdh_ctx *) polarssl_malloc( sizeof( wecdh_ctx ) );

    if ( ctx == NULL )
        return( NULL );
    else
    {
        ecdh_init( &ctx->ctx );
        ctx->role = ECDH_UNKNOWN;
    }

    return( ctx );
}

static void m_ecdh_free( void *ctx )
{
    wecdh_ctx *_ctx = (wecdh_ctx *) ctx;
    ecdh_free( (ecdh_context *) &_ctx->ctx );
    polarssl_free( ctx );
}

const ke_info_t ecdhe_info2 = {
    POLARSSL_KE_ECDHE,
    "M_ECDHE",
    m_ecdh_alloc,
    m_ecdh_free,
    wecdh_gen_public,
    wecdh_compute_shared,
    wecdh_set_params,
    wecdh_read_params,
    wecdh_read_public,
    NULL,
    NULL,
    wecdh_getsize_params,
    wecdh_write_params,
    wecdh_getsize_public,
    wecdh_write_public,
    wecdh_getsize_premaster,
    wecdh_write_premaster,
};

const ke_info_t ecdh_info2 = {
    POLARSSL_KE_ECDH,
    "M_ECDH",
    m_ecdh_alloc,
    m_ecdh_free,
    wecdh_gen_public,
    wecdh_compute_shared,
    wecdh_set_params,
    wecdh_read_params,
    wecdh_read_public,
    wecdh_read_from_self_pk_ctx,
    wecdh_read_from_peer_pk_ctx,
    wecdh_getsize_params,
    wecdh_write_params,
    wecdh_getsize_public,
    wecdh_write_public,
    wecdh_getsize_premaster,
    wecdh_write_premaster,
};

/*
 * END Our wrapper interfaces for ECDH key exchange
 */

#endif /* defined(POLARSSL_ECDH_C) */

#endif /* defined(POLARSSL_KEIF_C) */
