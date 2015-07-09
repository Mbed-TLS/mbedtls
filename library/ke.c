#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_KEIF_C)

#include "polarssl/ke.h"
#include "polarssl/ke_wrap.h"

const ke_info_t *ke_info_from_type( ke_type_t type )
{
#if defined(POLARSSL_DHM_C)
    if( type == POLARSSL_KE_DHM ) return( &dhm_info2 );
#endif

#if defined(POLARSSL_ECDH_C)
    if( type == POLARSSL_KE_EC    ) return( &ecdhe_info2 );
    if( type == POLARSSL_KE_ECDHE ) return( &ecdhe_info2 );
    if( type == POLARSSL_KE_ECDH  ) return( &ecdh_info2 );
#endif

    (void) type;
    return( NULL );
}

void ke_init( ke_context_t *ctx )
{
   ctx->ke_info = NULL;
   ctx->ke_ctx = NULL;
}

void ke_free( ke_context_t *ctx )
{
    if( ctx->ke_info == NULL )
        return;

    if( ctx->ke_info->ctx_free == NULL )
        return;

    ctx->ke_info->ctx_free( ctx->ke_ctx );
    ctx->ke_ctx = NULL;
}

int ke_init_ctx( ke_context_t *ctx, const ke_info_t *ke_info )
{
    if( ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    ctx->ke_info = ke_info;

    if( ke_info->ctx_alloc == NULL )
        return( POLARSSL_ERR_KE_ERR );

    ctx->ke_ctx = ke_info->ctx_alloc();

    if( ctx->ke_ctx == NULL )
        return( POLARSSL_ERR_KE_ERR );

    return( 0 );
}

size_t ke_getsize_premaster( const ke_context_t *ctx )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( 0 );

    return( ctx->ke_info->getsize_premaster( ctx->ke_ctx ) );
}

ke_type_t ke_get_type( const ke_context_t *ctx )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_KE_NONE );

    return( ctx->ke_info->type );
}

const char *ke_get_name( const ke_context_t *ctx )
{
    if( ctx == NULL )
        return( NULL );

    if( ctx->ke_info == NULL )
        return( NULL );

    return( ctx->ke_info->name );
}

int ke_gen_public( ke_context_t *ctx,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->gen_public == NULL )
        return( POLARSSL_ERR_KE_ERR );

    return( ctx->ke_info->gen_public( ctx->ke_ctx, f_rng, p_rng ) );

}

int ke_compute_shared( ke_context_t *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->compute_shared == NULL )
        return( POLARSSL_ERR_KE_ERR );

    return( ctx->ke_info->compute_shared( ctx->ke_ctx, f_rng, p_rng ) );
}

int ke_set_params( ke_context_t *ctx, const void *params )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->set_params == NULL )
        return( 0 );

    return( ctx->ke_info->set_params( ctx->ke_ctx, params ) );
}

int ke_read_ske_params( ke_context_t *ctx, int *rlen,
                        const unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->read_ske_params == NULL )
        return( 0 );

    return( ctx->ke_info->read_ske_params( ctx->ke_ctx, rlen, buf, blen ) );
}

int ke_read_public( ke_context_t *ctx, const unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->read_public == NULL )
        return( POLARSSL_ERR_KE_ERR );

    return( ctx->ke_info->read_public( ctx->ke_ctx, buf, blen ) );
}

int ke_read_from_self_pk_ctx( ke_context_t *ctx, const void *pk_ctx )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->read_from_self_pk_ctx == NULL )
        return( 0 );

    return( ctx->ke_info->read_from_self_pk_ctx( ctx->ke_ctx, pk_ctx ) );
}

int ke_read_from_peer_pk_ctx( ke_context_t *ctx, const void *pk_ctx )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->read_from_peer_pk_ctx == NULL )
        return( 0 );

    return( ctx->ke_info->read_from_peer_pk_ctx( ctx->ke_ctx, pk_ctx ) );
}

size_t ke_getsize_ske_params( const ke_context_t *ctx )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( 0 );

    if( ctx->ke_info->getsize_ske_params == NULL )
        return( 0 );

    return( ctx->ke_info->getsize_ske_params( ctx->ke_ctx ) );
}

int ke_write_ske_params( const ke_context_t *ctx, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->write_ske_params == NULL )
        return( 0 );

    return( ctx->ke_info->write_ske_params( olen, buf, blen, ctx->ke_ctx ) );
}

size_t ke_getsize_public( const ke_context_t *ctx )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( 0 );

    if( ctx->ke_info->getsize_public == NULL )
        return( 0 );

    return( ctx->ke_info->getsize_public( ctx->ke_ctx ) );
}

int ke_write_public( const ke_context_t *ctx, size_t *olen,
                     unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->write_public == NULL )
        return( 0 );

    return( ctx->ke_info->write_public( olen, buf, blen, ctx->ke_ctx ) );
}

int ke_write_premaster( const ke_context_t *ctx, size_t *olen,
                        unsigned char *buf, size_t blen )
{
    if( ctx == NULL )
        return( POLARSSL_ERR_KE_NOCTX_PROVIDED );

    if( ctx->ke_info == NULL )
        return( POLARSSL_ERR_KE_NOKEIF_INSTANCE );

    if( ctx->ke_info->write_premaster == NULL )
        return( POLARSSL_ERR_KE_ERR );

    return( ctx->ke_info->write_premaster( olen, buf, blen, ctx->ke_ctx ) );
}

#endif /* POLARSSL_KEIF_C */
