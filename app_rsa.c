/***************************************************************************//**
 * @file
 * @brief mbedTLS AES examples functions
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#include <app_rsa.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "em_device.h"
#include "em_chip.h"
#include "em_cmu.h"

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>


#define mbedtls_printf       printf

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#endif

#define KEY_SIZE 2048
#define EXPONENT 65537

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||   \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_GENPRIME) ||      \
    !defined(MBEDTLS_CTR_DRBG_C)
int app_rsa_key_gen( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_RSA_C and/or MBEDTLS_GENPRIME and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit( 0 );
}
#else


mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
unsigned char encrypted_buf[512];

uint32_t time_tick;
uint32_t time_diff_tick;
uint32_t time_diff_ms;

void app_rsa_key_gen( void )
{
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    int ret = 1;

    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_rsa_init( &rsa );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_printf( "\n  . Seeding the random number generator..." );


    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );


    time_tick = sl_sleeptimer_get_tick_count();

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                     EXPONENT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        goto exit;
    }

    time_diff_tick = sl_sleeptimer_get_tick_count() - time_tick;
    time_diff_ms = sl_sleeptimer_tick_to_ms(time_diff_tick);

    mbedtls_printf( " ok  clock cycles: %ld, time: %" PRIu32 " ms.\n\n Exporting the public  key ....", time_diff_tick, time_diff_ms );


    if( ( ret = mbedtls_rsa_export    ( &rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( &rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
        goto exit;
    }

#ifdef FILESYSTEM
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;

    if( ( fpub = fopen( "rsa_pub.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_write_file( "N = ", &N, 16, fpub ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = ", &E, 16, fpub ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Exporting the private key in rsa_priv.txt..." );


    if( ( fpriv = fopen( "rsa_priv.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! could not open rsa_priv.txt for writing\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_write_file( "N = " , &N , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = " , &E , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "D = " , &D , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "P = " , &P , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "Q = " , &Q , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DP = ", &DP, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DQ = ", &DQ, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "QP = ", &QP, 16, fpriv ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }
#endif

    mbedtls_printf( " ok\n\n" );


exit:

    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_GENPRIME && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */


/*******************************************************************************
 *******************************   DEFINES   ***********************************
 ******************************************************************************/
#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_ENTROPY_C) | \
    !defined(MBEDTLS_CTR_DRBG_C)
int app_rsa_encrypt( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit( 0 );
}
#else

char data_to_encrypt[] = "This is the message to encrypt with RSA";

void app_rsa_encrypt()
{

    int ret = 1;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    const char *pers = "rsa_encrypt";

    mbedtls_printf( "\n  . Seeding the random number generator..." );

    mbedtls_rsa_init( &rsa );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

#ifdef FILESYSTEM
    mbedtls_printf( "\n  . Reading public key from rsa_pub.txt" );


    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &N, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &E, 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                        ret );
        fclose( f );
        goto exit;
    }
    fclose( f );

#endif

    if( ( ret = mbedtls_rsa_import( &rsa, &N, NULL, NULL, NULL, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( strlen( data_to_encrypt ) > 100 )
    {
        mbedtls_printf( " Input data larger than 100 characters.\n\n" );
        return;
    }

    memcpy( input, data_to_encrypt, strlen( data_to_encrypt ) );

    /*
     * Calculate the RSA encryption of the hash.
     */
    mbedtls_printf( "\n  . Generating the RSA encrypted value... " );

    time_tick = sl_sleeptimer_get_tick_count();

    ret = mbedtls_rsa_pkcs1_encrypt( &rsa, mbedtls_ctr_drbg_random,
                                     &ctr_drbg, strlen( data_to_encrypt ), input, encrypted_buf);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %x\n\n",
                        ret );
        return;
    }

    time_diff_tick = sl_sleeptimer_get_tick_count() - time_tick;
    time_diff_ms = sl_sleeptimer_tick_to_ms(time_diff_tick);

#ifdef FILESYSTEM
    /*
     * Write the signature into result-enc.txt
     */
    if( ( f = fopen( "result-enc.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", "result-enc.txt" );
        goto exit;
    }

    for( i = 0; i < rsa.MBEDTLS_PRIVATE(len); i++ )
        mbedtls_fprintf( f, "%02X%s", encrypted_buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );
#endif
    mbedtls_printf( " ok clock cycles: %ld, time: %" PRIu32 " ms.\n\n", time_diff_tick, time_diff_ms );

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_rsa_free( &rsa );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */


#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int app_rsa_decrypt( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    mbedtls_exit( 0 );
}
#else


void app_rsa_decrypt(  )
{
    int ret = 1;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    const char *pers = "rsa_decrypt";


    memset(result, 0, sizeof( result ) );


    mbedtls_printf( "\n  . Seeding the random number generator..." );


    mbedtls_rsa_init( &rsa );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

#ifdef FILESYSTEM
    mbedtls_printf( "\n  . Reading private key from rsa_priv.txt" );


    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &N , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &E , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &D , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &P , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &Q , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &DP , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &DQ , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &QP , 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                        ret );
        fclose( f );
        goto exit;
    }
    fclose( f );
#endif

    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }
#ifdef FILESYSTEM
    /*
     * Extract the RSA encrypted value from the text file
     */
    if( ( f = fopen( "result-enc.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", "result-enc.txt" );
        goto exit;
    }

    i = 0;

    while( fscanf( f, "%02X", (unsigned int*) &c ) > 0 &&
           i < (int) sizeof( encrypted_buf ) )
        encrypted_buf[i++] = (unsigned char) c;

    fclose( f );


    if( i != rsa.MBEDTLS_PRIVATE(len) )
    {
        mbedtls_printf( "\n  ! Invalid RSA signature format\n\n" );
        goto exit;
    }
#endif
    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf( "\n  . Decrypting the encrypted data..." );

    time_tick = sl_sleeptimer_get_tick_count();

    ret = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, &i,
                                            encrypted_buf, result, 1024 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                        ret );
        goto exit;
    }

    time_diff_tick = sl_sleeptimer_get_tick_count() - time_tick;
    time_diff_ms = sl_sleeptimer_tick_to_ms(time_diff_tick);

    mbedtls_printf( " ok clock cycles: %ld, time: %" PRIu32 " ms. \n\n ", time_diff_tick, time_diff_ms );

    mbedtls_printf( "The decrypted result is: '%s'\n\n", result );


exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_FS_IO */
