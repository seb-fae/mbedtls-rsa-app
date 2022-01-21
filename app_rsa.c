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

mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
unsigned char encrypted_buf[512];
char data_to_encrypt[] = "This is the message to encrypt with RSA";

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

    mbedtls_printf( " ok  clock cycles: %ld, time: %" PRIu32 " ms\n  . Exporting the public  key ....", time_diff_tick, time_diff_ms );


    if( ( ret = mbedtls_rsa_export    ( &rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( &rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
        goto exit;
    }

    mbedtls_printf( " ok\n\n" );


exit:

    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}

/********************************************* Sign/verify **********************/

unsigned char din[2048] = "this is the data to sign";
unsigned char sign[MBEDTLS_MPI_MAX_SIZE];

void app_rsa_sign()
{
    int ret = 1;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_sign";

    mbedtls_rsa_init( &rsa );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) );

    mbedtls_printf( "\n  . Import private key" );


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

    mbedtls_printf( "\n  . Checking the private key" );

    if( ( ret = mbedtls_rsa_check_privkey( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    mbedtls_printf( "\n  . Generating the RSA/SHA-256 signature" );


    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    din, sizeof(din), hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not hash input \n\n" );
        goto exit;
    }

    time_tick = sl_sleeptimer_get_tick_count();

    if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, mbedtls_ctr_drbg_random,
                                        &ctr_drbg, MBEDTLS_MD_SHA256,
                                32, hash, sign ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }


    time_diff_tick = sl_sleeptimer_get_tick_count() - time_tick;
    time_diff_ms = sl_sleeptimer_tick_to_ms(time_diff_tick);

    mbedtls_printf( "\n  . OK  clock cycles: %ld, time: %" PRIu32 " ms\n\n" );

exit:
    mbedtls_rsa_free( &rsa );
}

void app_rsa_verify()
{
    int ret = 1;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];

    mbedtls_rsa_init( &rsa );

    mbedtls_printf( "\n  . Importing public key" );


    if( ( ret = mbedtls_rsa_import( &rsa, &N, NULL, NULL, NULL, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    rsa.MBEDTLS_PRIVATE(len) = ( mbedtls_mpi_bitlen( &rsa.MBEDTLS_PRIVATE(N) ) + 7 ) >> 3;

    /*
     * Compute the SHA-256 hash of the input file and
     * verify the signature
     */
    mbedtls_printf( "\n  . Verifying the RSA/SHA-256 signature" );


    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    din, sizeof(din), hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could hash input\n\n");
        goto exit;
    }

    time_tick = sl_sleeptimer_get_tick_count();

    if( ( ret = mbedtls_rsa_pkcs1_verify( &rsa, MBEDTLS_MD_SHA256,
                                          32, hash, sign ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }


    time_diff_tick = sl_sleeptimer_get_tick_count() - time_tick;
    time_diff_ms = sl_sleeptimer_tick_to_ms(time_diff_tick);

    mbedtls_printf( "\n  . OK (the signature is valid)  clock cycles: %ld, time: %" PRIu32 " ms\n\n" );

exit:

    mbedtls_rsa_free( &rsa );
}




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

    mbedtls_printf( " ok clock cycles: %ld, time: %" PRIu32 " ms.\n\n", time_diff_tick, time_diff_ms );

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_rsa_free( &rsa );
}




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



