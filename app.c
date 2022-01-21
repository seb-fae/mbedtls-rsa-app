/***************************************************************************//**
 * @file
 * @brief Top level application functions
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
#include "em_cmu.h"


#define ENCRYPT

/***************************************************************************//**
 * Initialize application.
 ******************************************************************************/
void app_init(void)
{
  printf("Sysclock %d\n", CMU_ClockFreqGet(cmuClock_SYSCLK));
  app_rsa_key_gen();
}

/***************************************************************************//**
 * App process function.
 ******************************************************************************/
void app_process_action(void)
{
  app_rsa_sign();
  app_rsa_verify();

  app_rsa_encrypt();
  app_rsa_decrypt();
}
