

/**
 ****************************************************************************************
 *
 * @file hello_world.c
 *
 * @brief Sample functions for Customer applicatons.
 *
 * Copyright (c) 2016-2020 Dialog Semiconductor. All rights reserved.
 *
 * This software ("Software") is owned by Dialog Semiconductor.
 *
 * By using this Software you agree that Dialog Semiconductor retains all
 * intellectual property and proprietary rights in and to this Software and any
 * use, reproduction, disclosure or distribution of the Software without express
 * written permission or a license agreement from Dialog Semiconductor is
 * strictly prohibited. This Software is solely for use on or in conjunction
 * with Dialog Semiconductor products.
 *
 * EXCEPT AS OTHERWISE PROVIDED IN A LICENSE AGREEMENT BETWEEN THE PARTIES, THE
 * SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. EXCEPT AS OTHERWISE
 * PROVIDED IN A LICENSE AGREEMENT BETWEEN THE PARTIES, IN NO EVENT SHALL
 * DIALOG SEMICONDUCTOR BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL,
 * OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THE SOFTWARE.
 *
 ****************************************************************************************
 */

#include "sdk_type.h"


#include "da16x_system.h"
#include "da16x_types.h"
#include "command_net.h"
#include "httpd.h"

/* External functions */

/* External variables */

/* Glocal variables */

/* Global functions */

/* Local functions */


void customer_hello_world_1(void *arg)
{
	PRINTF("\n\n");
	PRINTF(">>> Hello World #1 ( Non network dependent application ) !!!\n");
	PRINTF("\n\n");
	httpd_init();
	myCGIinit();//edit vuiiiii
	vTaskDelete(NULL);
}

void customer_hello_world_2(void *arg)
{
	PRINTF("\n\n");
	PRINTF(">>> Hello World #2 ( network dependent application ) !!!\n");
	PRINTF("\n\n");

	vTaskDelete(NULL);
}


/* EOF */
