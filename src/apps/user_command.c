/**
 ****************************************************************************************
 *
 * @file user_command.c
 *
 * @brief Console command specified by customer
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

#include "user_command.h"


const COMMAND_TREE_TYPE	cmd_user_list[] = {
	{ "user",			CMD_MY_NODE,	cmd_user_list,	NULL,		"User cmd "				},	// Head

	{ "-------",		CMD_FUNC_NODE,	NULL,	NULL,						"--------------------------------"	},
	{ "testcmd",		CMD_FUNC_NODE,	NULL,	&cmd_test,					"testcmd [option]"					},
#if defined(__COAP_CLIENT_SAMPLE__)
	{ "coap_client",	CMD_FUNC_NODE,	NULL,	&cmd_coap_client,			"CoAP Client"						},
#endif /* __COAP_CLIENT_SAMPLE__ */
    { NULL, 			CMD_NULL_NODE,	NULL,	NULL,	NULL 		}	// Tail
};

//
//-----------------------------------------------------------------------
// Internal Functions
//-----------------------------------------------------------------------

void cmd_test(int argc, char *argv[])
{	
	if (argc < 2)
	{
		PRINTF("Usage: testcmd [option]\n   ex) testcmd test\n\n");
		return;
	}

	PRINTF("\n### TEST CMD : %s ###\n\n", argv[1]);
}

#if defined(__COAP_CLIENT_SAMPLE__)
void cmd_coap_client(int argc, char *argv[])
{
	extern void coap_client_sample_cmd(int argc, char *argv[]);

	coap_client_sample_cmd(argc, argv);

	return ;
}
#endif /* __COAP_CLIENT_SAMPLE__ */

/* EOF */
