/**
 ****************************************************************************************
 *
 * @file user_apps.c
 *
 * @brief Config table to start user applications
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
#include "application.h"
#include "common_def.h"

#if defined ( __BLE_COMBO_REF__ )
#if defined (__USER_SENSOR__)
#include "../ble_svc/user_sensor/user_sensor.h"
#endif
#endif	//( __BLE_COMBO_REF__ )
/******************************************************************************
 * External global functions
 ******************************************************************************/
#if defined ( __SUPPORT_HELLO_WORLD__ )
extern void customer_hello_world_1(void *arg);
extern void customer_hello_world_2(void *arg);
#endif //( __SUPPORT_HELLO_WORLD__ )

#if defined ( __SUPPORT_WIFI_PROVISIONING__ )
extern void 	softap_provisioning(ULONG arg);
#endif	// __SUPPORT_WIFI_PROVISIONING__

#if defined (__BLE_COMBO_REF__)
#ifdef __BLE_FEATURE_ENABLED__
extern void gtl_init(void *pvParameters);
#endif
#if defined(__BLE_CENT_SENSOR_GW__) || defined(__BLE_PERI_WIFI_SVC__)
extern void udp_client_main(void *pvParameters);
#endif
#if defined (__BLE_PERI_WIFI_SVC_TCP_DPM__)
#define SAMPLE_TCP_CLI_DPM					"TCPC_DPM"
#define TCP_CLI_TEST_PORT					10192
#if defined (__BLE_PERI_WIFI_SVC_TCP_DPM__) && !defined (__FOR_DPM_SLEEP_CURRENT_TEST__)
extern void	tcp_client_dpm_sample(void *pvParameters);
#endif
#endif /* __BLE_PERI_WIFI_SVC_TCP_DPM__ */
#endif	/* __BLE_COMBO_REF__ */

/******************************************************************************
 * External global variables
 ******************************************************************************/
#if defined ( __SUPPORT_WIFI_CONN_CB__ )
#if defined ( __SUPPORT_ATCMD__ )
extern void PRINTF_ATCMD(const char *fmt, ...);
#endif	// __SUPPORT_ATCMD__

extern SemaphoreHandle_t   wifi_conn_notify_mutex;

extern unsigned char	wifi_conn_flag;
extern unsigned char	wifi_conn_fail_flag;
extern short			wifi_conn_fail_reason;
extern unsigned char	wifi_disconn_flag;
extern short			wifi_disconn_reason;
#endif  // __SUPPORT_WIFI_CONN_CB__

/******************************************************************************
 * Local static functions
 ******************************************************************************/
#if defined ( __SUPPORT_WIFI_CONN_CB__ )
#if 0	// Don't need this operation
static void user_wifi_conn(void *arg);
#endif	// 0
static void user_wifi_conn_fail(void *arg);
static void user_wifi_disconn(void *arg);
#endif  // __SUPPORT_WIFI_CONN_CB__

/******************************************************************************
 * Local variables
 ******************************************************************************/


/**********************************************************
 * Customer's application thread table
 **********************************************************/

const app_task_info_t	user_apps_table[] = {
/* name, func, stack_size, priority, net_chk_flag, dpm_flag, port_no, run_sys_mode */

/*
 * !!! Caution !!!
 *
 * 	User applications should not affect the operation of the Sample code.
 *
 * 	Do not remove "__ENABLE_SAMPLE_APP__" feature in this table.
 */

#if !defined ( __ENABLE_SAMPLE_APP__ )

#if defined ( __SUPPORT_WIFI_CONN_CB__ )
#if 0	// Don't need this operation
	{ WIFI_CONN,		user_wifi_conn,			256,   (tskIDLE_PRIORITY + 2), FALSE, FALSE,  UNDEF_PORT, RUN_ALL_MODE    },
#endif	// 0
	{ WIFI_CONN_FAIL,	user_wifi_conn_fail,	256,   (tskIDLE_PRIORITY + 2), FALSE, FALSE,  UNDEF_PORT, RUN_ALL_MODE    },
	{ WIFI_DISCONN,		user_wifi_disconn,		256,   (tskIDLE_PRIORITY + 2), FALSE, FALSE,  UNDEF_PORT, RUN_ALL_MODE    },
#endif  // __SUPPORT_WIFI_CONN_CB__

#if defined ( __BLE_COMBO_REF__ )
#if defined (__USER_SENSOR__)
  { USER_SENSOR_TAG,	user_sensor_task,		256,	(tskIDLE_PRIORITY + 1), FALSE,  FALSE,  UNDEF_PORT,     RUN_ALL_MODE    },
#endif
#ifdef __BLE_FEATURE_ENABLED__
  { APP_GTL_INIT,		gtl_init,		512,	(tskIDLE_PRIORITY + 1), FALSE,	FALSE,	UNDEF_PORT,	RUN_STA_MODE	},
#endif
#if defined(__BLE_CENT_SENSOR_GW__) || defined(__BLE_PERI_WIFI_SVC__)
  { APP_COMBO_UDP_CLI,  udp_client_main,		512,	(tskIDLE_PRIORITY + 2), TRUE,	TRUE,	10195,		RUN_STA_MODE	},
#endif	// __BLE_CENT_SENSOR_GW__ || __BLE_PERI_WIFI_SVC__
#if defined (__BLE_PERI_WIFI_SVC_TCP_DPM__) && !defined (__FOR_DPM_SLEEP_CURRENT_TEST__)
  { SAMPLE_TCP_CLI_DPM,	tcp_client_dpm_sample,		256,	(tskIDLE_PRIORITY + 2), TRUE, 	FALSE,	TCP_CLI_TEST_PORT,		RUN_STA_MODE },
#endif
#endif	//( __BLE_COMBO_REF__ )

#if defined ( __SUPPORT_HELLO_WORLD__ )
  { HELLO_WORLD_1,  customer_hello_world_1,		128,	(tskIDLE_PRIORITY + 2),	FALSE, FALSE,  UNDEF_PORT, RUN_ALL_MODE    },
  { HELLO_WORLD_2,  customer_hello_world_2,		128,	(tskIDLE_PRIORITY + 2),	TRUE,  FALSE,  UNDEF_PORT, RUN_ALL_MODE    },
#endif  // __SUPPORT_HELLO_WORLD__

#if defined (__SUPPORT_WIFI_PROVISIONING__)
 { CUSTOMER_PROVISIONING,		softap_provisioning,	256,	 (tskIDLE_PRIORITY + 2), FALSE, FALSE,	UNDEF_PORT,		RUN_ALL_MODE },
#endif	// __SUPPORT_WIFI_PROVISIONING__

#endif	/* !__ENABLE_SAMPLE_APP__ */
  { NULL,	NULL,	0, 0, FALSE, FALSE, UNDEF_PORT, 0	}
};


/*============================================================
 *
 * Customer's applications ...
 *
 *============================================================*/

#define	MCU_PWR_ON	pdTRUE
#define MCU_PWR_OFF	pdFALSE

/**
 ****************************************************************************************
 * @brief				Customer MCU power on/off operation
 * @param[in] flag		Power On/Off flag
 * @return				None
 ****************************************************************************************
 */
void customer_mcu_pwr_control(UCHAR flag)
{
	if (flag == MCU_PWR_ON)
	{
		PRINTF("-- Customer MCU : Power-On !!!\n");
		/* ... */
	}
	else if (flag == MCU_PWR_OFF)
	{
		PRINTF("-- Customer MCU : Power-Off !!!\n");
		/* ... */
	}
}

#if defined	( __SUPPORT_WIFI_CONN_CB__ )

///////////////////////////////////////////////////////////////////////////////
////  Customer call-back function to notify WI-Fi connection status
///////////////////////////////////////////////////////////////////////////////

/*
 * Customer thread function
 */
static void user_wifi_conn(void *arg)
{
	while (TRUE) {
		if (wifi_conn_flag == TRUE) {
			/*
			 * Customer tunning value :
			 *  Wait 100msec until sync with MCU
			 */
			vTaskDelay(10);

			PRINTF("\n### Customer Call-back : Success to connect Wi-Fi ...\n");

			/* Clear event flag */
			xSemaphoreTake(wifi_conn_notify_mutex, 300);

			wifi_conn_flag = FALSE;

			xSemaphoreGive(wifi_conn_notify_mutex);
		}

		/* loop time delay : 10 msec */
		vTaskDelay(1);
	}
}

static void user_wifi_conn_fail(void *arg)
{
	while (TRUE) {
		if (wifi_conn_fail_flag == TRUE) {
			/*
			 * Customer tunning value :
			 *  Wait 100msec until sync with MCU
			 */
			vTaskDelay(10);

#if defined ( __SUPPORT_ATCMD__ )

#define WLAN_REASON_TIMEOUT                         39
#define WLAN_REASON_PEERKEY_MISMATCH                45
#define WLAN_REASON_AUTHORIZED_ACCESS_LIMIT_REACHED 46

			switch (wifi_conn_fail_reason) {
				case WLAN_REASON_TIMEOUT :
					PRINTF_ATCMD("\r\n+WFJAP:0,TIMEOUT\r\n"); break;
				case WLAN_REASON_PEERKEY_MISMATCH :
					PRINTF_ATCMD("\r\n+WFJAP:0,WRONGPWD\r\n"); break;
				case WLAN_REASON_AUTHORIZED_ACCESS_LIMIT_REACHED :
					PRINTF_ATCMD("\r\n+WFJAP:0,ACCESSLIMIT\r\n"); break;
				default :
					PRINTF_ATCMD("\r\n+WFJAP:0,OTHER,%d\r\n", wifi_disconn_reason); break;
			}
#else
			PRINTF("\n### User Call-back : Failed to connect Wi-Fi ( reason_code = %d ) ...\n", wifi_conn_fail_reason);

#endif  // __SUPPORT_ATCMD__


			/* Clear event flag */
			xSemaphoreTake(wifi_conn_notify_mutex, 300);

			wifi_conn_fail_reason = 0;
			wifi_conn_fail_flag = FALSE;

			xSemaphoreGive(wifi_conn_notify_mutex);
		}

		/* loop time delay : 10 msec */
		vTaskDelay(1);
	}
}

/*
 * Customer thread function
 */
static void user_wifi_disconn(void *arg)
{
	while (TRUE) {
		if (wifi_disconn_flag == TRUE) {
			/*
			 * Customer tunning value :
			 *  Wait 100msec until sync with MCU
			 */
			vTaskDelay(10);

#if defined ( __SUPPORT_ATCMD__ )

#define WLAN_REASON_PREV_AUTH_NOT_VALID             2
#define WLAN_REASON_DEAUTH_LEAVING                  3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY      4
#define WLAN_REASON_DISASSOC_AP_BUSY                5

			switch (wifi_disconn_reason) {
				case WLAN_REASON_PREV_AUTH_NOT_VALID :
					PRINTF_ATCMD("\r\n+WFDAP:0,AUTH_NOT_VALID\r\n"); break;
				case WLAN_REASON_DEAUTH_LEAVING :
					PRINTF_ATCMD("\r\n+WFDAP:0,DEAUTH\r\n"); break;
				case WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY :
					PRINTF_ATCMD("\r\n+WFDAP:0,INACTIVITY\r\n"); break;
				case WLAN_REASON_DISASSOC_AP_BUSY :
					PRINTF_ATCMD("\r\n+WFDAP:0,APBUSY\r\n"); break;
				default :
					PRINTF_ATCMD("\r\n+WFDAP:0,OTHER,%d\r\n", wifi_disconn_reason); break;
			}
#else
			PRINTF("\n### User Call-back : Wi-Fi disconnected ( reason_code = %d ) ...\n", wifi_disconn_reason);
#endif  // __SUPPORT_ATCMD__

			/* Clear event flag */
			xSemaphoreTake(wifi_conn_notify_mutex, 300);

			wifi_disconn_reason = 0;
			wifi_disconn_flag = FALSE;

			xSemaphoreGive(wifi_conn_notify_mutex);
        }

		/* loop time delay : 10 msec */
		vTaskDelay(1);
	}
}

#endif	// __SUPPORT_WIFI_CONN_CB__

/* EOF */
