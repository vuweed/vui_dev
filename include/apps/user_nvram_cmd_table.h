/**
 ****************************************************************************************
 *
 * @file user_nvram_cmd_table.h
 *
 * @brief Define for user NVRAM operation command table
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

#ifndef __USER_CONFIG_H__
#define	__USER_CONFIG_H__

#include "common_config.h"

/// NVRAM string value structure
typedef struct _user_conf_str {
	/// Parameter name (DA16X_USER_CONF_STR)
	int		id;
	/// NVRAM save name
	char	nvram_name[24];
	/// Maximum length of the string value
	int		max_length;
} user_conf_str;

/// NVRAM integer value structure
typedef struct _user_conf_int {
	/// Parameter name (DA16X_USER_CONF_INT)
	int		id;
	/// NVRAM save name
	char	nvram_name[24];
	/// Minimum value
	int min_value;
	/// Maximum value
	int max_value;
	/// Default value
	int def_value;
} user_conf_int;

/// User Configurations (for string value)
typedef enum {
	DA16X_CONF_STR_USER_START = DA16X_CONF_STR_MAX,
	DA16X_CONF_STR_TEST_PARAM,

#if defined (__SUPPORT_MQTT__)
	DA16X_CONF_STR_MQTT_BROKER_IP,
	DA16X_CONF_STR_MQTT_SUB_TOPIC,
	DA16X_CONF_STR_MQTT_SUB_TOPIC_ADD,
	DA16X_CONF_STR_MQTT_SUB_TOPIC_DEL,
	DA16X_CONF_STR_MQTT_PUB_TOPIC,
	DA16X_CONF_STR_MQTT_USERNAME,
	DA16X_CONF_STR_MQTT_PASSWORD,
	DA16X_CONF_STR_MQTT_WILL_TOPIC,
	DA16X_CONF_STR_MQTT_WILL_MSG,
	DA16X_CONF_STR_MQTT_SUB_CLIENT_ID,
	DA16X_CONF_STR_MQTT_PUB_CLIENT_ID,
#if defined (__MQTT_TLS_OPTIONAL_CONFIG__)
	DA16X_CONF_STR_MQTT_TLS_SNI,
#endif // __MQTT_TLS_OPTIONAL_CONFIG__
#endif // (__SUPPORT_MQTT__)

#if defined (__SUPPORT_ZERO_CONFIG__)
	DA16X_CONF_STR_ZEROCONF_MDNS_HOSTNAME,
#if defined (__SUPPORT_DNS_SD__)
	DA16X_CONF_STR_ZEROCONF_SRV_NAME,
	DA16X_CONF_STR_ZEROCONF_SRV_PROT,
	DA16X_CONF_STR_ZEROCONF_SRV_TXT,
#endif // (__SUPPORT_DNS_SD__)
#endif // (__SUPPORT_ZERO_CONFIG__)

#if defined (__SUPPORT_ATCMD_TLS__)
	DA16X_CONF_STR_ATCMD_TLSC_CA_CERT_NAME_0,
	DA16X_CONF_STR_ATCMD_TLSC_CA_CERT_NAME_1,
	DA16X_CONF_STR_ATCMD_TLSC_CERT_NAME_0,
	DA16X_CONF_STR_ATCMD_TLSC_CERT_NAME_1,
	DA16X_CONF_STR_ATCMD_TLSC_HOST_NAME_0,
	DA16X_CONF_STR_ATCMD_TLSC_HOST_NAME_1,
	DA16X_CONF_STR_ATCMD_TLSC_PEER_IPADDR_0,
	DA16X_CONF_STR_ATCMD_TLSC_PEER_IPADDR_1,
#endif // (__SUPPORT_ATCMD_TLS__)

	DA16X_CONF_STR_FINAL_MAX
} DA16X_USER_CONF_STR;

/// User Configurations (for integer value)
typedef enum {
	DA16X_CONF_INT_TEST_PARAM = DA16X_CONF_INT_MAX,

#if defined (__SUPPORT_MQTT__)
	DA16X_CONF_INT_MQTT_SUB,
	DA16X_CONF_INT_MQTT_PUB,
	DA16X_CONF_INT_MQTT_AUTO,
	DA16X_CONF_INT_MQTT_PORT,
	DA16X_CONF_INT_MQTT_QOS,
	DA16X_CONF_INT_MQTT_TLS,
	DA16X_CONF_INT_MQTT_WILL_QOS,
	DA16X_CONF_INT_MQTT_PING_PERIOD,
	DA16X_CONF_INT_MQTT_CLEAN_SESSION,
	DA16X_CONF_INT_MQTT_SAMPLE,
	DA16X_CONF_INT_MQTT_VER311,
	DA16X_CONF_INT_MQTT_TLS_INCOMING,
	DA16X_CONF_INT_MQTT_TLS_OUTGOING,
	DA16X_CONF_INT_MQTT_TLS_AUTHMODE,
#endif // (__SUPPORT_MQTT__)

#if defined (__SUPPORT_ZERO_CONFIG__)
	DA16X_CONF_INT_ZEROCONF_MDNS_REG,
#if defined (__SUPPORT_DNS_SD__)
	DA16X_CONF_INT_ZEROCONF_SRV_REG,
	DA16X_CONF_INT_ZEROCONF_SRV_PORT,
#endif // (__SUPPORT_DNS_SD__)
#endif // (__SUPPORT_ZERO_CONFIG__)

#if defined (__SUPPORT_ATCMD_TLS__)
	DA16X_CONF_INT_ATCMD_TLS_CID_0,
	DA16X_CONF_INT_ATCMD_TLS_CID_1,
	DA16X_CONF_INT_ATCMD_TLS_ROLE_0,
	DA16X_CONF_INT_ATCMD_TLS_ROLE_1,
	DA16X_CONF_INT_ATCMD_TLS_PROFILE_0,
	DA16X_CONF_INT_ATCMD_TLS_PROFILE_1,
	DA16X_CONF_INT_ATCMD_TLSC_INCOMING_LEN_0,
	DA16X_CONF_INT_ATCMD_TLSC_INCOMING_LEN_1,
	DA16X_CONF_INT_ATCMD_TLSC_OUTGOING_LEN_0,
	DA16X_CONF_INT_ATCMD_TLSC_OUTGOING_LEN_1,
	DA16X_CONF_INT_ATCMD_TLSC_AUTH_MODE_0,
	DA16X_CONF_INT_ATCMD_TLSC_AUTH_MODE_1,
	DA16X_CONF_INT_ATCMD_TLSC_LOCAL_PORT_0,
	DA16X_CONF_INT_ATCMD_TLSC_LOCAL_PORT_1,
	DA16X_CONF_INT_ATCMD_TLSC_PEER_PORT_0,
	DA16X_CONF_INT_ATCMD_TLSC_PEER_PORT_1,
#endif // (__SUPPORT_ATCMD_TLS__)

	DA16X_CONF_INT_FINAL_MAX
} DA16X_USER_CONF_INT;


int user_set_str(int name, char *value, int cache);
int user_set_int(int name, int value, int cache);
int user_get_str(int name, char *value);
int user_get_int(int name, int *value);

#endif	/* __USER_CONFIG_H__ */
