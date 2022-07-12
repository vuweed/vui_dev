/**
 ****************************************************************************************
 *
 * @file user_http_client.c
 *
 * @brief HTTP Client thread
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

#include "FreeRTOSConfig.h"

#include "lwip/apps/http_client.h"
#include "lwip/altcp_tcp.h"
#include "lwip/dns.h"
#include "lwip/debug.h"
#include "lwip/mem.h"
#include "lwip/altcp_tls.h"
#include "lwip/init.h"
#include "lwip/err.h"
#include "mbedtls/ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "command.h"
#include "command_net.h"
#include "common_def.h"
#include "common_uart.h"

#include "sdk_type.h"
#include "da16x_system.h"
#include "da16x_network_common.h"

#include "application.h"
#include "iface_defs.h"
#include "nvedit.h"
#include "environ.h"

#include "user_dpm.h"

#include "user_http_client.h"
#include "util_api.h"
#if defined (__SUPPORT_ATCMD__)
#include "atcmd.h"
#endif // (__SUPPORT_ATCMD__)

#undef ENABLE_HTTPC_DEBUG_INFO
#define ENABLE_HTTPC_DEBUG_ERR

#define	HTTPC_PRINTF			PRINTF

#if defined (ENABLE_HTTPC_DEBUG_INFO)
	#define	HTTPC_DEBUG_INFO(fmt, ...)	\
					HTTPC_PRINTF("[%s:%d]" fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
	#define	HTTPC_DEBUG_INFO(...)		do {} while (0)
#endif	// ENABLED_HTTPC_DEBUG_INFO

#if defined (ENABLE_HTTPC_DEBUG_ERR)
	#define	HTTPC_DEBUG_ERR(fmt, ...)	\
					HTTPC_PRINTF("[%s:%d]" fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
	#define	HTTPC_DEBUG_ERR(...)		do {} while (0)
#endif	// (ENABLED_HTTPC_DEBUG_ERR)

//variables
#if defined (__SUPPORT_ATCMD__)
static char atc_buf[3] = {0, };
#if defined (__ATCMD_IF_UART2__)
static int UART_IF_IDX = UART_UNIT_2;
#else
static int UART_IF_IDX = UART_UNIT_1;
#endif // (__ATCMD_IF_UART2__)
#endif // (__SUPPORT_ATCMD__)

static ip_addr_t server_addr;
static httpc_connection_t conn_settings = {0, };
static httpc_state_t *connection = NULL;
DA16_HTTP_CLIENT_CONF da16_http_client_conf = {HTTP_CLIENT_STATUS_READY, 0,};

TaskHandle_t g_http_client_xHandle = NULL;
static EventGroupHandle_t g_http_client_event;
#define EVENT_HTTPC_FINISH	0x01
#define EVENT_HTTPC_STOP	0x02
#define EVENT_HTTPC_RECV	0x04
#define EVENT_HTTPC_ALL		0xFF

static void http_client_clear_alpn(httpc_secure_connection_t *conf)
{
	int idx = 0;

	if (conf->alpn)
	{
		for (idx = 0 ; idx < conf->alpn_cnt ; idx++)
		{
			if (conf->alpn[idx])
			{
				vPortFree(conf->alpn[idx]);
				conf->alpn[idx] = NULL;
			}
		}

		vPortFree(conf->alpn);
	}

	conf->alpn = NULL;
	conf->alpn_cnt = 0;

	return ;
}

static void http_client_clear_https_conf(httpc_secure_connection_t *conf)
{
	if (conf)
	{
		if (conf->ca)
		{
			vPortFree(conf->ca);
		}

		if (conf->cert)
		{
			vPortFree(conf->cert);
		}

		if (conf->privkey)
		{
			vPortFree(conf->privkey);
		}

		if (conf->sni)
		{
			vPortFree(conf->sni);
		}

		http_client_clear_alpn(conf);

		memset(conf, 0x00, sizeof(httpc_secure_connection_t));

		conf->auth_mode = MBEDTLS_SSL_VERIFY_NONE;
		conf->incoming_len = HTTPC_DEF_INCOMING_LEN;
		conf->outgoing_len = HTTPC_DEF_OUTGOING_LEN;
	}

	return ;
}

static void http_client_copy_https_conf(httpc_secure_connection_t *dst,
										httpc_secure_connection_t *src)
{
	if (dst->alpn)
	{
		http_client_clear_alpn(dst);
	}

	memcpy(dst, src, sizeof(httpc_secure_connection_t));

	return ;
}

static err_t http_client_clear_request(DA16_HTTP_CLIENT_REQUEST *request)
{
	request->op_code = HTTP_CLIENT_OPCODE_READY;

	request->iface = WLAN0_IFACE;
	request->port = HTTP_SERVER_PORT;
	request->insecure = pdFALSE;

	memset(request->hostname, 0x00, HTTPC_MAX_HOSTNAME_LEN);
	memset(request->path, 0x00, HTTPC_MAX_PATH_LEN);
	memset(request->data, 0x00, HTTPC_MAX_REQ_DATA);
	memset(request->username, 0x00, HTTPC_MAX_NAME);
	memset(request->password, 0x00, HTTPC_MAX_PASSWORD);

	http_client_clear_https_conf(&request->https_conf);

	return ERR_OK;
}

UINT http_client_init_conf(DA16_HTTP_CLIENT_CONF *config)
{
	HTTPC_DEBUG_INFO("Init http client configuration\n");

	config->status = HTTP_CLIENT_STATUS_READY;

	return http_client_clear_request(&config->request);
}

err_t http_client_copy_request(DA16_HTTP_CLIENT_REQUEST *dst,
							   DA16_HTTP_CLIENT_REQUEST *src)
{
	memset(dst, 0x00, sizeof(DA16_HTTP_CLIENT_REQUEST));

	dst->op_code = src->op_code;

	dst->iface = src->iface;
	dst->port = src->port;
	dst->insecure = src->insecure;

	strcpy((char *)dst->hostname, (char *)src->hostname);
	strcpy((char *)dst->path, (char *)src->path);
	strcpy((char *)dst->data, (char *)src->data);
	strcpy((char *)dst->username, (char *)src->username);
	strcpy((char *)dst->password, (char *)src->password);

	http_client_copy_https_conf(&dst->https_conf, &src->https_conf);

	return ERR_OK;
}

err_t http_client_parse_request(int argc, char *argv[], DA16_HTTP_CLIENT_REQUEST *request)
{
	int index = 0;
	err_t err = ERR_OK;

	char **cur_argv = ++argv;

	unsigned int content_len = 0;
	unsigned int auth_mode = 0;
	unsigned int sni_len = 0;
	unsigned int alpn_len = 0;

	char alpn[HTTPC_MAX_ALPN_CNT][HTTPC_MAX_ALPN_LEN] = {0x00,};
	int alpn_cnt = 0;

	request->op_code = HTTP_CLIENT_OPCODE_READY;

	for (index = 1 ; index < argc ; index++, cur_argv++)
	{
		if (**cur_argv == '-')
		{
			//Parse options
			if (strcmp("-i", *cur_argv) == 0)
			{
				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set interface\n");
					return ERR_VAL;
				}

				++cur_argv;

				if (strcasecmp("WLAN0", *cur_argv) == 0)
				{
					request->iface = WLAN0_IFACE;
				}
				else if (strcasecmp("WLAN1", *cur_argv) == 0)
				{
					request->iface = WLAN1_IFACE;
				}
				else
				{
					return ERR_VAL;
				}
			}
			else if (strcmp("-head", *cur_argv) == 0)
			{
				if (request->op_code != HTTP_CLIENT_OPCODE_READY)
				{
					HTTPC_DEBUG_ERR("Invalid parameters\n");
					return ERR_VAL;
				}

				request->op_code = HTTP_CLIENT_OPCODE_HEAD;
			}
			else if (strcmp("-get", *cur_argv) == 0)
			{
				if (request->op_code != HTTP_CLIENT_OPCODE_READY)
				{
					HTTPC_DEBUG_ERR("Invalid parameters\n");
					return ERR_VAL;
				}

				request->op_code = HTTP_CLIENT_OPCODE_GET;
			}
			else if ((strcmp("-put", *cur_argv) == 0)
					 || (strcmp("-post", *cur_argv) == 0))
			{
				if (request->op_code != HTTP_CLIENT_OPCODE_READY)
				{
					HTTPC_DEBUG_ERR("Invalid parameters\n");
					return ERR_VAL;
				}

				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set resource of PUT request\n");
					return ERR_VAL;
				}

				if (strcmp("-put", *cur_argv) == 0)
				{
					request->op_code = HTTP_CLIENT_OPCODE_PUT;
				}
				else
				{
					request->op_code = HTTP_CLIENT_OPCODE_POST;
				}

				++cur_argv;

				if (strlen(*cur_argv) > HTTPC_MAX_REQ_DATA)
				{
					HTTPC_DEBUG_ERR("request data is too long(%ld)\n",
						   strlen(*cur_argv));
					return ERR_VAL;
				}

				strcpy((char *)request->data, *cur_argv);
			}
			else if (strcmp("-help", *cur_argv) == 0)
			{
				if (request->op_code != HTTP_CLIENT_OPCODE_READY)
				{
					HTTPC_DEBUG_ERR("Invalid parameters\n");
					return ERR_VAL;
				}

				request->op_code = HTTP_CLIENT_OPCODE_HELP;
			}
			else if (strcmp("-status", *cur_argv) == 0)
			{
				if (request->op_code != HTTP_CLIENT_OPCODE_READY)
				{
					HTTPC_DEBUG_ERR("Invalid parameters\n");
					return ERR_VAL;
				}

				request->op_code = HTTP_CLIENT_OPCODE_STATUS;
			}
			else if (strcmp("-stop", *cur_argv) == 0)
			{
				if (request->op_code != HTTP_CLIENT_OPCODE_READY)
				{
					HTTPC_DEBUG_ERR("Invalid parameters\n");
					return ERR_VAL;
				}

				request->op_code = HTTP_CLIENT_OPCODE_STOP;
			}
			else if (strcmp("-incoming", *cur_argv) == 0)
			{
				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set incoming length\r\n");
					return ERR_VAL;
				}

				++cur_argv;

				content_len = atoi(*cur_argv);
				if ((content_len >= HTTPC_MIN_INCOMING_LEN)
						&& (content_len <= HTTPC_MAX_INCOMING_LEN))
				{
					request->https_conf.incoming_len = content_len;
				}
				else
				{
					HTTPC_DEBUG_ERR("Invalid buffer length(%d)\r\n", content_len);
					return ERR_VAL;
				}
			}
			else if (strcmp("-outgoing", *cur_argv) == 0)
			{
				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set outgoing length\r\n");
					return ERR_VAL;
				}

				++cur_argv;

				content_len = atoi(*cur_argv);
				if ((content_len >= HTTPC_MIN_OUTGOING_LEN)
						&& (content_len <= HTTPC_MAX_OUTGOING_LEN))
				{
					request->https_conf.outgoing_len = content_len;
				}
				else
				{
					HTTPC_DEBUG_ERR("Invalid buffer length(%d)\r\n", content_len);
					return ERR_VAL;
				}
			}
			else if (strcmp("-authmode", *cur_argv) == 0)
			{
				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set authmode\r\n");
					return ERR_VAL;
				}

				++cur_argv;

				auth_mode = atoi(*cur_argv);
				if (auth_mode <= 2)
				{
					request->https_conf.auth_mode = auth_mode;
				}
				else
				{
					HTTPC_DEBUG_ERR("Invalid authmode(%d)\r\n", auth_mode);
					return ERR_VAL;
				}
			}
			else if (strcmp("-sni", *cur_argv) == 0)
			{
				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set sni\n");
					return ERR_ARG;
				}

				++cur_argv;

				sni_len = strlen(*cur_argv);

				if ((sni_len > 0) && (sni_len < HTTPC_MAX_SNI_LEN))
				{
					if (request->https_conf.sni)
					{
						vPortFree(request->https_conf.sni);
					}

					request->https_conf.sni = pvPortMalloc(sni_len + 1);
					if (!request->https_conf.sni)
					{
						HTTPC_DEBUG_ERR("Failed to allocate SNI(%ld)\n", sni_len);
						return ERR_MEM;
					}

					strcpy(request->https_conf.sni, *cur_argv);
					request->https_conf.sni_len = sni_len + 1;
				}
				else
				{
					HTTPC_DEBUG_ERR("Invalid SNI length(%ld)\n", sni_len);
					return ERR_ARG;
				}
			}
			else if (strcmp("-alpn", *cur_argv) == 0)
			{
				if (--argc < 1)
				{
					HTTPC_DEBUG_ERR("Failed to set alpn\n");
					return ERR_ARG;
				}

				++cur_argv;

				alpn_len = strlen(*cur_argv);

				if (alpn_cnt >= HTTPC_MAX_ALPN_CNT)
				{
					HTTPC_DEBUG_ERR("Overflow ALPN(%d)\n", HTTPC_MAX_ALPN_CNT);
					return ERR_ARG;
				}
				else if ((alpn_len) > 0 && (alpn_len < HTTPC_MAX_ALPN_LEN))
				{
					strcpy(alpn[alpn_cnt], *cur_argv);
					alpn_cnt++;
				}
				else
				{
					HTTPC_DEBUG_ERR("Invalid ALPN length(%ld)\n", alpn_len);
					return ERR_ARG;
				}
			}
			else
			{
				HTTPC_DEBUG_ERR("Invalid parameters(%s)\n", *cur_argv);
				return ERR_VAL;
			}
		}
		else
		{
			//Parse URI
			err = http_client_parse_uri((UCHAR *)*cur_argv, strlen((char *)*cur_argv), request);
			if (err != ERR_OK)
			{
				HTTPC_DEBUG_ERR("Failed to set URI\n");
				return err;
			}
		}
	}

	if (alpn_cnt > 0)
	{
		http_client_clear_alpn(&request->https_conf);

		request->https_conf.alpn = pvPortMalloc((alpn_cnt + 1) * sizeof(char *));
		if (!request->https_conf.alpn)
		{
			HTTPC_DEBUG_ERR("Failed to allocate ALPN\n");
			return ERR_MEM;
		}

		for (index = 0 ; index < alpn_cnt ; index++)
		{
			request->https_conf.alpn[index] = pvPortMalloc(strlen(alpn[index]));
			if (!request->https_conf.alpn[index])
			{
				HTTPC_DEBUG_ERR("Failed to allocate ALPN#%d\n", index + 1);
				http_client_clear_alpn(&request->https_conf);
				return ERR_MEM;
			}

			strcpy(request->https_conf.alpn[index], alpn[index]);

			request->https_conf.alpn_cnt++;
		}

		request->https_conf.alpn[index] = NULL;
	}

	if ((request->op_code == HTTP_CLIENT_OPCODE_READY)
			&& (strlen((char *)request->hostname) > 0))
	{
		request->op_code = HTTP_CLIENT_OPCODE_GET;
	}

	if ((request->op_code == HTTP_CLIENT_OPCODE_PUT)
		|| request->op_code == HTTP_CLIENT_OPCODE_POST)
	{
		if (strlen(request->data) <= 0)
		{
			return ERR_ARG;
		}
		err = httpc_insert_send_data((request->op_code == HTTP_CLIENT_OPCODE_PUT) ? "put":"post",
										request->data, strlen(request->data));
		if (err != ERR_OK)
		{
			HTTPC_DEBUG_ERR("Failed to insert data\n");
			return err;
		}
	}

	return err;
}


err_t http_client_execute_request(DA16_HTTP_CLIENT_CONF *config,
								  DA16_HTTP_CLIENT_REQUEST *request)
{
	if (request->op_code == HTTP_CLIENT_OPCODE_READY)
	{
		return ERR_ARG;
	}

	switch (request->op_code)
	{
		case HTTP_CLIENT_OPCODE_STATUS:
		{
			http_client_display_request(config, &config->request);
		} break;
		case HTTP_CLIENT_OPCODE_HELP:
		{
			http_client_display_usage();
		} break;
		case HTTP_CLIENT_OPCODE_STOP:
		{
			if (g_http_client_event)
			{
				xEventGroupSetBits(g_http_client_event, EVENT_HTTPC_STOP);
			}
		} break;
		default:
		{
			if (config->status == HTTP_CLIENT_STATUS_PROGRESS)
			{
				HTTPC_DEBUG_INFO("Http client is progressing previous request\n");
				return ERR_INPROGRESS;
			}
			http_client_copy_request(&config->request, request);
		} break;
	}

	return ERR_OK;
}


err_t http_client_parse_uri(unsigned char *uri, size_t len,
						DA16_HTTP_CLIENT_REQUEST *request)
{
	unsigned char *p = NULL;
	unsigned char *q = NULL;
	ULONG ip_addr = 0;
	ULONG dns_query_wait_option = 400;

	p = uri;
	if (*p == '/')
	{
		q = p;
		goto path;
	}

	q = (unsigned char *)"http";
	while (len && *q && tolower(*p) == *q)
	{
		++p;
		++q;
		--len;
	}

	if (*q)
	{
		HTTPC_DEBUG_ERR("invalid prefix(http)\n");
		goto error;
	}

	if (len && (tolower(*p) == 's'))
	{
		++p;
		--len;
		request->insecure = pdTRUE;
		request->port = HTTPS_SERVER_PORT;
	}
	else
	{
		request->insecure = pdFALSE;
		request->port = HTTP_SERVER_PORT;
	}

	q = (unsigned char *)"://";
	while (len && *q && tolower(*p) == *q)
	{
		++p;
		++q;
		--len;
	}

	if (*q)
	{
		HTTPC_DEBUG_ERR("invalid uri\n");
		goto error;
	}

	/* p points to beginning of Uri-Host */
	q = p;
	if (len && *p == '[')   /* IPv6 address reference */
	{
		//not supported ipv6
		HTTPC_DEBUG_ERR("Not supported IPv6\n");
		goto error;
	}
	else     /* IPv4 address or FQDN */
	{
		while (len && *q != ':' && *q != '/' && *q != '?')
		{
			*q = tolower(*q);
			++q;
			--len;
		}

		if (p == q)
		{
			HTTPC_DEBUG_ERR("invalid hostname\n");
			goto error;
		}

		memset(request->hostname, 0x00, HTTPC_MAX_HOSTNAME_LEN);
		memcpy(request->hostname, (const char *)p, q - p);
	}

	/* check for Uri-Port */
	if (len && *q == ':')
	{
		p = ++q;
		--len;

		while (len && isdigit(*q))
		{
			++q;
			--len;
		}

		if (p < q)   /* explicit port number given */
		{
			UINT port = 0;

			while (p < q)
			{
				port = port * 10 + (*p++ - '0');
			}

			request->port = port;
		}
	}

	/* at this point, p must point to an absolute path */
path:
	if (!len)
	{
		goto end;
	}

	if (*q == '/')
	{

		p = q;

		while (len)
		{
			++q;
			--len;
		}

		if (p < q)
		{
			memset(request->path, 0x00, HTTPC_MAX_PATH_LEN);
			memcpy(request->path, (const char *)p, q - p);
			p = q;
		}
	}

end:
	return len ? ERR_VAL : ERR_OK;

error:
	return ERR_VAL;
}

static err_t httpc_cb_headers_done_fn(httpc_state_t *connection, void *arg,
									  struct pbuf *hdr, u16_t hdr_len, u32_t content_len)
{
	err_t error = ERR_OK;
	unsigned char *tmp_buf = NULL;

	if (g_http_client_event)
		xEventGroupSetBits(g_http_client_event, EVENT_HTTPC_RECV);

	if ((hdr->payload != NULL) && (hdr->len > 0))
	{
#if defined (__SUPPORT_ATCMD__)
		puts_UART(UART_IF_IDX, hdr->payload, hdr_len);
#endif // (__SUPPORT_ATCMD__)
		HTTPC_PRINTF("\n<<hdr_len : %d, content_len : %d>>\n",
			   hdr_len, content_len);
		tmp_buf = pvPortMalloc(hdr_len+1);
		if (tmp_buf)
		{
			memset(tmp_buf, 0, hdr_len+1);
			memcpy(tmp_buf, hdr->payload, hdr_len);
			HTTPC_PRINTF("%s\n\n", tmp_buf);
			vPortFree(tmp_buf);
		}
	}
	else
	{
		HTTPC_DEBUG_ERR("\nFailed to receive http header!! \n");
		error = ERR_UNKNOWN;
	}

	return error;
}

static void httpc_cb_result_fn(void *arg, httpc_result_t httpc_result,
							   u32_t rx_content_len, u32_t srv_res, err_t err)
{

	if (g_http_client_event)
		xEventGroupSetBits(g_http_client_event, EVENT_HTTPC_STOP);

#if defined (__SUPPORT_ATCMD__)
	memset(atc_buf, 0, sizeof(atc_buf));
	sprintf(atc_buf, "%d", httpc_result);
	atcmd_asynchony_event(9, atc_buf); // ATC_EV_HTCSTATUS
#endif // (__SUPPORT_ATCMD__)

	HTTPC_PRINTF("\n[%s:%d]httpc_result: %d, received: %d byte, err: %d\r\n",
		   __func__, __LINE__, httpc_result, rx_content_len, err);

	return;
}

static err_t httpc_cb_recv_fn(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	err_t error = ERR_OK;

	if (g_http_client_event)
		xEventGroupSetBits(g_http_client_event, EVENT_HTTPC_RECV);

		if ((p->payload != NULL) && (p->len > 0))
		{
#if defined (__SUPPORT_ATCMD__)
			puts_UART(UART_IF_IDX, p->payload, p->len);
#endif // (__SUPPORT_ATCMD__)
			error = err;
			HTTPC_DEBUG_INFO("Receive length: %d\n", p->tot_len);
	}
	else
	{
		HTTPC_DEBUG_ERR("\nReceive data is NULL !! \n");
		error = ERR_BUF;
	}

	return error;
}

static int http_client_read_cert(unsigned int addr, unsigned char **out, size_t *outlen)
{
	int ret = 0;
	unsigned char *buf = NULL;
	size_t buflen = CERT_MAX_LENGTH;

	buf = pvPortMalloc(CERT_MAX_LENGTH);
	if (!buf)
	{
		HTTPC_DEBUG_ERR("Failed to allocate memory(%x)\r\n", addr);
		return -1;
	}

	memset(buf, 0x00, CERT_MAX_LENGTH);

	ret = cert_flash_read(addr, buf, CERT_MAX_LENGTH);
	if (ret == 0 && buf[0] != 0xFF)
	{
		*out = buf;
		*outlen = strlen(buf) + 1;
		return 0;
	}

	if (buf)
		vPortFree(buf);
	return 0;
}

static void http_client_read_certs(httpc_secure_connection_t *conf)
{
	int ret = 0;

	//to read ca certificate
	ret = http_client_read_cert(SFLASH_ROOT_CA_ADDR2, &conf->ca, &conf->ca_len);
	if (ret)
	{
		HTTPC_DEBUG_ERR("failed to read CA cert\r\n");
		goto err;
	}
	HTTPC_PRINTF("Read CA(length = %ld)\n", conf->ca_len);

	//to read certificate
	ret = http_client_read_cert(SFLASH_CERTIFICATE_ADDR2,
								&conf->cert, &conf->cert_len);
	if (ret)
	{
		HTTPC_DEBUG_ERR("failed to read certificate\r\n");
		goto err;
	}
	HTTPC_PRINTF("Read Cert(length = %ld)\n", conf->cert_len);

	//to read private key
	ret = http_client_read_cert(SFLASH_PRIVATE_KEY_ADDR2,
								&conf->privkey, &conf->privkey_len);
	if (ret)
	{
		HTTPC_DEBUG_ERR("failed to read private key\r\n");
		goto err;
	}
	HTTPC_PRINTF("Read Privkey(length = %ld)\n", conf->privkey_len);

	return ;

err:

	if (conf->ca) {
		vPortFree(conf->ca);
	}

	if (conf->cert) {
		vPortFree(conf->cert);
	}

	if (conf->privkey) {
		vPortFree(conf->privkey);
	}

	conf->ca = NULL;
	conf->ca_len = 0;
	conf->cert = NULL;
	conf->cert_len = 0;
	conf->privkey = NULL;
	conf->privkey_len = 0;

	return ;
}

static void http_client_process_request(void *arg)
{
	err_t error = ERR_OK;

    const int max_timeout = HTTPC_MAX_STOP_TIMEOUT;
    const int timeout = HTTPC_DEF_TIMEOUT;
    int cur_timeout = 0;

	DA16_HTTP_CLIENT_CONF *conf = (DA16_HTTP_CLIENT_CONF *)arg;
	DA16_HTTP_CLIENT_REQUEST *request = &(conf->request);
	ULONG events;

	unsigned int sni_len = 0;
	char *sni_str;
	int index = 0;
	int alpn_cnt = 0;

	HTTPC_DEBUG_INFO("Start of Task\r\n");

	// Initialize ...
	memset(&server_addr, 0, sizeof(ip_addr_t));
	memset(&conn_settings, 0, sizeof(httpc_connection_t));
	connection = NULL;

	conf->status = HTTP_CLIENT_STATUS_PROGRESS;

	if (!g_http_client_event)
	{
		g_http_client_event = xEventGroupCreate();
		if (g_http_client_event == NULL)
		{
			goto finish;
		}
	}

	conn_settings.use_proxy = 0;
	conn_settings.altcp_allocator = NULL;

	conn_settings.headers_done_fn = httpc_cb_headers_done_fn;
	conn_settings.result_fn = httpc_cb_result_fn;
	conn_settings.insecure = request->insecure;

	if (conn_settings.insecure)
	{
		memset(&conn_settings.tls_settings, 0x00, sizeof(httpc_secure_connection_t));

		http_client_read_certs(&request->https_conf);

		memcpy(&conn_settings.tls_settings, &request->https_conf,
			   sizeof(httpc_secure_connection_t));

		conn_settings.tls_settings.incoming_len = HTTPC_MAX_INCOMING_LEN;
		conn_settings.tls_settings.outgoing_len = HTTPC_DEF_OUTGOING_LEN;
		sni_str = read_nvram_string(HTTPC_NVRAM_CONFIG_TLS_SNI);
		if (sni_str != NULL)
		{
			sni_len = strlen(sni_str);

			if ((sni_len > 0) && (sni_len < HTTPC_MAX_SNI_LEN))
			{
				if (conn_settings.tls_settings.sni != NULL)
				{
					vPortFree(conn_settings.tls_settings.sni);
				}
				conn_settings.tls_settings.sni = pvPortMalloc(sni_len + 1);
				if (conn_settings.tls_settings.sni == NULL)
				{
					HTTPC_DEBUG_ERR("Failed to allocate SNI(%ld)\n", sni_len);
					goto finish;
				}
				strcpy(conn_settings.tls_settings.sni, sni_str);
				conn_settings.tls_settings.sni_len = sni_len + 1;
				HTTPC_PRINTF("ReadNVRAM SNI = %s\n", conn_settings.tls_settings.sni);
			}
		}

		if (read_nvram_int(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM, &alpn_cnt) == 0)
		{
			if (alpn_cnt > 0)
			{
				http_client_clear_alpn(&conn_settings.tls_settings);

				conn_settings.tls_settings.alpn = pvPortMalloc((alpn_cnt + 1) * sizeof(char *));
				if (!conn_settings.tls_settings.alpn)
				{
					HTTPC_DEBUG_ERR("Failed to allocate ALPN\n");
					goto finish;
	}

				for (index = 0 ; index < alpn_cnt ; index++)
				{
					char nvrName[15] = {0, };
					char *alpn_str;

					if (index >= HTTPC_MAX_ALPN_CNT)
						break;

					sprintf(nvrName, "%s%d", HTTPC_NVRAM_CONFIG_TLS_ALPN, index);
					alpn_str = read_nvram_string(nvrName);

					conn_settings.tls_settings.alpn[index] = pvPortMalloc(strlen(alpn_str)+1);
					if (!conn_settings.tls_settings.alpn[index])
					{
						HTTPC_DEBUG_ERR("Failed to allocate ALPN#%d(len=%d)\n", index + 1, strlen(alpn_str));
						http_client_clear_alpn(&conn_settings.tls_settings);
						goto finish;
					}

					conn_settings.tls_settings.alpn_cnt = index + 1;
					strcpy(conn_settings.tls_settings.alpn[index], alpn_str);
					HTTPC_PRINTF("ReadNVRAM ALPN#%d = %s\n",
							conn_settings.tls_settings.alpn_cnt,
							conn_settings.tls_settings.alpn[index]);
				}
				conn_settings.tls_settings.alpn[index] = NULL;
			}
		}
	}

	if (isvalidip((char *)request->hostname))
	{
		ip4addr_aton(request->hostname, &server_addr);

		error = httpc_get_file(&server_addr, request->port, &request->path[0],
							   &conn_settings, (altcp_recv_fn)httpc_cb_recv_fn,
							   NULL, &connection);
	}
	else
	{
		error = httpc_get_file_dns(&request->hostname[0], request->port, &request->path[0],
								   &conn_settings, (altcp_recv_fn)httpc_cb_recv_fn,
								   NULL, &connection);
	}
	if (error != ERR_OK)
	{
		HTTPC_DEBUG_ERR("Request Error (%d)\r\n", error);
	}
	else
	{
		while (cur_timeout < max_timeout)
		{
		events = xEventGroupWaitBits(g_http_client_event,
									 EVENT_HTTPC_ALL,
									 pdTRUE,
									 pdFALSE,
									 timeout);

		HTTPC_DEBUG_INFO("Recevied Event(0x%x)\r\n", events);

		if (events & EVENT_HTTPC_FINISH)
		{
			break;
		}
		else if (events & EVENT_HTTPC_STOP)
		{
			break;
		}
		else if (events & EVENT_HTTPC_RECV)
		{
			cur_timeout = 0;
		}

		cur_timeout += timeout;
		}
	}

finish:

	http_client_clear_request(request);

	conf->status = HTTP_CLIENT_STATUS_WAIT;

	HTTPC_DEBUG_INFO("End of Task\r\n");

	if (g_http_client_event)
	{
		vEventGroupDelete(g_http_client_event);
		g_http_client_event = NULL;
	}

	g_http_client_xHandle = NULL;
	vTaskDelete(NULL);

	return;
}

err_t http_client_set_sni(int argc, char *argv[])
{
	char *tmp_str;

	if ((argc == 2 && argv[1][0] == '?') || argc == 1)
	{
		tmp_str = read_nvram_string(HTTPC_NVRAM_CONFIG_TLS_SNI);
		if (tmp_str)
			HTTPC_PRINTF("%s = %s\n",HTTPC_NVRAM_CONFIG_TLS_SNI, tmp_str);
	}
	else if (argc == 2)
	{
		if (strcmp(argv[1], "-delete") == 0)
		{
			delete_nvram_env(HTTPC_NVRAM_CONFIG_TLS_SNI);
			return ERR_OK;
		}

		if (strlen(argv[1]) > HTTPC_MAX_SNI_LEN)
		{
			return ERR_ARG;
		}
		else
		{
			if (write_nvram_string(HTTPC_NVRAM_CONFIG_TLS_SNI, argv[1]))
				return ERR_ARG;
		}
	}
	else
	{
		return ERR_UNKNOWN;
	}
	return ERR_OK;
}
err_t http_client_set_alpn(int argc, char *argv[])
{
	int	result_int;
	int alpn_num = 0;
	char *tmp_str;

	if ((argc == 2 && argv[1][0] == '?') || argc == 1)
	{
		/* AT+NWHTCALPN=? */
		if (read_nvram_int(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM, &result_int))
		{
			return ERR_VAL;
		}
		else
		{
			//char* result_str_pos;

			if (result_int >= 1)
			{
				for (int i = 0; i < result_int; i++)
				{
					char nvrName[15] = {0, };
					//char *tmp_str;
					sprintf(nvrName, "%s%d", HTTPC_NVRAM_CONFIG_TLS_ALPN, i);
					tmp_str = read_nvram_string(nvrName);
					HTTPC_PRINTF("%s = %s\n", nvrName, tmp_str);
				}
			}
		}
	}
	else if (argc >= 2)
	{
		int tmp;

		if (strcmp(argv[1], "-delete") == 0)
		{
			if (!read_nvram_int(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM, &tmp))
			{
				for (int i = 0; i < tmp; i++)
				{
					char nvr_name[15] = {0, };
					sprintf(nvr_name, "%s%d", HTTPC_NVRAM_CONFIG_TLS_ALPN, i);
					delete_nvram_env(nvr_name);
				}
				delete_nvram_env(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM);
			}
			return ERR_OK;
		}

		alpn_num = atoi(argv[1]);
		if (alpn_num > HTTPC_MAX_ALPN_CNT || alpn_num <= 0)
			return ERR_ARG;

		for (int i = 0; i < alpn_num; i++)
		{
			if ((strlen(argv[i + 2]) > HTTPC_MAX_ALPN_LEN)
				|| (strlen(argv[i + 2]) <= 0))
			{
				return ERR_ARG;
			}
		}

		if (!read_nvram_int(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM, &tmp))
		{
			for (int i = 0; i < tmp; i++)
			{
				char nvr_name[15] = {0, };
				sprintf(nvr_name, "%s%d", HTTPC_NVRAM_CONFIG_TLS_ALPN, i);
				delete_nvram_env(nvr_name);
			}
			delete_nvram_env(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM);
		}

		for (int i = 0; i < alpn_num; i++)
		{
			char nvr_name[15] = {0, };
			sprintf(nvr_name, "%s%d", HTTPC_NVRAM_CONFIG_TLS_ALPN, i);
			write_nvram_string(nvr_name, argv[i + 2]);
		}
		write_nvram_int(HTTPC_NVRAM_CONFIG_TLS_ALPN_NUM, alpn_num);

	}
	else
	{
		return ERR_UNKNOWN;
	}
	return ERR_OK;
}
err_t run_user_http_client(int argc, char *argv[])
{
	err_t err = ERR_OK;
	BaseType_t	xReturned;
	DA16_HTTP_CLIENT_REQUEST request = {0x00,};

	if (argc <= 1)
	{
		http_client_display_usage();
		return ERR_ARG;
	}

	http_client_clear_request(&request);

	if (da16_http_client_conf.status == HTTP_CLIENT_STATUS_READY)
	{
		http_client_init_conf(&da16_http_client_conf);
	}

	err = http_client_parse_request(argc, argv, &request);
	if (err != ERR_OK)
	{
		http_client_display_usage();
		goto err;
	}

#if defined (ENABLE_HTTPC_DEBUG_INFO)
	http_client_display_request(&da16_http_client_conf, &request);
#endif	// (ENABLE_HTTPC_DEBUG_INFO)

	err = http_client_execute_request(&da16_http_client_conf, &request);
	if (err != ERR_OK)
	{
		goto err;
	}

	xReturned = xTaskCreate(http_client_process_request,
							HTTPC_XTASK_NAME,
							HTTPC_STACK_SZ,
							&da16_http_client_conf,
							tskIDLE_PRIORITY + 1,
							&g_http_client_xHandle);
	if (xReturned != pdPASS)
	{
		HTTPC_DEBUG_ERR(RED_COLOR "Failed task create %s\r\n" CLEAR_COLOR, "HttpClient");
		err = ERR_ARG;
		goto err;
	}

	return ERR_OK;

err:

	http_client_clear_request(&request);

	return err;
}

void http_client_display_usage(void)
{
	HTTPC_PRINTF("\nUsage: HTTP Client\n");
	HTTPC_PRINTF("\x1b[93mName\x1b[0m\n");
	HTTPC_PRINTF("\thttp-client - HTTP Client\n");
	HTTPC_PRINTF("\x1b[93mSYNOPSIS\x1b[0m\n");
	HTTPC_PRINTF("\thttp-client [OPTION]...URL\n");
	HTTPC_PRINTF("\x1b[93mDESCRIPTION\x1b[0m\n");
	HTTPC_PRINTF("\tRequest client's method to URL\n");

	HTTPC_PRINTF("\t\x1b[93m-i [wlan0|wlan1]\x1b[0m\n");
	HTTPC_PRINTF("\t\tSet interface of HTTP Client\n");
	HTTPC_PRINTF("\t\x1b[93m-status\x1b[0m\n");
	HTTPC_PRINTF("\t\tDisplay status of HTTP Client\n");
	HTTPC_PRINTF("\t\x1b[93m-help\x1b[0m\n");
	HTTPC_PRINTF("\t\tDisplay help\n");

	HTTPC_PRINTF("\t\x1b[93m-head\x1b[0m\n");
	HTTPC_PRINTF("\t\tRequest HEAD method to URI\n");
	HTTPC_PRINTF("\t\x1b[93m-get\x1b[0m\n");
	HTTPC_PRINTF("\t\tRequest GET method to URI\n");
	HTTPC_PRINTF("\t\x1b[93m-post RESOURCE\x1b[0m\n");
	HTTPC_PRINTF("\t\tRequest POST method to URI with RESOURCE\n");
	HTTPC_PRINTF("\t\x1b[93m-put RESOURCE\x1b[0m\n");
	HTTPC_PRINTF("\t\tRequest PUT method to URI with RESOURCE\n");

	HTTPC_PRINTF("\t\x1b[93m-incoming Size\x1b[0m\n");
	HTTPC_PRINTF("\t\tSet incoming buffer size of TLS Contents\n");
	HTTPC_PRINTF("\t\x1b[93m-outgoing Size\x1b[0m\n");
	HTTPC_PRINTF("\t\tSet outgoing buffer size of TLS Contents\n");
	HTTPC_PRINTF("\t\x1b[93m-sni <Server Name Indicator>\x1b[0m\n");
	HTTPC_PRINTF("\t\tSet SNI for TLS extension\n");
	HTTPC_PRINTF("\t\x1b[93m-alpn <ALPN Protocols>\x1b[0m\n");
	HTTPC_PRINTF("\t\tSet ALPN for TLS extension\n");
	return ;
}

void http_client_display_request(DA16_HTTP_CLIENT_CONF *config,
								 DA16_HTTP_CLIENT_REQUEST *request)
{
	HTTPC_PRINTF("\n%-30s\n", "***** HTTP Client Requst *****");

	HTTPC_PRINTF("\n%-30s:", "HTTP Client Status");
	if (config->status == HTTP_CLIENT_STATUS_READY)
	{
		HTTPC_PRINTF("\t%s\n", "Ready");
	}
	else if (config->status == HTTP_CLIENT_STATUS_WAIT)
	{
		HTTPC_PRINTF("\t%s\n", "Wait");
	}
	else if (config->status == HTTP_CLIENT_STATUS_PROGRESS)
	{
		HTTPC_PRINTF("\t%s\n", "Progress");
	}
	else
	{
		HTTPC_PRINTF("\t%s(%d)\n", "Unknown", config->status);
	}
#if 0
	HTTPC_PRINTF("%-30s:", "Operation Status");
	if (config->http_client.nx_http_client_state == NX_HTTP_CLIENT_STATE_READY)
	{
		HTTPC_PRINTF("\t%s\n", "Ready");
	}
	else if (config->http_client.nx_http_client_state == NX_HTTP_CLIENT_STATE_GET)
	{
		HTTPC_PRINTF("\t%s\n", "GET");
	}
	else if (config->http_client.nx_http_client_state == NX_HTTP_CLIENT_STATE_PUT)
	{
		HTTPC_PRINTF("\t%s\n", "PUT");
	}
	else
	{
		HTTPC_PRINTF("\t%s(0x%02x)\n", "Unknown",
					 config->http_client.nx_http_client_state);
	}
#endif
	HTTPC_PRINTF("%-30s:", "Interface");
	if (request->iface == WLAN0_IFACE)
	{
		HTTPC_PRINTF("\t%s\n", "wlan0");
	}
	else if (request->iface == WLAN1_IFACE)
	{
		HTTPC_PRINTF("\t%s\n", "wlan1");
	}
	else
	{
		HTTPC_PRINTF("\t%s(%d)\n", "Unknown", request->iface);
	}
#if 0
	HTTPC_PRINTF("%-30s:\t%d.%d.%d.%d(%d)\n",
				 "HTTP Server IP Address",
				 ((request->ip_addr.nxd_ip_address.v4 >> 24) & 0x0ff),
				 ((request->ip_addr.nxd_ip_address.v4 >> 16) & 0x0ff),
				 ((request->ip_addr.nxd_ip_address.v4 >> 8) & 0x0ff),
				 ((request->ip_addr.nxd_ip_address.v4 >> 0) & 0x0ff),
				 request->port);
#endif
	if (strlen((char *)request->hostname))
	{
		HTTPC_PRINTF("%-30s:\t%s\n", "Host Name", request->hostname);
	}

	if (strlen((char *)request->username))
	{
		HTTPC_PRINTF("%-30s:\t%s\n", "User Name", request->username);
	}

	if (strlen((char *)request->password) > 0)
	{
		HTTPC_PRINTF("%-30s:\t%s\n", "User Password", request->password);
	}

	if (strlen((char *)request->path))
	{
		HTTPC_PRINTF("%-30s:\t%s\n", "Path", request->path);
	}

	if (strlen((char *)request->data))
	{
		HTTPC_PRINTF("%-30s:\t%s\n", "Data", request->data);
	}

	HTTPC_PRINTF("%-30s:\t%s\n", "Secure", request->insecure ? "Yes" : "No");
	HTTPC_PRINTF("%-30s:\t%d\n", "Incoming buffer length", request->https_conf.incoming_len);
	HTTPC_PRINTF("%-30s:\t%d\n", "Outgoing buffer length", request->https_conf.outgoing_len);
	HTTPC_PRINTF("%-30s:\t%d\n", "Auth Mode", request->https_conf.auth_mode);
	if (request->https_conf.sni_len)
	{
		HTTPC_PRINTF("%-30s:\t%s(%ld)\n", "SNI", request->https_conf.sni,
					 strlen(request->https_conf.sni));
	}
	if (request->https_conf.alpn_cnt)
	{
		HTTPC_PRINTF("%-30s:\t%ld\n", "ALPN", request->https_conf.alpn_cnt);
		for (int idx = 0 ; idx < request->https_conf.alpn_cnt ; idx++)
		{
			HTTPC_PRINTF("\t* %s(%ld)\n", request->https_conf.alpn[idx],
						 strlen(request->https_conf.alpn[idx]));
		}
	}

	HTTPC_PRINTF("%-30s:", "Op code");
	switch (request->op_code)
	{
		case HTTP_CLIENT_OPCODE_READY:
		{
			HTTPC_PRINTF("\t%s\n", "READY");
		} break;
		case HTTP_CLIENT_OPCODE_HEAD:
		{
			HTTPC_PRINTF("\t%s\n", "HEAD");
		} break;
		case HTTP_CLIENT_OPCODE_GET:
		{
			HTTPC_PRINTF("\t%s\n", "GET");
		} break;
		case HTTP_CLIENT_OPCODE_PUT:
		{
			HTTPC_PRINTF("\t%s\n", "PUT");
		} break;
		case HTTP_CLIENT_OPCODE_POST:
		{
			HTTPC_PRINTF("\t%s\n", "POST");
		} break;
		case HTTP_CLIENT_OPCODE_DELETE:
		{
			HTTPC_PRINTF("\t%s\n", "DELETE");
		} break;
		case HTTP_CLIENT_OPCODE_STATUS:
		{
			HTTPC_PRINTF("\t%s\n", "STATUS");
		} break;
		case HTTP_CLIENT_OPCODE_HELP:
		{
			HTTPC_PRINTF("\t%s\n", "HELP");
		} break;
		case HTTP_CLIENT_OPCODE_STOP:
		{
			HTTPC_PRINTF("\t%s\n", "STOP");
		} break;
		default:
		{
			HTTPC_PRINTF("\t%s(%d)\n", "Unknown", request->op_code);
		} break;
	}
	return ;
}


/* EOF */
