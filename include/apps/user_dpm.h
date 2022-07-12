/**
 ****************************************************************************************
 *
 * @file user_dpm.h
 *
 * @brief Definition for User DPM feature.
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

#ifndef __USER_DPM_H__
#define	__USER_DPM_H__

#include "sdk_type.h"
#include "FreeRTOSConfig.h"
#include "da16x_types.h"

#define	WAIT_DPM_SLEEP				0
#define	RUN_DPM_SLEEP				1
#define	DONE_DPM_SLEEP				2

#define	DPM_OK						0
#define	DPM_REG_OK					0
#define	DPM_SET_OK					0

#define	DPM_REG_ERR					-1
#define	DPM_SET_ERR					-2
#define	DPM_SET_ERR_BLOCK			-9

#define	DPM_NOT_DPM_MODE			7777
#define	DPM_NOT_REGISTERED			8888
#define	DPM_REG_DUP_NAME			9999

#define	DPM_MAX_TCP_SESS			8

#define REG_NAME_DPM_MAX_LEN		20
#define DPM_TIMER_NAME_MAX_LEN		8

#define	FUNC_ERROR					100
#define FUNC_STATUS					200

#define STATUS_WAKEUP				(FUNC_STATUS + 1)
#define STATUS_POR					(FUNC_STATUS + 2)


enum USER_DPM_TID {
	TID_U_USER_WAKEUP = 2,
	TID_U_DHCP_CLIENT,
	TID_U_ABNORMAL
};

//__CHK_DPM_ABNORM_STS__ - Start
#define	DPM_UNDEFINED			0x000000
#define	DPM_UC					0x000001 /* UC */
#define	DPM_BC_MC				0x000002 /* BC/MC */
#define	DPM_BCN_CHANGED			0x000004
#define DPM_NO_BCN				0x000008
#define	DPM_FROM_FAST			0x000010
#define	DPM_KEEP_ALIVE_NO_ACK	0x000020
#define	DPM_FROM_KEEP_ALIVE		0x000040
#define	DPM_NO					0x000080
#define	DPM_UC_MORE				0x000200 /* UC more */
#define	DPM_AP_RESET			0x000400
#define	DPM_DEAUTH				0x000800
#define	DPM_DETECTED_STA		0x001000
#define	DPM_FROM_FULL			0x002000
#define DPM_USER0               0x080000
#define DPM_USER1               0x100000

/////////////////////////////////////////////////////////////////////////////
/// DA16X DPM Structures   ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

#define	DPM_ETH_ALEN			6
#define	DPM_MAX_SSID_LEN		32
#define	DPM_MAX_WEP_KEY_LEN		16
#define	DPM_PSK_LEN				32

/// Global network information for DPM operation
typedef  struct {
	/* for Network Instances */
	char	net_mode;

	/* for da16x Supplicant */
	char	wifi_mode;
	char	country[4];

	char	reserve_1[2];
} user_dpm_supp_net_info_t;

/// Global IP address information for DPM operation
typedef  struct {
	/// DPM dhcp xid
	long	dpm_dhcp_xid;

	/// DPM IP address
	ULONG	dpm_ip_addr;

	/// DPM IP address Netmask
	ULONG	dpm_netmask;

	/// DPM Gateway address
	ULONG	dpm_gateway;

	/// DPM DNS server address
	ULONG	dpm_dns_addr[2];

	/// DPM DHCP Client Lease timeout
	LONG	dpm_lease;

	/// DPM DHCP Client renew timeout
	LONG	dpm_renewal;

	/// DPM DHCP Client operation timeout
	ULONG	dpm_timeout; //dpm_rebind

	/// DPM DHCP Client renew Server IP address
	ULONG	dpm_dhcp_server_ip;
} user_dpm_supp_ip_info_t;

typedef  struct {
	int		mode;
	int		disabled;

	int		id;
	int		ssid_len;
	int		scan_ssid;
	int		psk_set;
	int		auth_alg;
	unsigned char	bssid[DPM_ETH_ALEN];	// 6
	unsigned char	reserved[2]; // Padding 2bytes
	unsigned char	ssid[DPM_MAX_SSID_LEN];	// 32
	unsigned char	psk[DPM_PSK_LEN];		// 32

#if defined ( DEF_SAVE_DPM_WIFI_MODE )
 	int 	wifi_mode;
	int 	dpm_opt;

#ifdef __SUPPORT_IEEE80211W__
	unsigned char	pmf;
	unsigned char	reserved_2[3]; // Padding 3bytes
#else
	unsigned char	reserved_2[4]; // 4bytes
#endif // __SUPPORT_IEEE80211W__

#else	/////////////////////////////////

#ifdef __SUPPORT_IEEE80211W__
	unsigned char	pmf;
	unsigned char	reserved_2[11]; // Padding 3bytes + 9bytes
#else
	unsigned char	reserved_2[12]; // 12bytes
#endif // __SUPPORT_IEEE80211W__
#endif	// DEF_SAVE_DPM_WIFI_MODE
} user_dpm_supp_conn_info_t;

#define WPA_KCK_MAX_LEN 32
#define WPA_KEK_MAX_LEN 64
#define WPA_TK_MAX_LEN  32

typedef	 struct{
	int		wpa_alg;
	int		key_idx;
	int		set_tx;
	UCHAR	seq[6];
	int		seq_len;
	UCHAR	ptk_kck[WPA_KCK_MAX_LEN]; /* EAPOL-Key Key Confirmation Key (KCK) */
	UCHAR	ptk_kek[WPA_KEK_MAX_LEN]; /* EAPOL-Key Key Encryption Key (KEK) */
	UCHAR	ptk_tk1[WPA_TK_MAX_LEN]; /* Temporal Key 1 (TK1) */
	int		key_len;
} user_cipher_ptk_t;

typedef	 struct{
	int		wpa_alg;
	int		key_idx;
	int		set_tx;
	UCHAR	seq[6];
	int		seq_len;
	UCHAR	gtk[32];
	int		key_len;
} user_cipher_gtk_t;

typedef	 struct {
	int		proto;
	int		key_mgmt;
	int		pairwise_cipher;
	int		group_cipher;

	UCHAR	wep_key_len;
	UCHAR	wep_tx_keyidx;
	UCHAR	wep_key[DPM_MAX_WEP_KEY_LEN];

	user_cipher_ptk_t ptk;
	user_cipher_gtk_t gtk;

	UCHAR	reserve_1[8];
} user_dpm_supp_key_info_t;


/////////////////////////////////////////////////////////////////////////////
/// DA16200 USER API function     ///////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////


extern int	chk_retention_mem_exist(void);

extern void	enable_dpm_mode(void);
extern void	disable_dpm_mode(void);
extern int	chk_dpm_mode(void);
extern int	get_dpm_mode(void);

extern void	enable_dpm_wakeup(void);
extern void	disable_dpm_wakeup(void);
extern int	chk_dpm_wakeup(void);

extern unsigned int current_usec_count(void);

extern void	show_dpm_sleep_info(void);
extern int	chk_dpm_reg_state(char *mod_name);
extern int	chk_dpm_set_state(char *mod_name);
extern char	*chk_dpm_reg_port(UINT port_number);
extern int	chk_dpm_pdown_start(void);

extern int	reg_dpm_sleep(char *mod_name, UINT port_number);
extern void unreg_dpm_sleep(char *mod_name);
extern int	set_dpm_sleep(char *mod_name);
extern int	clr_dpm_sleep(char *mod_name);
extern int	set_dpm_rcv_ready(char *mod_name);
extern int	set_dpm_rcv_ready_by_port(unsigned int port);

extern void	start_dpm_sleep_daemon(int val);
extern void	set_da16x_dpm_data_dpm_timeout(int val);

extern void	*get_supp_net_info_ptr(void);
extern void	*get_supp_ip_info_ptr(void);
extern void	*get_supp_conn_info_ptr(void);
extern void	*get_supp_key_info_ptr(void);
extern void	*get_rtc_timer_ops_ptr(void);

extern int	rtc_register_timer(UINT secs,
								char *name,
								int timer_id,
								int peri,
								void (* callback_func)(char *timer_name));
extern int	rtc_cancel_timer(int timer_id);
extern void	rtc_timer_list_info(void);
extern int	rtc_timer_info(int tid);
extern int	rtc_register_timer_test(int timer_id, UINT secs, int peri);
extern int	set_dpm_init_done(char *mod_name);

extern int	chk_dpm_sleepd_hold_state(void);
extern void	hold_dpm_sleepd(void);
extern void	resume_dpm_sleepd(void);

extern void	init_dpm_environment(void);
extern void	reset_dpm_info(void);

extern void	set_dpm_keepalive_config(int duration);
extern int	get_dpm_keepalive_config(void);
extern void	set_systimeoffset_to_rtm(unsigned long long offset);
extern unsigned long long get_systimeoffset_from_rtm(void);

extern void		set_rtc_oldtime_to_rtm(unsigned long long time);
extern unsigned long long get_rtc_oldtime_from_rtm(void);

extern void		set_rtc_offset_to_rtm(unsigned long long offset);
extern unsigned long long get_rtc_offset_from_rtm(void);

extern void		set_timezone_to_rtm(long timezone);
extern ULONG	get_timezone_from_rtm(void);

extern void		set_sntp_use_to_rtm(UINT use);
extern UINT		get_sntp_use_from_rtm(void);

extern void		set_sntp_period_to_rtm(long period);
extern ULONG	get_sntp_period_from_rtm(void);

extern void		set_sntp_timeout_to_rtm(ULONG timezone);
extern ULONG	get_sntp_timeout_from_rtm(void);

extern int		get_supp_conn_state(void);
extern int		chk_supp_connected(void);

#if 0	/* F_F_S */
extern int		dpm_save_tcp_sess(NX_TCP_SOCKET *tcp_sock);
extern void		dpm_clr_tcp_sess(NX_TCP_SOCKET *tcp_sock, char *tcp_sess_name);
extern UINT		dpm_restore_tcp_sess(NX_TCP_SOCKET *tcp_sock, UINT port, NX_IP *ip_ptr, char *tcp_sess_name);
extern NX_TCP_SOCKET	*dpm_get_new_tcp_sock_addr(char *tcp_sess_name);
extern NX_TCP_SOCKET 	*get_assigned_tcp_sock_addr(char *tcp_sess_name);
#endif

extern void		clr_all_dpm_tcp_sess_info(void);
extern void		clr_all_dpm_tcp_ka_info(void);
extern void		set_dpm_tcp_ka_info(char *tcp_sess_name, UINT rtc_timer_id);
extern int		get_dpm_tcp_ka_info(char *tcp_sess_name);
extern void		dpm_clr_tcp_ka_info(char *tcp_sess_name, UINT rtc_timer_id);

extern void		dpm_set_mdns_info(const char *hostname, size_t len);
extern int		dpm_get_mdns_info(char *hostname);
extern void		dpm_clear_mdns_info(void);

extern UCHAR	*get_da16x_dpm_dns_cache(void);
extern unsigned char *get_da16x_dpm_mdns_ptr(void);
extern unsigned char *get_da16x_dpm_arp_ptr(void);

extern unsigned int dpm_user_rtm_allocate(char *name, void **memory_ptr, unsigned long memory_size, unsigned long wait_option);
extern unsigned int dpm_user_rtm_release(char *name);
extern unsigned int dpm_user_rtm_get(char *name, unsigned char **data);

extern void		set_dpm_tim_wakeup_dur(UINT dtim_period , int flag);
extern void		set_dpm_mc_filter(ULONG mc_addr);
extern void		set_dpm_udp_port_filter(unsigned short d_port);
extern int		set_dpm_TIM_wakeup_time_to_nvram(int sec);
extern void		set_dpm_bcn_wait_timeout(unsigned int msec);
extern void		set_dpm_nobcn_check_step(int step);

extern void		dpm_user_timer_list_print(void);
extern int		dpm_user_timer_get_remaining_secs(char *thread_name, char *timer_name);
extern int		dpm_user_timer_delete(char *thread_name, char *timer_name);
extern int		dpm_user_timer_delete_all(UINT level);
extern int		dpm_user_timer_change(char *thread_name, char *timer_name, UINT secs);
extern int		dpm_user_timer_create(char *thread_name, char *timer_name, void (* callback_func)(char *timer_name), unsigned int secs, unsigned int reschedule_secs);

extern UCHAR	get_last_abnormal_act(void);


#ifdef __SUPPORT_DPM_DBG_CMD__
extern void	set_dpm_dbg_level(unsigned int level);
#endif /* __SUPPORT_DPM_DBG_CMD__ */



/* Global APIs */

/**
 *********************************************************************************
 * @brief       Display User RTM (Retention Memory) usage
 * @return      None
 *********************************************************************************
 */
void	show_rtm_for_app(void);


/**
 *********************************************************************************
 * @brief       Display DHCP Client RTM (Retention Memory) usage
 * @return      None
 *********************************************************************************
 */
void	print_rtm_dhcpc_info(void);


/**
 *********************************************************************************
 * @brief       Check wakeup state is Abnormal-Wakeup when DPM wakeup
 * @return      0 when Abnormal-wakeup, 1 other wakeup
 *********************************************************************************
 */
int chk_abnormal_wakeup(void);


//
//////////////////////////////////////////////////////////////////////


#endif	/* __USER_DPM_H__ */

/* EOF */
