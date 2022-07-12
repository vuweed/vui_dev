/**
 ****************************************************************************************
 *
 * @file user_dpm_api.h
 *
 * @brief Defined User DPM API.
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


#ifndef __USER_DPM_API_H__
#define	__USER_DPM_API_H__

#include "da16x_types.h"

/*
 * Global extern functions
 */
extern void	enable_dpm_mode(void);
extern void	disable_dpm_mode(void);
extern int	chk_dpm_mode(void);
extern int	chk_dpm_wakeup(void);
extern int	chk_dpm_pdown_start(void);
extern void	fc80211_da16x_pri_pwr_down(unsigned char retention);
extern void	fc80211_da16x_sec_pwr_down(unsigned long long usec, unsigned char retention);
extern int	dpm_get_wakeup_source(void);
extern int	da16x_get_dpm_wakeup_type(void);

extern int	reg_dpm_sleep(char *mod_name, unsigned int port_number);
extern void	unreg_dpm_sleep(char *mod_name);
extern int	set_dpm_sleep(char *mod_name);
extern int	clr_dpm_sleep(char *mod_name);
extern int	set_dpm_init_done(char *mod_name);

extern UINT	dpm_user_rtm_allocate(char *name, void **memory_ptr, unsigned long memory_size, unsigned long wait_option);
extern UINT	dpm_user_rtm_release(char *name);
extern UINT	dpm_user_rtm_get(char *name, unsigned char **data);

extern int	rtc_register_timer(unsigned int secs, char *name, int timer_id, int peri, void (* callback_func)(char *timer_name));
extern int	rtc_cancel_timer(int timer_id);

#if 0	/* F_F_S */
extern NX_TCP_SOCKET *dpm_get_new_tcp_sock_addr(char *tcp_sock_name);
extern NX_TCP_SOCKET *get_assigned_tcp_sock_addr(char *tcp_sess_name);
extern void	dpm_clr_tcp_sess(NX_TCP_SOCKET *tcp_sock, char *tcp_sess_name);
extern int	dpm_tcp_socket_allocate_cnt_info_get(void);

extern int	dpm_save_tcp_sess(NX_TCP_SOCKET *tcp_sock);
extern UINT	dpm_restore_tcp_sess(NX_TCP_SOCKET *tcp_sock, UINT port, NX_IP *ip_ptr, char *tcp_sess_name);
#endif

extern int	get_dpm_tcp_ka_info(char *tcp_sess_name);
extern void	set_dpm_tcp_ka_info(char *tcp_sess_name, unsigned int rtc_timer_id);
extern void	dpm_clr_tcp_ka_info(char *tcp_sess_name, unsigned int rtc_timer_id);
extern void dpm_udp_hole_punch(int period, unsigned long dest_ip, unsigned short src_port, unsigned short dest_port);

extern int	set_dpm_rcv_ready(char *mod_name);
extern int	set_dpm_rcv_ready_by_port(unsigned int port);
extern void	dpm_arp_en(int period, int mode);

extern void dpm_udpf_cntrl(unsigned char en_flag);
extern void dpm_tcpf_cntrl(unsigned char en_flag);
extern void	set_dpm_udp_port_filter(unsigned short d_port);
extern void	set_dpm_tcp_port_filter(unsigned short d_port);
extern void	del_dpm_udp_port_filter(unsigned short d_port);
extern void	del_dpm_tcp_port_filter(unsigned short d_port);

// DPM Manager API
extern int dpm_mng_start();
extern int dpm_mng_regist_config_cb(void (*regConfigFunction)());
extern int dpm_mng_send_to_session(UINT sessionNo, ULONG ip, ULONG port, char *buf, UINT size);
extern int dpm_mng_stop_session(UINT sess_idx);
extern int dpm_mng_start_session(UINT sess_idx);
extern int dpm_mng_set_session_info(UINT sessionNo, ULONG type, ULONG myPort, char *peerIp, ULONG peerPort, ULONG kaInterval, void (*connCb)(), void (*recvCb)());
extern int dpm_mng_set_session_info_my_port_no(UINT sessionNo, ULONG port);			/* for Server */
extern int dpm_mng_set_session_info_peer_port_no(UINT sessionNo, ULONG port);		/* for Server */
extern int dpm_mng_set_session_info_peer_ip_addr(UINT sessionNo, char *ip);			/* for Server */
extern int dpm_mng_set_session_info_server_ip_addr(UINT sessionNo, char *ip);		/* for Client */
extern int dpm_mng_set_session_info_server_port_no(UINT sessionNo, ULONG port);		/* for Client */
extern int dpm_mng_set_session_info_local_port(UINT sessionNo, ULONG port);			/* for Client */
extern int dpm_mng_set_session_info_window_size(UINT sessionNo, UINT windowSize);	/* for TCP */
extern int dpm_mng_set_session_info_conn_retry_count(UINT sessionNo, UINT connRetryCount);/* for TCP Client */
extern int dpm_mng_set_session_info_conn_wait_time(UINT sessionNo, UINT connWaitTime);	/* for TCP Client */
extern int dpm_mng_set_session_info_auto_reconnect(UINT sessionNo, UINT autoReconnect);	/* for TCP Client */
extern int dpm_mng_set_DPM_timer(UINT id, UINT type, UINT interval, void (*timerCallback)());
extern int dpm_mng_unset_DPM_timer(UINT id);
extern int dpm_mng_init_done();
#ifdef __DPM_MNG_SAVE_RTM__
extern void dpm_mng_save_rtm();
#endif
extern void dpm_mng_print_session_info();
extern void dpm_mng_print_session_config(UINT sessionNo);
extern int dpm_mng_job_start();
extern int dpm_mng_job_done();

#if !defined (DEF_DPM_WAKEUP_TYPE)
#define DEF_DPM_WAKEUP_TYPE
/* DPM Wakeup type */
enum DPM_WAKEUP_TYPE {
	DPM_UNKNOWN_WAKEUP     = 0,
	DPM_RTCTIME_WAKEUP     = 1,
	DPM_PACKET_WAKEUP      = 2,
	DPM_USER_WAKEUP        = 3,
	DPM_NOACK_WAKEUP       = 4,
	DPM_DEAUTH_WAKEUP      = 5,
	DPM_TIM_ERR_WAKEUP     = 6,
	DPM_DDPS_BUFP_WAKEUP	= 7	
};
#endif // DEF_DPM_WAKEUP_TYPE

/* Defines */
#define	DPM_ENABLED			1
#define	DPM_DISABLED		0

#define	DPM_WAKEUP			1
#define	NORMAL_BOOT			0

/* DPM mode APIs */
#define	dpm_mode_enable						enable_dpm_mode
#define	dpm_mode_disable					disable_dpm_mode
#define	dpm_mode_is_enabled					chk_dpm_mode
#define	dpm_mode_is_wakeup					chk_dpm_wakeup

#define	dpm_mode_get_wakeup_source			dpm_get_wakeup_source
#define	dpm_mode_get_wakeup_type			da16x_get_dpm_wakeup_type

/* DPM sleep starting status APIs */
#define	dpm_sleep_is_started				chk_dpm_pdown_start
#define	dpm_sleep_start_mode_1				fc80211_da16x_pri_pwr_down
#define	dpm_sleep_start_mode_2				fc80211_da16x_sec_pwr_down

/* DPM sleep flag APIs */
#define	dpm_app_register					reg_dpm_sleep
#define	dpm_app_unregister					unreg_dpm_sleep
#define	dpm_app_sleep_ready_set				set_dpm_sleep
#define	dpm_app_sleep_ready_clear			clr_dpm_sleep
#define	dpm_app_wakeup_done					set_dpm_init_done

/* DPM retention memory user APIs */
#define dpm_user_mem_init_check				dpm_user_rtm_pool_init_chk
#define	dpm_user_mem_alloc					dpm_user_rtm_allocate
#define	dpm_user_mem_free					dpm_user_rtm_release
#define	dpm_user_mem_get					dpm_user_rtm_get

/* DPM Timer APIs */
#define	dpm_timer_create					dpm_user_timer_create
#define	dpm_timer_delete					dpm_user_timer_delete
#define	dpm_timer_change					dpm_user_timer_change

/* DPM TCP Socket APIs */
#define	dpm_tcp_socket_alloc				dpm_get_new_tcp_sock_addr
#define	dpm_tcp_socket_free					dpm_clr_tcp_sess
#define	dpm_tcp_socket_get					get_assigned_tcp_sock_addr
#define	dpm_tcp_socket_save					dpm_save_tcp_sess
#define	dpm_tcp_socket_restore				dpm_restore_tcp_sess

#define	dpm_tcp_socket_keep_alive_get		get_dpm_tcp_ka_info
#define	dpm_tcp_socket_keep_alive_set		set_dpm_tcp_ka_info
#define	dpm_tcp_socket_keep_alive_delete	dpm_clr_tcp_ka_info

/* DPM UDP Socket APIs */
#define dpm_udp_hole_punch_set				dpm_udp_hole_punch

#define	dpm_app_data_rcv_ready_set			set_dpm_rcv_ready
#define	dpm_arp_enable						dpm_arp_en

/* DPM port number filter APIs */
#define	dpm_udp_filter_enable				dpm_udpf_cntrl
#define	dpm_tcp_filter_enable				dpm_tcpf_cntrl
#define	dpm_udp_port_filter_set				set_dpm_udp_port_filter
#define	dpm_tcp_port_filter_set				set_dpm_tcp_port_filter
#define	dpm_udp_port_filter_delete			del_dpm_udp_port_filter
#define	dpm_tcp_port_filter_delete			del_dpm_tcp_port_filter

#endif	/* __USER_DPM_API_H__ */

/* EOF */
