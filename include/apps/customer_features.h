/**
 ****************************************************************************************
 *
 * @file sdk_type.h
 *
 * @brief Defines and macros for customer feature
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

#ifndef	__CUSTOMER_FEATURES_H__
#define	__CUSTOMER_FEATURES_H__

/* ... Common Features ... */

#undef	CUSTOMER_GENERIC	// Generic 			(__CUSTOMER_100__)
#undef	CUSTOMER_GENERIC_2ND	// Generic : Small-System	(__CUSTOMER_100__)
#define	CUSTOMER_MESH		// Mesh system			(__CUSTOMER_200__)


/* ... Customer : KOREA ... */
#undef	CUSTOMER_SDS_DOORLOCK	// For SDS Doorlock		(__CUSTOMER_1__)


/* ... Customer : USA ... */


/* ... Customer : CHINA ... */
#undef	CUSTOMER_HUAMI		// Huami 			(__CUSTOMER_10__)


/* ... Platform ... */
#undef	CUSTOMER_DOORBELL	// Doorbell Reference system	(__CUSTOMER_110__)

/* 
	To be ablt to run Combo build
	1) Use DA16600 EVB
	2) Use Build\ldscripts\DA16xxx_rtos_cache.icf.4MB
	3) Use Build\SBOOT\cmconfig\da16xtpmconfig.cfg.W25Q32JW(4MB)
	4) Load BLE image (\1.UTILS\combo\ble_pre-built_img\): loady 19a000 1000 bin
*/
#undef	CUSTOMER_COMBO		// Wi-FI + BLE Combo system	(__CUSTOMER_300__)


/* ... Manufacturing feature ... */
#undef	MANUFACTURE		// Basic : Manufacturing	(__CUSTOMER_999__)

/****************************************************************/

#ifdef	CUSTOMER_GENERIC
	#include "customer_generic.h"
#endif	/* CUSTOMER_GENERIC */

#ifdef	CUSTOMER_GENERIC_2ND
	#include "customer_generic_2nd.h"
#endif	/* CUSTOMER_GENERIC */

#ifdef	CUSTOMER_MESH
	#include "customer_mesh.h"
#endif	/* CUSTOMER_MESH */


/* ... Customer : KOREA ... */
#ifdef	CUSTOMER_SDS_DOORLOCK
	#include "customer_sds_doorlock.h"
#endif	/* CUSTOMER_SDS_DOORLOCK */

/* ... Customer : USA ... */


/* ... Customer : CHINA ... */
#ifdef	CUSTOMER_HUAMI
	#include "customer_huami.h"
#endif	/* CUSTOMER_HUAMI */


/* ... IoT Platform ... */
#ifdef	CUSTOMER_COMBO
	#include "customer_combo.h"
#endif	/* CUSTOMER_COMBO */

#ifdef	CUSTOMER_DOORBELL
	#include "customer_doorbell.h"
#endif	/* CUSTOMER_DOORBELL */


/* ... For Manufacturing feature ... */
#ifdef	MANUFACTURE
	#include "customer_manufacture.h"
#endif	/* MANUFACTURE */

#endif	/* __CUSTOMER_FEATURES_H__ */

/* EOF */
