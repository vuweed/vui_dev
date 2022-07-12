/**
 ****************************************************************************************
 *
 * @file user_main.c
 *
 * @brief MAIN starting entry point
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

#include "driver.h"
#include "da16x_system.h"
#include "common_def.h"
#include "sys_specific.h"

#ifdef __SUPPORT_NAT__
#include "common_config.h"
#include "common_def.h"
#endif /* __SUPPORT_NAT__ */



/*
 * extern symbols : Not for customer
 */
extern void		version_display(int argc, char *argv[]);
extern int		get_boot_mode(void);
extern int		get_run_mode(void);
extern void		system_start(void);
extern INT32	__GPIO_RETAIN_HIGH_RECOVERY();

#if defined ( __REMOVE_32KHZ_CRYSTAL__ )
extern int		ALT_RTC_ENABLE(void);
#endif	// __REMOVE_32KHZ_CRYSTAL__
#if defined ( __SUPPORT_NAT__ )
extern void		set_nat_flag_enable(void);
extern int		chk_dpm_wakeup(void);
#endif // __SUPPORT_NAT__


/*
 *********************************************************************************
 * @brief	Configure system Pin-Mux
 * @return	None
 *********************************************************************************
 */
int config_pin_mux(void)
{
	/* DA16200 default pin-configuration */

	_da16x_io_pinmux(PIN_AMUX, AMUX_GPIO);
	_da16x_io_pinmux(PIN_BMUX, BMUX_GPIO);
	_da16x_io_pinmux(PIN_CMUX, CMUX_GPIO);
	_da16x_io_pinmux(PIN_DMUX, DMUX_GPIO);		// For GPIO 6,7
	_da16x_io_pinmux(PIN_EMUX, EMUX_GPIO);
	_da16x_io_pinmux(PIN_FMUX, FMUX_GPIO);
	_da16x_io_pinmux(PIN_HMUX, HMUX_JTAG);

	/* PIN remapping for UART, SPI and SDIO */	
	#if defined (__ATCMD_IF_UART1__) || defined (__SUPPORT_UART1__)
		_da16x_io_pinmux(PIN_CMUX, CMUX_UART1d);
	#elif defined(__ATCMD_IF_SPI__)
		_da16x_io_pinmux(PIN_BMUX, BMUX_SPIs);
		_da16x_io_pinmux(PIN_EMUX, EMUX_SPIs);
	#elif defined(__ATCMD_IF_SDIO__)
		_da16x_io_pinmux(PIN_CMUX, CMUX_SDs);
		_da16x_io_pinmux(PIN_DMUX, DMUX_SDs);
		_da16x_io_pinmux(PIN_EMUX, EMUX_SDs);
	#endif /* PIN remapping for UART, SPI and SDIO */

#if defined (__ATCMD_IF_UART2__) || defined (__SUPPORT_UART2__)
	_da16x_io_pinmux(PIN_UMUX, UMUX_UART2GPIO);   // UART2 for AT commands or user uart2
#endif
#if defined(__ATCMD_IF_SPI__)|| defined (__ATCMD_IF_SDIO__)
	// Set GPIOC6 as Interrupt pin
	static HANDLE gpio;
	gpio = GPIO_CREATE(GPIO_UNIT_C);
	GPIO_INIT(gpio);

	PRINTF("[WS]>>> Initialize interrupt: %x\n", GPIO_ALT_FUNC_GPIO6);
	GPIO_SET_ALT_FUNC(gpio, GPIO_ALT_FUNC_EXT_INTR,
						(GPIO_ALT_GPIO_NUM_TYPE)(GPIO_ALT_FUNC_GPIO6));
	GPIO_CLOSE(gpio);
#endif

	/* Need to configure by customer */
	SAVE_PULLUP_PINS_INFO(GPIO_UNIT_A, GPIO_PIN6 | GPIO_PIN7);

	return TRUE;
}


/**
 ******************************************************************************
 * @brief		System entry point
 * @input[in]	init_state	initalize result of pTIME and RamLib
 * @return		None
 ******************************************************************************
 */
int user_main(char init_state)
{
	int	status = 0;

	/*
	 * 1. Restore saved GPIO PINs
	 * 2. RTC PAD connection
	 */
	__GPIO_RETAIN_HIGH_RECOVERY();

#if defined ( __REMOVE_32KHZ_CRYSTAL__ )
	/* Initialize Alternative RTC counter */
	ALT_RTC_ENABLE();
#endif	// __REMOVE_32KHZ_CRYSTAL__

	/* Entry point for customer main */
	if (init_state == pdTRUE) {
		system_start();
	} else {
		PRINTF("\nFailed to initialize the RamLib or pTIM !!!\n");
	}

	return status;
}

/* EOF */
