//#include "ledweb.h"
#include "string.h"
#include "stdint.h"
//#include "main.h"
#include "lwip/apps/httpd.h"
#include "app_provision.h"
#include "httpd.h"
/*example request GET: /leds.cgi?led=2
	/uri?<key1>=<value1>&<key2>=<value2>&...
*/
// prototype CGI handler for the LED control
const char * wifiConfigCGIhandler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]);
// this structure contains the name of the LED CGI and corresponding handler for the LEDs
const tCGI wifiConfigCGI={"/wifiConfig.cgi", wifiConfigCGIhandler};
//table of the CGI names and handlers
tCGI theCGItable[1]; //bang list cac handles.


// Initialize the CGI handlers
void myCGIinit(void)
{
	//add LED control CGI to the table
	theCGItable[0] = wifiConfigCGI;
	//give the table to the HTTP server
	http_set_cgi_handlers(theCGItable, 1);
} //myCGIinit


/**** CGI handler for controlling the LEDs ****/
// the function pointer for a CGI script handler is defined in httpd.h as tCGIHandler
const char * wifiConfigCGIhandler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
{
	uint32_t i=0;
	// index of the CGI within the theCGItable array passed to http_set_cgi_handlers
	// Given how this example is structured, this may be a redundant check.
	// Here there is only one handler iIndex == 0
	printf("HTTPD: CGI params:\n \
					handle index: %d\n \
					numParams: %d \n ",iIndex, iNumParams);  //moi 1 handles co the co nhieu cap <key>=<value>
	if (iIndex == 0)
	{
	// turn off the LEDsPage 13 of 17
//	BSP_LED_Off(LED2);
//	BSP_LED_Off(LED3);
	// Check the cgi parameters, e.g., GET /leds.cgi?led=1&led=2
//		for (i=0; i<iNumParams; i++)
//		{
//			printf("paramIdx %d: <key>=<value>: %s=%s\n",i,pcParam[i],pcValue[i]);
//			//if pcParmeter contains "led", then one of the LED check boxes has been set on
//			if (strcmp(pcParam[i], "led") == 0)
//			{
//				//see if checkbox for LED 1 has been set
//				if(strcmp(pcValue[i], "1") == 0)
//				{
//					// switch led 1 ON if 1
//					BSP_LED_Toggle(LED2);
//				}
//				//see if checkbox for LED 2 has been set
//				else if(strcmp(pcValue[i], "2") == 0)
//				{
//					// switch led 2 ON if 2
//					BSP_LED_Toggle(LED3);
//				}
//			} //if
//		} //for
				for (i=0; i<iNumParams; i++)
				{
					printf("paramIdx %d: <key>=<value>: %s=%s\n",i,pcParam[i],pcValue[i]);
					//if pcParmeter contains "led", then one of the LED check boxes has been set on
					PRINTF("paramIdx %d: <key>=<value>: %s=%s\n",i,pcParam[i],pcValue[i]);
						//see if checkbox for LED 1 has been set
						if(strcmp(pcValue[0], "Makihome") == 0 && strcmp(pcValue[1], "makihome2021") == 0)
						{
							// switch led 1 ON if 1
							//BSP_LED_Toggle(LED2);
							PRINTF("WIFI CONNECTED!!");

							app_reset_ap_to_station("Makihome", "makihome2021", 3 , 0,0);
						}
						//see if checkbox for LED 2 has been set
						else
						{
							PRINTF("wrong pw!!");
						}

				} //for
	} //if
	//uniform resource identifier to send after CGI call, i.e., path and filename of the response
	return "/wifiConfig.html";		//uri tra ve de httpserver gui tra 1 file ung voi uri nay cho web client
} //LedCGIhandler






