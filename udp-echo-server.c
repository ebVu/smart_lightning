/*
 * Copyright (c) 2012, Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/** \addtogroup cc2538-examples
 * @{
 *
 * \defgroup cc2538-echo-server cc2538dk UDP Echo Server Project
 *
 *  Tests that a node can correctly join an RPL network and also tests UDP
 *  functionality
 * @{
 *
 * \file
 *  An example of a simple UDP echo server for the cc2538dk platform
 */
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip-debug.h"
#include "dev/leds.h"
#include "net/rpl/rpl.h"
#include "dev/watchdog.h"
#include "dev/uart1.h" 
#include "sys/rtimer.h"
#include "dev/rom-util.h"
#include "dev/cbc.h"
#include "dev/uart.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include "dev/leds.h"
#include "net/rpl/rpl.h"
#include "dev/watchdog.h"

#ifdef SLS_USING_CC2538DK
#include "dev/uart.h"
#endif

#include "sls.h"	

/*---------------------------------------------------------------------------*/
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

#define MAX_PAYLOAD_LEN 120
#define DEBUG_SIZE 16

/*---------------------------------------------------------------------------*/
static struct uip_udp_conn *server_conn;
static char buf[MAX_PAYLOAD_LEN];
static uint16_t len;

/* SLS define */
static 	led_struct_t led_db;
//static struct led_struct_t *led_db_ptr = &led_db;

static 	gw_struct_t gw_db;
static 	net_struct_t net_db;
//static struct led_struct_t *gw_db_ptr = &gw_db;

static 	cmd_struct_t cmd, reply;
//static 	cmd_struct_t *cmdPtr = &cmd;

static 	radio_value_t aux;
static  char rxbuf[MAX_PAYLOAD_LEN];
static 	int cmd_cnt;
static	int	state;

/*define timers */
static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;
static	struct	etimer	et;
//static	struct	rtimer	rt;
static bool	emergency_status;


/* define prototype of fucntion call */
//static 	void set_connection_address(uip_ipaddr_t *ipaddr);
static 	void get_radio_parameter(void);
static 	void init_default_parameters(void);
static 	void reset_parameters(void);

#ifdef SLS_USING_CC2538DK
static 	unsigned int uart0_send_bytes(const	unsigned  char *s, unsigned int len);
static 	int uart0_input_byte(unsigned char c);
//static 	unsigned int uart1_send_bytes(const	unsigned  char *s, unsigned int len);
//static 	int uart1_input_byte(unsigned char c);
#define security_enable 1
#ifdef security_enable
#define KEY_LENGTH 16
struct cbc_param
{
	bool encrypt;
	uint8_t key_area;
	uint8_t key[DEBUG_SIZE];
	uint8_t iv[DEBUG_SIZE];
	uint8_t mdata_in[DEBUG_SIZE];
	uint8_t mdata_out[DEBUG_SIZE];
	int mdata_len;	
};
static struct cbc_param descrypt_param;
static uint8_t receive_data_flag;
#endif
#endif 

static 	void send_cmd_to_led_driver();
static	void process_hello_cmd(cmd_struct_t command);
static	void print_cmd_data(cmd_struct_t command);
static 	void send_reply (cmd_struct_t res);
static	void blink_led(unsigned char led);
static void security_prepare();
static void print_data();
static void proccess_cmd(void);
static void get_request_data(void);

/*---------------------------------------------------------------------------*/
PROCESS(udp_echo_server_process, "UDP echo server process");
AUTOSTART_PROCESSES(&udp_echo_server_process);

/*---------------------------------------------------------------------------*/
static void print_data() {
	uint8_t i;	
  	PRINTF("data = [");
	for (i=0;i < DEBUG_SIZE;i++) 
    	PRINTF("%x,",descrypt_param.mdata_out[i]);
  	PRINTF("]\n");
}
static void security_prepare()
{
	int ret;
	ret = CRYPTO_SUCCESS;
	static uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	static uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	static uint8_t count = 1; 
	//static uint8_t data[] = { 0x39, 0xa9, 0xb4, 0x2d, 0xe1, 0x9e, 0x51, 0x2a, 0xb7, 0xf3, 0x04, 0x35, 0x64, 0xc3, 0x51, 0x5a };
	static uint8_t data[] = {0x73,0xfd,0x7,0xc2,0x8f,0x43,0xb4,0x8d,0xc2,0x4,0xff,0x77,0x59,0x77,0x59,0xaa};

	//static uint8_t data[] = {0x1187e, 0x1000118, 0x10001, 0x00, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	//static uint8_t data[] = {0x7e,0x6b,0x3a,0xb2,0xa4,0xe6,0x90,0x2c,0xf5,0xd7,0x1d,0x2b,0x72,0x56,0x9c,0x54};
	// descrypt_param.mdata_len = sizeof(cmd_struct_t);
	descrypt_param.mdata_len = DEBUG_SIZE;
	descrypt_param.encrypt = false;
	descrypt_param.key_area = 0;
	memcpy(&descrypt_param.key, &key, KEY_LENGTH);
	memcpy(&descrypt_param.iv, &iv, KEY_LENGTH);
	memcpy(&descrypt_param.mdata_in, &data, descrypt_param.mdata_len);

	ret = aes_load_keys(descrypt_param.key, AES_KEY_STORE_SIZE_KEY_SIZE_128, count, 0);
    if(ret != CRYPTO_SUCCESS)
    {
        printf(" CRYPTO: load key not success\n");
    }
}

static void process_req_cmd(cmd_struct_t cmd){
	//uint8_t i;
	reply = cmd;
	reply.type =  MSG_TYPE_REP;
	reply.err_code = ERR_NORMAL;

	if (state==STATE_NORMAL) {
		switch (cmd.cmd) {
			case CMD_LED_ON:
				leds_on(RED);
				led_db.status = STATUS_LED_ON;
				//PRINTF ("Execute CMD = %s\n",SLS_LED_ON);
				break;
			case CMD_LED_OFF:
				leds_off(RED);
				led_db.status = STATUS_LED_OFF;
				//PRINTF ("Execute CMD = %d\n",CMD_LED_OFF);
				break;
			case CMD_LED_DIM:
				leds_toggle(GREEN);
				led_db.status = STATUS_LED_DIM;
				led_db.dim = cmd.arg[0];			
				//PRINTF ("Execute CMD = %d; value %d\n",CMD_LED_DIM, led_db.dim);
				break;
			case CMD_LED_REBOOT:
				send_reply(reply);
				clock_delay(5000000);
				watchdog_reboot();
				break;
			case CMD_GET_LED_STATUS:
				reply.arg[0] = led_db.id;
				reply.arg[1] = led_db.power;
				reply.arg[2] = led_db.temperature;
				reply.arg[3] = led_db.dim; 
				reply.arg[4] = led_db.status;
				break;
			case CMD_GET_NW_STATUS:
				reply.arg[0] = net_db.channel;
				reply.arg[1] = net_db.rssi;
				reply.arg[2] = net_db.lqi;
				reply.arg[3] = net_db.tx_power; 
				reply.arg[4] = (net_db.panid >> 8);
				reply.arg[5] = (net_db.panid) & 0xFF;				
				break;
			case CMD_GET_GW_STATUS:
				break;
			case CMD_GET_APP_KEY:
				memcpy(&reply.arg,&net_db.app_code,MAX_CMD_DATA_LEN);
				break;
			case CMD_REPAIR_ROUTE:
				rpl_repair_root(RPL_DEFAULT_INSTANCE);
				break;
			default:
				reply.err_code = ERR_UNKNOWN_CMD;			
		}
	}
	else if (state==STATE_HELLO) {
		//PRINTF("in HELLO state: no process REQ cmd\n");	
		switch (cmd.cmd) {
			case CMD_LED_REBOOT:
				send_reply(reply);
				clock_delay(500000);
				watchdog_reboot();
				break;
			case CMD_REPAIR_ROUTE:
				rpl_repair_root(RPL_DEFAULT_INSTANCE);
				break;
			default:
				break;
		}		
		reply = cmd;	
		reply.err_code = ERR_IN_HELLO_STATE;
	}
}

/*---------------------------------------------------------------------------*/
static void process_hello_cmd(cmd_struct_t command){
	reply = command;
	reply.type =  MSG_TYPE_HELLO;
	reply.err_code = ERR_NORMAL;

	if (state==STATE_HELLO) {
		switch (command.cmd) {
			case CMD_LED_HELLO:
				state = STATE_HELLO;
				leds_off(LEDS_RED);
				//rpl_repair_root(RPL_DEFAULT_INSTANCE);
				break;
			case CMD_SET_APP_KEY:
				state = STATE_NORMAL;
				leds_on(LEDS_RED);
				memcpy(&net_db.app_code,&cmd.arg,MAX_CMD_DATA_LEN);
				break;
			default:
				reply.err_code = ERR_IN_HELLO_STATE;
				break;
		}	
	}				
}

/*---------------------------------------------------------------------------*/
static void print_cmd_data(cmd_struct_t command) {
	uint8_t i;	
  	PRINTF("data = [");
	for (i=0;i<MAX_CMD_DATA_LEN;i++) 
    	PRINTF("0x%02X,",command.arg[i]);
  	PRINTF("]\n");
}

/*---------------------------------------------------------------------------*/
static void send_reply (cmd_struct_t res) {
	/* echo back to sender */	
	//PRINTF("Reply to [");
	//PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
	//PRINTF("]:%u %u bytes\n", UIP_HTONS(UIP_UDP_BUF->srcport), sizeof(res));
	uip_udp_packet_send(server_conn, &res, sizeof(res));

	/* Restore server connection to allow data from any node */
	uip_create_unspecified(&server_conn->ripaddr);
	//memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
	//server_conn->rport = 0;
#ifdef SLS_USING_CC2538DK
	blink_led(BLUE);
#else
	blink_led(RED);	
#endif	
}

/*---------------------------------------------------------------------------*/
/* brief: get data packet */
static void get_request_data(void)
{
	/* initialize flag variable*/
	receive_data_flag = 0;
	memset(buf, 0, MAX_PAYLOAD_LEN);
	if(uip_newdata()) {

	/* mark that data is got */
	receive_data_flag = 1;
	len = uip_datalen();
	memcpy(buf, uip_appdata, len);
	//PRINTF("Received from [");
	//PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
	//PRINTF("]:%u ", UIP_HTONS(UIP_UDP_BUF->srcport));
	//PRINTF("%u bytes DATA\n",len);
	
	uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
	server_conn->rport = UIP_UDP_BUF->srcport;

	get_radio_parameter();
	reset_parameters();
	}
}
/*---------------------------------------------------------------------------*/
/* brief: proccess cmd data */
static void proccess_cmd(void)
{
	if(receive_data_flag)
	{
		cmd = *(cmd_struct_t *)(&buf);
		PRINTF("Rx Cmd-Struct: sfd=0x%02X; len=%d; seq=%d; type=0x%02X; cmd=0x%02X; err_code=0x%02X\n",cmd.sfd, cmd.len, 
										cmd.seq, cmd.type, cmd.cmd, cmd.err_code);
		print_cmd_data(cmd);
		
		reply = cmd;		
		if (cmd.type==MSG_TYPE_REQ) {
			process_req_cmd(cmd);
			reply.type = MSG_TYPE_REP;
		}
		else if (cmd.type==MSG_TYPE_HELLO) {
			process_hello_cmd(cmd);	
			reply.type = MSG_TYPE_HELLO;
		}
		else if (cmd.type==MSG_TYPE_EMERGENCY) {
		}

		//prepare reply and response to sender
		send_reply(reply);


		/* send command to LED-driver */
		send_cmd_to_led_driver();
	}
}
/*---------------------------------------------------------------------------*/
static void blink_led(unsigned char led) {
#ifdef SLS_USING_CC2538DK
	leds_on(led);
	clock_delay_usec((uint16_t)2000000);
	leds_off(led);
#endif	
}

#ifdef SLS_USING_CC2538DK
static int uart0_input_byte(unsigned char c) {
	if (c==SFD) {
		cmd_cnt=1;
		rxbuf[cmd_cnt-1]=c;
	}
	else {
		cmd_cnt++;
		rxbuf[cmd_cnt-1]=c;
		if (cmd_cnt==sizeof(cmd_struct_t)) {
			cmd_cnt=0;
			PRINTF("Get cmd from LED-driver %s \n",rxbuf);
			blink_led(BLUE);
		}
	}
	return 1;
}

static unsigned int uart0_send_bytes(const	unsigned  char *s, unsigned int len) {
	unsigned int i;
	for (i = 0; i<len; i++) {
		uart_write_byte(0, (uint8_t) (*(s+i)));
   	}   
   return 1;
}
#endif


/*---------------------------------------------------------------------------*/
static void send_cmd_to_led_driver() {
#ifdef SLS_USING_CC2538DK
	uart0_send_bytes((const unsigned  char *)(&cmd), sizeof(cmd));	
#endif
}

/*---------------------------------------------------------------------------*/
static void reset_parameters(void) {
	memset(&reply, 0, sizeof(reply));
}

/*---------------------------------------------------------------------------*/
static void get_radio_parameter(void) {
	NETSTACK_RADIO.get_value(RADIO_PARAM_CHANNEL, &aux);
	net_db.channel = (unsigned int) aux;
	//printf("CH: %u ", (unsigned int) aux);	

 	aux = packetbuf_attr(PACKETBUF_ATTR_RSSI);
	net_db.rssi = (int8_t)aux;
 	//printf("RSSI: %ddBm ", (int8_t)aux);

	aux = packetbuf_attr(PACKETBUF_ATTR_LINK_QUALITY);
	net_db.lqi = aux;
 	//printf("LQI: %u\n", aux);

	NETSTACK_RADIO.get_value(RADIO_PARAM_TXPOWER, &aux);
	net_db.tx_power = aux;
 	//printf("   Tx Power %3d dBm", aux);
}

/*---------------------------------------------------------------------------*/
static void init_default_parameters(void) {

	state = STATE_HELLO;

	led_db.id		= 0x20;				//001-0 0000b
	led_db.panid 	= SLS_PAN_ID;
	led_db.power	= 120;
	led_db.dim		= 80;
	led_db.status	= STATUS_LED_ON; 
	led_db.temperature = 37;

	gw_db.id		= 0x40;				//010-0 0000b
	gw_db.panid 	= SLS_PAN_ID;
	gw_db.power		= 120;
	gw_db.status	= GW_CONNECTED; 

	cmd.sfd  = SFD;
	cmd.seq	 = 1;
	cmd.type = MSG_TYPE_REP;
	cmd.len  = sizeof(cmd_struct_t);

	net_db.panid 	= SLS_PAN_ID;

	emergency_status = DEFAULT_EMERGENCY_STATUS;

	// init UART0-1
#ifdef SLS_USING_CC2538DK
	uart_init(0); 		
 	uart_set_input(0,uart0_input_byte);
#endif
}

/*---------------------------------------------------------------------------*/

static void set_connection_address(uip_ipaddr_t *ipaddr) {
  // change this IP address depending on the node that runs the server!
  uip_ip6addr(ipaddr, 0xaaaa,0x0000,0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
}


/*---------------------------------------------------------------------------*/

static void timeout_hanler(){
	static int seq_id;
	char buf[100];

	if (state==STATE_NORMAL) {	
		if (emergency_status==true) {	
			sprintf(buf, "Emergency msg %d from the client", ++seq_id);
			uip_udp_packet_send(client_conn, buf, strlen(buf));
			PRINTF("Client sending to: ");
			PRINT6ADDR(&client_conn->ripaddr);
			PRINTF(" (msg: %s)\n", buf);
		}
	}
}


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_echo_server_process, ev, data) {
	int ret, res;

	PROCESS_BEGIN();

   	/* init uart */
   	uart_init(0);
   	crypto_init(); 		
 	uart_set_input(0,uart0_input_byte);

	// security_prepare();

	// /* start enscrypt data */
 //    rom_util_memcpy(descrypt_param.mdata_out, descrypt_param.mdata_in, descrypt_param.mdata_len);
 
 //    ret = cbc_crypt_start(descrypt_param.encrypt, descrypt_param.key_area,
 //                          descrypt_param.iv, descrypt_param.mdata_out, descrypt_param.mdata_out, descrypt_param.mdata_len,
 //                          &udp_echo_server_process);

 //    if(ret == CRYPTO_SUCCESS)
 //    {
 //        PROCESS_WAIT_EVENT_UNTIL((res = cbc_crypt_check_status()) != CRYPTO_PENDING);
 //        printf("res = %x\n", res);
 //    }
 //    if(ret != CRYPTO_SUCCESS)
 //    {
 //        PROCESS_PAUSE();
 //    }
 //    PROCESS_PAUSE();
	// print_data();

	//PROCESS_PAUSE();
	//SENSORS_ACTIVATE(button_sensor);

  	NETSTACK_MAC.off(1);

	init_default_parameters();

	server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  	if(server_conn == NULL) {
    	PROCESS_EXIT();
  	}
  	
  	udp_bind(server_conn, UIP_HTONS(SLS_NORMAL_PORT));

	etimer_set(&et, CLOCK_SECOND*30);
  	// wait until the timer has expired
//  	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

  	set_connection_address(&server_ipaddr);
	client_conn = udp_new(&server_ipaddr, UIP_HTONS(SLS_EMERGENCY_PORT), NULL);

 	while(1) {
    	PROCESS_YIELD();
    	if(ev == tcpip_event) {
      		// tcpip_handler();

      		/* get message data from tcpip */
      		get_request_data();

      		/* initialize descrypt data */
			security_prepare();

			/* start descrypt data */
		    rom_util_memcpy(descrypt_param.mdata_out, descrypt_param.mdata_in, descrypt_param.mdata_len);
		 
		    ret = cbc_crypt_start(descrypt_param.encrypt, descrypt_param.key_area,
		                          descrypt_param.iv, descrypt_param.mdata_out, descrypt_param.mdata_out, descrypt_param.mdata_len,
		                          &udp_echo_server_process);

		    if(ret == CRYPTO_SUCCESS)
		    {
		        PROCESS_WAIT_EVENT_UNTIL((res = cbc_crypt_check_status()) != CRYPTO_PENDING);
		        printf("res = %x\n", res);
		    }
		    if(ret != CRYPTO_SUCCESS)
		    {
		        PROCESS_PAUSE();
		    }
		    PROCESS_PAUSE();
			print_data();

			/* process cmd data after descrypt data */
			proccess_cmd();
    	}
    	else if (ev==PROCESS_EVENT_TIMER) {
    		timeout_hanler();
    		etimer_restart(&et);
    	}
    	//else if (ev == sensors_event && data == &button_sensor) {
      	//	PRINTF("Initiaing global repair\n");
      	//	rpl_repair_root(RPL_DEFAULT_INSTANCE);
    	//}
  	}

	PROCESS_END();
}
