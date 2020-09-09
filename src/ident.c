#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lion.h"
#include "misc.h"

#include "lbnc.h"
#include "relay.h"
#include "client.h"
#include "server.h"
#include "ident.h"









int ident_handler(lion_t *handle, void *user_data, 
				  int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;
	int lport;
	unsigned long laddr;
	
	if (lbnc_debug)
		printf("[ident] handler %p/%p %d\n", 
			   handle, 
			   user_data,
			   status);
	

	if (!node) return 0;

	switch( status ) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[ident] connection lost %d:%s\n", size, line);

		/* fallhrough */
	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[ident] connection %p/%p closed.\n", handle, user_data);

		node->ident_handle = NULL;

		ident_reply(node, "[CLOSED/LOST]");
		break;

	case LION_CONNECTION_CONNECTED:

		lion_getsockname(node->client_control_handle, &laddr, &lport);

		// Send ident query. its their local port, and our local port.
		lion_printf(handle, "%u,%u\r\n",
					node->client_port,
					lport);

		break;


	case LION_INPUT:
		if (lbnc_debug)
			printf("[ident] %p/%p :%s\n", handle, user_data, line);

		// Handle ident reply
		{
			char reply[256];
			int rmt_port;
			
			// Do a nice buffer check here. size is strlen line
			if ((size < 256) &&
				(sscanf(line, "%u , %*u : USERID :%*[^:]:%9s",
						&rmt_port, reply) == 2)  &&
				/*(ni->remote_port == our_port) &&*/
				(node->client_port == rmt_port)) {
				
				ident_reply(node, reply);

				break;
			} // sscanf good.

			ident_reply(node, "[PARSE-ERROR]");
			break;

		}

		break;

	}

	return 0;

}











//
// Start the IDENT lookup code.
//
// Issue connection back to ident.
// On success, failure or timeout 
// send IDEN line, then restart relay code.
//
void ident_new(relay_s *node)
{
	if (lbnc_debug)
		printf("[ident] connecting %s:%d\n", 
			   lion_ntoa(node->client_host), IDENT_PORT);
	

	// Ready for timeout.
	node->ident_start = lion_global_time;

	// Connect
	node->ident_handle = lion_connect(lion_ntoa(node->client_host),
									  IDENT_PORT,
									  0,
									  0,
									  LION_FLAG_FULFILL,
									  (void *)node);

	lion_set_handler(node->ident_handle, ident_handler);


}




void ident_reply(relay_s *node, char *msg)
{

	if (lbnc_debug)
		printf("[ident] result for %s:%d -> '%s'\n", 
			   lion_ntoa(node->client_host), node->client_port,
			   msg);


	// Close the descriptor.
	if (node->ident_handle) {

		// disconnect us
		lion_set_userdata(node->ident_handle, NULL);

		lion_close(node->ident_handle);

		node->ident_handle = NULL;

	}
	

	// If we are still connected, start the relay process
	if (node->client_control_handle && 
		lion_isconnected(node->client_control_handle)) {

		// Save ident value for later.
		SAFE_COPY(node->ident, msg);

		// start up server side.
		client_relay(node, NULL);
		
		server_new(node);
		
	}
	
}



int ident_periodical_sub( lion_t *handle, void *arg1, void *arg2 )
{
	relay_s *node;

	if (!handle) return 1;

	// Check its a ident request
	if (lion_get_handler(handle) != ident_handler)
		return 1;

	node = (relay_s *) lion_get_userdata(handle);

	if (!node) return 1;

	// Timed-out?
	if (node->ident_start + IDENT_TIMEOUT < lion_global_time) 
		ident_reply(node, "[TIMEOUT]");

	return 1;
}



void ident_periodical(void)
{
	static time_t last_run = 0;

	if (lion_global_time <= last_run) {

		last_run = lion_global_time;
		return;

	}

	//	if (lbnc_debug)
	//	printf("[ident] periodical\n");

	// Attempt to find ident requests that has timed out.
	lion_find(ident_periodical_sub, NULL, NULL);

}


