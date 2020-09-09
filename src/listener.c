
#include <stdio.h>

#include "lion.h"
#include "lbnc.h"
#include "relay.h"
#include "client.h"
#include "listener.h"



static lion_t *local_listen = NULL;



void listener_init(void)
{

	local_listen = lion_listen( &local_port, lbnc_bindcontrolif, 
								LION_FLAG_FULFILL, NULL);
	lion_set_handler(local_listen, listener_handler);

}


void listener_free(void)
{

	if (local_listen) {
		
		lion_disconnect(local_listen);
		local_listen = NULL;

	}
	
}









//
// Main handle for the listening port for incoming FTP connections
// user_data here is not used. (NULL)
//
int listener_handler(lion_t *handle, void *user_data, 
					 int status, int size, char *line)
{
	relay_s *newd;
	
	if (lbnc_debug)
		printf("[listener] handler %p/%p %d %d:%s\n", 
			   handle, 
			   user_data,
			   status,
			   size,
			   line ? line : "(null)");
	
	switch( status ) {

	case LION_CONNECTION_LOST:
	case LION_CONNECTION_CLOSED:
		printf("[listener] listening port closed/lost %d:%s\n",
			   size, line ? line : "(null)");
		local_listen = NULL;
		exit_interrupt();
		break;


	case LION_CONNECTION_NEW:
		if (lbnc_debug)
			printf("[listener] New connection triggered\n");

		newd = relay_new();

		if (!newd) {
			
			lion_disconnect( lion_accept(handle, 0, LION_FLAG_FULFILL, NULL,
										 NULL, NULL));
			break;

		}

		newd->client_control_handle = 
			lion_accept(handle, 0, LION_FLAG_FULFILL, (void *)newd,
						NULL, NULL);

		lion_set_handler(newd->client_control_handle, client_handler);


	}


	return 0;

}


