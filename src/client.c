
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>


#include "lion.h"
#include "lbnc.h"
#include "relay.h"
#include "server.h"
#include "misc.h"
#include "data.h"
#include "client.h"
#include "ident.h"




void client_relay(relay_s *node, char *line)
{
	if (lbnc_debug)
		printf("[client] relaying resumed '%s'\n", line ? line : "");

	node->client_state = CLIENT_RELAY;

	if (node->server_control_handle)
		lion_enable_read(node->server_control_handle);

	if (line) client_input(node, line);

}




int client_command(relay_s *node, char *cmd, char *line)
{
	int i;

	if (lbnc_debug)
		printf("[client] command '%s' - '%s' (server_nodata %d)\n", cmd, line,
               server_nodata);


	if (!mystrccmp("AUTH", cmd)) {

		// Check if it is for SSL/TLS, and start negotiations if it is.
		// But only if SSL is NOT disabled.

		if (SSL_client_control != SSL_CONTROL_DISABLED) {

			if (!mystrccmp(" TLS", &line[4]) ||
				!mystrccmp(" SSL", &line[4])) {

				if (lbnc_debug)
					printf("[client] Starting TLS phase.\n");


				// Pause server so it can't interfer
				lion_disable_read(node->server_control_handle);

				// Start SSL negotiations
				i = lion_ssl_set(node->client_control_handle, LION_SSL_SERVER);

				if (i == -3) {
					printf("AUTH TLS attempted when we failed to load a certificate.\n");
					printf("Consider supplying a certificate, or, specify -c to silence this\n");

					lion_printf(node->client_control_handle,
                                "500 AUTH TLS not supported: no certificate.\r\n");

                    if (node->server_control_handle)
                        lion_enable_read(node->server_control_handle);
					return 1;
				}

				// Tell 'em to start
				lion_printf(node->client_control_handle,
							"234 Attempting TLS connection\r\n");

				// Set our state.
				node->client_state = CLIENT_SSL;

				return 1;

			}


		} else { // client_control == DISABLED. Just give error.

			lion_printf(node->client_control_handle,
						"500 Unknown Command\r\n");

			return 1;

		}




		// Should we also check PASS ?
	} if (!mystrccmp("USER", cmd)) {


		// They have issued USER, check if we enforce SSL, and if SSL is not
		// on, dis-allow.
		if ((SSL_client_control == SSL_CONTROL_ENFORCED) &&
			!lion_ssl_enabled(node->client_control_handle)) {

			lion_printf(node->client_control_handle,
						"500 Only SECURE connections allowed\r\n");
			return 1;


		}




	} if (!server_nodata && !mystrccmp("PBSZ", cmd)) {

		lion_printf(node->client_control_handle, "200 OK\r\n");
		return 1;




	} if (!server_nodata && !mystrccmp("PROT", cmd)) {

		node->client_prot_level = (line[5] == 'P') ?
			1 : 0;

		lion_printf(node->client_control_handle, "200 OK\r\n");
		return 1;




	} if (!server_nodata && !mystrccmp("PASV", cmd)) {

		// Set that we are awaiting a PASV reply.
		// pause input from client
		// then tell server to start data session.

        if (lbnc_debug)
            printf("[client] got PASV command\n");


		// If prot level is 0, and we are enforcing data security, fail it.
		if (!node->client_prot_level &&
			(SSL_client_data == SSL_DATA_SECURE)) {

			if (lbnc_debug)
				printf("[client] refusing PASV due to prot level. 1\n");

			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\r\n");
			return 1;

		}


		if (client_pasv(node)) {

			node->client_state = CLIENT_GOT_PASV;

            if (lbnc_debug)
				printf("[client] disable read on PASV port.\n");

            if (node->client_control_handle)
                lion_disable_read(node->client_control_handle);

			server_start_data( node, 1 ); // 1 suggest we came in as pasv.

			return 1;

		}

		return 1;

	} if (!server_nodata && !mystrccmp("PORT", cmd)) {

		// Parse the PORT string,
		// pause client, connect to the port
		// if connected, start server side.
		// If prot level is 0, and we are enforcing data security, fail it.
		if (!node->client_prot_level &&
			(SSL_client_data == SSL_DATA_SECURE)) {

			if (lbnc_debug)
				printf("[client] refusing PORT due to prot level. 1\n");

			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\r\n");
			return 1;

		}


		if (client_port(node, &line[4])) {

			node->client_state = CLIENT_GOT_PORT;

			lion_disable_read(node->client_control_handle);

			//server_start_data( node, 1 ); // 1 suggest we came in as pasv.

			return 1;

		}

		return 1;

	} if (!server_nodata && !mystrccmp("EPSV", cmd)) {

		// Set that we are awaiting a EPSV reply.
		// pause input from client
		// then tell server to start data session.

		// If prot level is 0, and we are enforcing data security, fail it.
		if (!node->client_prot_level &&
			(SSL_client_data == SSL_DATA_SECURE)) {

			if (lbnc_debug)
				printf("[client] refusing EPSV due to prot level. 1\n");

			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\r\n");
			return 1;

		}


		if (client_epsv(node)) {

			node->client_state = CLIENT_GOT_EPSV;

            if (node->client_control_handle)
                lion_disable_read(node->client_control_handle);

			server_start_data( node, 1 ); // 1 suggest we came in as pasv.
			// we don't talk EPSV to server, translate to pasv for clients.
			return 1;

		}

		return 1;


	} if (!server_nodata && !mystrccmp("SSCN", cmd)) {
		client_sscn(node, line);
		return 1;

	} if (!server_nodata && !mystrccmp("CCSN", cmd)) {
		client_ccsn(node, line);
		return 1;

		// Stop these until we support them
	} if (!server_nodata && !mystrccmp("EPRT", cmd)) {
		lion_printf(node->client_control_handle, "500 Unknown Command\r\n");
		return 1;
	} if (!server_nodata && !mystrccmp("CPSV", cmd)) {
		lion_printf(node->client_control_handle, "500 CPSV: Unknown Command: use CCSN (or SSCN)\r\n");
		return 1;

	} if (lbnc_sendident && !mystrccmp("IDEN", cmd)) {
		// If we send IDEN command, we eat any from clients, this ensures no
		// fake stuff. But we do allow it if we aren't to send IDEN. Then you
		// can chain lbnc'ers.

		return 1; // just eat it.

	} if (lbnc_sendident && !mystrccmp("IDNT", cmd)) {
		// If we send IDNT command, we eat any from clients, this ensures no
		// fake stuff. But we do allow it if we aren't to send IDNT. Then you
		// can chain lbnc'ers.

		return 1; // just eat it.

	}


	return 0;

}









void client_input(relay_s *node, char *line)
{
	char command[5];

	command[0] = 0;

	// The commands we are interested in are always 4 characters, followed
	// either by null (newlines are stripped) or space.
	if ( line &&
		 isalnum(line[ 0 ]) &&
		 isalnum(line[ 1 ]) &&
		 isalnum(line[ 2 ]) &&
		 isalnum(line[ 3 ])) {

		strncpy(command, line, sizeof(command));
		command[4] = 0;

		// Check the command and act on them.
		if (client_command(node, command, line))
			return; // Skip the state logic below (dont relay the input)

	}




	switch(node->client_state) {

	case CLIENT_GOT_PASV:
	case CLIENT_GOT_EPSV:

		// Just idle until we get reply from server...

		break;


	case CLIENT_RELAY:
		lion_printf(node->server_control_handle, "%s\r\n", line);
		break;

	default:
		break;

	}


}









int client_handler(lion_t *handle, void *user_data,
				   int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;

	if (lbnc_debug)
		printf("[client] handler %p/%p %d\n",
			   handle,
			   user_data,
			   status);


	if (!node) return 0;

	switch( status ) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[client] connection lost %d:%s\n", size, line);

		/* fallhrough */
	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[client] connection %p/%p closed.\n", handle, user_data);

		node->client_control_handle = NULL;
		if (node->client_data_handle) lion_close(node->client_data_handle);
		if (node->server_data_handle) lion_close(node->server_data_handle);
		if (node->ident_handle)       lion_close(node->ident_handle);

		if (node->server_control_handle)
			lion_close(node->server_control_handle);

		relay_free(node);
		break;

	case LION_CONNECTION_CONNECTED:

		lion_getpeername(handle, &node->client_host, &node->client_port);

		if (lbnc_debug)
			printf("[client] new client %p/%p %s:%d\n",
				   handle, user_data,
				   lion_ntoa(node->client_host), node->client_port);

		// If we are to use ident, we need to issue that first of all.
		// then ident will trigger the same code as below.
		if (server_useident) {

			ident_new(node);
			break;
		}

		// start up server side.
		client_relay(node, NULL);

		server_new(node);
		break;


	case LION_INPUT:
		if (lbnc_debug)
			printf("[client] %p/%p :%s\n", handle, user_data, line);

		client_input(node, line);

		break;



	case LION_CONNECTION_SECURE_FAILED:
		if (lbnc_debug)
			printf("[client] SSL failed\n");

		client_relay(node, NULL);
		break;


	case LION_CONNECTION_SECURE_ENABLED:
		if (lbnc_debug)
			printf("[client] SSL enabled\n");

		client_relay(node, NULL);
		break;


	}

	return 0;

}




int client_port(relay_s *node, char *line)
{

	// Parse it...
	if (!lion_ftp_pasv(line, &node->client_data_host,
					   &node->client_data_port)) {

		lion_printf(node->client_control_handle,
					"500 PORT line parse error\r\n");
		return 0;

	}


	// Ok, attempt to connect.
	node->client_data_handle = lion_connect( lion_ntoa(node->client_data_host),
											 node->client_data_port,
											 lbnc_binddataif,  // FIXME
											 0,
											 LION_FLAG_FULFILL,
											 (void *) node);

	lion_set_handler(node->client_data_handle, data_client_port_handler);
	lion_setbinary(node->client_data_handle);

	return 1;
}



int client_pasv(relay_s *node)
{

	// Open listening socket in readiness to reply to PASV
	lion_getsockname(node->client_control_handle,
					 &node->client_data_host,
					 &node->client_data_port);

	// Random port, or pick port.
	node->client_data_port = 0;

	// Lets not open it in FULFILL so we know right away if it fails.
	node->client_data_handle = lion_listen(&node->client_data_port,
										   node->client_data_host,
										   0,
										   (void *) node);

	if (lbnc_debug)
		printf("[client] data port for pasv bound %s:%d\n",
			   lion_ntoa(node->client_data_host),
			   node->client_data_port);

	// Did we fail?
	if (node->client_data_handle) {

		lion_set_handler(node->client_data_handle, data_client_pasv_handler);
		lion_setbinary(node->client_data_handle);
		return 1;

	}

	// Failed...
	lion_printf(node->client_control_handle,
				"425 Can't build data connection: %s\r\n",
				strerror( errno ));

	return 0;
}



int client_epsv(relay_s *node)
{

	// Open listening socket in readiness to reply to PASV
	lion_getsockname(node->client_control_handle,
					 &node->client_data_host,
					 &node->client_data_port);

	// Random port, or pick port.
	node->client_data_port = 0;

	// Lets not open it in FULFILL so we know right away if it fails.
	node->client_data_handle = lion_listen(&node->client_data_port,
										   node->client_data_host,
										   0,
										   (void *) node);

	if (lbnc_debug)
		printf("[client] data port for epsv bound %s:%d\n",
			   lion_ntoa(node->client_data_host),
			   node->client_data_port);

	// Did we fail?
	if (node->client_data_handle) {

		lion_set_handler(node->client_data_handle, data_client_pasv_handler);
		lion_setbinary(node->client_data_handle);
		return 1;

	}

	// Failed...
	lion_printf(node->client_control_handle,
				"425 Can't build data connection: %s\r\n",
				strerror( errno ));

	return 0;
}




void client_data_reply(relay_s *node, int good, char *msg)
{

	// Finally send PASV reply.

	if (node->client_state == CLIENT_GOT_PASV) {

		if (good) {

			if (lbnc_debug)
				printf("[client] replying to client with PASV 227.\n");

			lion_printf(node->client_control_handle,
						"227 Entering Passive Mode (%s)\r\n",
						lion_ftp_port(lbnc_fakeipclient ? lbnc_fakeipclient :
									  node->client_data_host,
									  node->client_data_port));

			// Server side is connected, we actually disable it now so that
			// we dont read things on it until the client side is ready
			// But in PORT mode it is NOT ready, and never will be.
			// try 2 XXX
			//lion_disable_read(node->server_data_handle);

		} else {

			// If msg has "XXX " then send only that, other wise its
			// the reason.
			if (msg &&
				isdigit(msg[0]) &&
				isdigit(msg[1]) &&
				isdigit(msg[2]) &&
				(msg[3] == ' '))

				lion_printf(node->client_control_handle,
							"%s\r\n",
							msg ? msg : "server error");
			else
				lion_printf(node->client_control_handle,
							"425 Can't build data connection: %s\r\n",
							msg ? msg : "server error");

            if (node->client_data_handle)
                lion_close(node->client_data_handle);

		}


	} else if (node->client_state == CLIENT_GOT_EPSV) {

		if (good) {

			// 229 Entering Extended Passive Mode (|||54829|)

			if (lbnc_debug)
				printf("[client] replying to client with EPSV 229.\n");

			lion_printf(node->client_control_handle,
						"229 Entering Passive Mode (|||%u|)\r\n",
						node->client_data_port);

			// Server side is connected, we actually disable it now so that
			// we dont read things on it until the client side is ready
			// But in PORT mode it is NOT ready, and never will be.
			// try 2 XXX
			//lion_disable_read(node->server_data_handle);

		} else {

			// If msg has "XXX " then send only that, other wise its
			// the reason.
			if (msg &&
				isdigit(msg[0]) &&
				isdigit(msg[1]) &&
				isdigit(msg[2]) &&
				(msg[3] == ' '))

				lion_printf(node->client_control_handle,
							"%s\r\n",
							msg ? msg : "server error");
			else
				lion_printf(node->client_control_handle,
							"425 Can't build data connection: %s\r\n",
							msg ? msg : "server error");

            if (node->client_data_handle)
                lion_close(node->client_data_handle);

		}


	} else if (node->client_state == CLIENT_GOT_PORT) {   // PORT!

		if (good) {

			lion_printf(node->client_control_handle, "200 PORT Command Successful.\r\n");
            if (node->client_data_handle)
                lion_enable_read(node->client_data_handle);

		} else { // BAD

			if (msg &&
				isdigit(msg[0]) &&
				isdigit(msg[1]) &&
				isdigit(msg[2]) &&
				(msg[3] == ' '))
				lion_printf(node->client_control_handle,
							"%s\r\n", msg ? msg : "500 FAILED");
			else
				lion_printf(node->client_control_handle,
							"500 PORT Command failed: %s\r\n", msg ? msg : "");

            if (node->client_data_handle)
                lion_close(node->client_data_handle);

		}




	} else {

		// No mode set. most likely we are near the end of server PORT mode
		// so we want to enable client data here
#if 0
		if (lbnc_debug)
			printf("[client] enabling client data\n");

		if (node->client_data_handle)
			lion_enable_read(node->client_data_handle);
#endif
		if (lbnc_debug) printf("[client] data_check_ready\n");

		data_check_ready(node);


	}


	if (node->client_control_handle)
        lion_enable_read(node->client_control_handle);

	client_relay(node, NULL);

}




void client_sscn(relay_s *node, char *line)
{

	// Off or On?
	// line = "CCSN On"
	// Skip command, the input parser checks commands are 4 chars, so
	// we can safely skip that.
	line += 4; // Skip SSCN
	while (*line == ' ') line++; // skip spaces

	if (!line || !*line) {
		lion_printf(node->client_control_handle,
					"200 %s mode\r\n",
					node->client_sscn ? "Client" : "Server");
		return;
	}


	if (toupper(line[0]) == 'O') {

		if (toupper(line[1]) == 'F') {
			node->client_sscn = 0;
			lion_printf(node->client_control_handle,
						"200 Server mode\r\n");
			return;
		}

		if (toupper(line[1]) == 'N') {
			if (node->client_ccsn) {
				lion_printf(node->client_control_handle,
							"500 Attempting to set SSCN when CCSN is already ON. Why?\r\n");
				return;
			}

			node->client_sscn = 1;
			lion_printf(node->client_control_handle,
						"200 Client mode\r\n");
			return;
		}

	}
	lion_printf(node->client_control_handle, "500 Incorrect SSCN Syntax.\r\n");
}


void client_ccsn(relay_s *node, char *line)
{

	// Off or On?
	// line = "CCSN On"
	// Skip command, the input parser checks commands are 4 chars, so
	// we can safely skip that.
	line += 4; // Skip SSCN
	while (*line == ' ') line++; // skip spaces

	if (!line || !*line) {
		lion_printf(node->client_control_handle,
					"200 %s mode\r\n",
					node->client_ccsn ? "Client" : "Server");
		return;
	}


	if (toupper(line[0]) == 'O') {

		if (toupper(line[1]) == 'F') {
			node->client_ccsn = 0;
			lion_printf(node->client_control_handle,
						"200 Server mode\r\n");
			return;
		}

		if (toupper(line[1]) == 'N') {
			if (node->client_sscn) {
				lion_printf(node->client_control_handle,
							"500 Attempting to set CCSN when SSCN is already ON. Why?\r\n");
				return;
			}

			node->client_ccsn = 1;
			lion_printf(node->client_control_handle,
						"200 Client mode\r\n");
			return;
		}

	}
	lion_printf(node->client_control_handle, "500 Incorrect CCSN Syntax.\r\n");
}

