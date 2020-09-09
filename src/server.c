#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#endif

#include "lion.h"
#include "misc.h"
#include "lbnc.h"
#include "relay.h"
#include "client.h"
#include "data.h"
#include "server.h"








//
// Client has connected and we are to connect to server.
//
void server_new(relay_s *node)
{

	node->server_state = SERVER_WANT_220;


	node->server_control_handle = lion_connect( relay_host, relay_port,
												lbnc_bindcontrolif, 0,
												LION_FLAG_FULFILL,
												(void *) node);

	lion_set_handler( node->server_control_handle, server_handler );

	// Basically, we need to go off and connect to the server, and do various
	// challanges. While we do that, we pause the client.
	lion_disable_read(node->client_control_handle);

}




void server_relay(relay_s *node, char *line)
{

	if (lbnc_debug)
		printf("[server] relaying resumed '%s'\n", line ? line : "");

	node->server_state = SERVER_RELAY;
    if (node->client_control_handle)
        lion_enable_read(node->client_control_handle);

	if (line) server_input(node, line);

}




//
// Input from server, parse it.
//
void server_input(relay_s *node, char *line)
{
	int response;

	// Server reply should always be "DDD " where D is a digit.
	// But we allow anything if we are in RELAY.
	if ((node->server_state != SERVER_RELAY) &&
		(!line ||
		 !isdigit(line[0]) ||
		 !isdigit(line[1]) ||
		 !isdigit(line[2]) ||
		 (line[3] != ' ')))
		return;

	response = atoi(line);

	if (lbnc_debug)
		printf("[server] response '%d'\n", response);



	switch(node->server_state) {

	case SERVER_WANT_220:

		if (response != 220)
			break;

		if (SSL_server_control == SSL_CONTROL_DISABLED) {


			server_relay(node, line);
			break;

		}

		// Save the greeting for later.
		SAFE_COPY(node->saved_line, line);

		// Attempt SSL here.
		node->server_state = SERVER_WANT_SSL;
		lion_printf(node->server_control_handle, "AUTH TLS\r\n");
		if (lbnc_debug)
			printf("server->AUTH TLS\n");

		break;


	case SERVER_WANT_SSL:

		// Check if it failed
		if (response >= 500) {

			// Do we enforce SSL?
			if (lbnc_debug)
				printf("[server] failed to upgrade to SSL\n");


			if (SSL_server_control == SSL_CONTROL_ENFORCED) {

				lion_close(node->server_control_handle);
				break;

			}

			// Lets just continue anyway...
			server_relay(node, node->saved_line); // send the 220.
			break;

		}


		if (response == 234) {

			// Start SSL
			lion_ssl_set(node->server_control_handle, LION_SSL_CLIENT);

		}
		break;


	case SERVER_SSL_CMD1:  // PBSZ, don't care what they replied.
		node->server_state = SERVER_SSL_PROT;
		lion_printf(node->server_control_handle, "PROT %c\r\n",
					SSL_server_data == SSL_DATA_INSECURE ?
					'C' : 'P');
		if (lbnc_debug)
			printf("server -> PROT %c\n",
				   SSL_server_data == SSL_DATA_INSECURE ?
				   'C' : 'P');
		break;

	case SERVER_SSL_PROT: // we do care what server says here.

		// Fetch out mode set
		if ((response != 200) &&
			(SSL_server_data == SSL_DATA_SECURE)) {

			if (lbnc_debug)
				printf("[server] can't enforce server data privacy\n");
			lion_close(node->server_control_handle);
		}

		if (response == 200)
			node->server_prot_level = SSL_server_data == SSL_DATA_INSECURE ?
				0 : 1;
		else
			node->server_prot_level = 0;


		server_relay(node, node->saved_line); // send 220
		break;



	case SERVER_SENT_PASV:
		// We have sent PASV, either we get 227, or 425, 426 or 5xx.
		if (response == 227) {

			if (!lion_ftp_pasv( &line[3],
								&node->server_data_host,
								&node->server_data_port)) {

				client_data_reply(node, 0, "parse error");
				break;

			}


			if (lbnc_debug)
				printf("[server] 227 parsed, connecting...\n");

			// Successful... try connecting...
			node->server_data_handle = lion_connect(
													lion_ntoa(node->server_data_host),
													node->server_data_port,
													lbnc_binddataif, 0,
													LION_FLAG_FULFILL,
													(void *) node);

			lion_set_handler(node->server_data_handle, data_server_pasv_handler);
			lion_setbinary(node->server_data_handle);

		}

		if ((response == 425) ||
			(response == 426) ||
			(response >= 500)) {

			client_data_reply(node, 0, line);

		}

		server_relay(node, NULL);

		break;

	case SERVER_SENT_PORT:
		if (response == 200) {  // PORT ok

			//Tell client.. this may turn on read on the client data
			client_data_reply(node, 1, NULL);

			// If the server data isn't connected yet, disable client data
			// so we can't miss stuff.

			// Try 2 XXX
			//if (!lion_isconnected(node->server_data_handle))
			//	lion_disable_read(node->client_data_handle);

		}

		if (response >= 500) {

			client_data_reply(node, 1, line);

		}

		server_relay(node, NULL);
		break;



	case SERVER_RELAY:
		// The most common state, just relay crap to client
		// HOWEVER! We need to capture replies to "FEAT" here, since they
		// might promise capabilities that we do not have implemented.
		// For example, server might advertise AUTH TLS, and we are in non-
		// SSL mode, or CPSV which we don't support (and never will, use
		// CCSN).
		if (line && *line && !strncasecmp("211-", line, 4))
			node->feat = 1;
		else if (line && *line && !strncasecmp("211 ", line, 4)) {
			node->feat = 0;
			// Add our own features now.

			// Add AUTH if we have SSL
			if ((SSL_client_control != SSL_CONTROL_DISABLED)) {
				if (lbnc_debug) printf("[server] Adding in FEAT: AUTH, SSCN and CCSN\n");
				lion_printf(node->client_control_handle,
							" AUTH TLS\r\n SSCN\r\n CCSN\r\n");
			}


		}

		// Censor FEAT command
		if (node->feat && line) {
			int i;

			// Skip leading spaces.
			for (i = 0; line[i]==' '; i++) /* empty */ ;

			if (!strncasecmp("CPSV", &line[i], 4) ||
				!strncasecmp("AUTH", &line[i], 4) ||
				!strncasecmp("SSCN", &line[i], 4) ||
				!strncasecmp("CCSN", &line[i], 4)) {

				if (lbnc_debug)
					printf("[server] censoring FEAT '%s'.\n", line);
				return;
			}
		}

		lion_printf(node->client_control_handle, "%s\r\n", line);
		break;


	default:
		break;

	}



}



















int server_handler(lion_t *handle, void *user_data,
				   int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;

	if (lbnc_debug)
		printf("[server] handler %p/%p %d\n",
			   handle,
			   user_data,
			   status);


	if (!node) return 0;

	switch( status ) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[server] connection lost %d:%s\n", size, line);

		/* fallhrough */
	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[server] connection %p/%p closed.\n", handle, user_data);

		node->server_control_handle = NULL;
		if (node->client_data_handle) lion_close(node->client_data_handle);
		if (node->server_data_handle) lion_close(node->server_data_handle);
		if (node->client_control_handle)
			lion_close(node->client_control_handle);

		//relay_free(node);  // the client close releases the node
		break;

	case LION_CONNECTION_CONNECTED:

		lion_getpeername(handle, &node->server_host, &node->server_port);

		if (lbnc_debug)
			printf("[server] server connected %p/%p %s:%d\n",
				   handle, user_data,
				   lion_ntoa(node->server_host), node->server_port);

		// Do we send the IDEN line here?
		if (lbnc_sendident == 1) {
			lion_printf(node->server_control_handle, "IDEN %s@%s\r\n",
						node->ident ? node->ident : "[lbnc]",
						lion_ntoa(node->client_host));
		}

		if (lbnc_sendident == 2) {
			lion_printf(node->server_control_handle, "IDNT %s@%s:%s\r\n",
						node->ident ? node->ident : "[lbnc]",
						lion_ntoa(node->client_host),
						lion_ntoa(node->client_host));
		}

		if (lbnc_sendident && lbnc_debug)
				printf("[server] sending IDEN/IDNT %s@%s\n",
					   node->ident ? node->ident : "[lbnc]",
					   lion_ntoa(node->client_host));


		break;


	case LION_INPUT:
		if (lbnc_debug)
			printf("[server] %p/%p :%s\n", handle, user_data, line);

		server_input(node, line);

		break;






	case LION_CONNECTION_SECURE_FAILED:
		if (SSL_server_control == SSL_CONTROL_ENFORCED) {

			lion_close(node->server_control_handle);
			break;

		}

		server_relay(node, node->saved_line); // send the 220.
		break;

	case LION_CONNECTION_SECURE_ENABLED:
		if (lbnc_debug)
			printf("server-> PBSZ 0\n");

		node->server_state = SERVER_SSL_CMD1;
		lion_printf(node->server_control_handle, "PBSZ 0\r\n");

		break;




	}

	return 0;

}



void server_port(relay_s *node)
{
	// Open socket
	// send PORT line, await 200 or error
	// send OK but leave client_data disable.
	// on connection OK, enable client data

	// Open listening socket in readiness to reply to PASV
	lion_getsockname(node->server_control_handle,
					 &node->server_data_host,
					 &node->server_data_port);

	// Random port, or pick port.
	node->server_data_port = 0;

	// Lets not open it in FULFILL so we know right away if it fails.
	node->server_data_handle = lion_listen(&node->server_data_port,
										   node->server_data_host,
										   0,
										   (void *) node);

	if (lbnc_debug)
		printf("[server] data port for PORT bound %s:%d\n",
			   lion_ntoa(node->server_data_host),
			   node->server_data_port);

	// Did we fail?
	if (node->server_data_handle) {

		lion_set_handler(node->server_data_handle, data_server_port_handler);
		lion_setbinary(node->server_data_handle);

		lion_printf(node->server_control_handle,
					"PORT %s\r\n",
					lion_ftp_port(node->server_data_host,
								  node->server_data_port));
		node->server_state = SERVER_SENT_PORT;
		return;

	}

	// Failed...
	client_data_reply(node, 0, "server error");

}


void server_pasv(relay_s *node)
{

	// client is pause. Send PASV, expect reply.
	// if good reply, connect,
	// if good, reply good.

	if (lbnc_debug)
		printf("[server] sending PASV\n");

	node->server_state = SERVER_SENT_PASV;
	lion_printf(node->server_control_handle, "PASV\r\n");

}




void server_start_data(relay_s *node, int pasv)
{

	if (lbnc_debug)
		printf("[server] starting data channel\n");


	if (lbnc_onlypasv) {

		server_pasv(node);
		return;

	}

	if (lbnc_onlyport) {

		server_port(node);
		return;

	}

	if (pasv)
		server_pasv(node);
	else
		server_port(node);


}
