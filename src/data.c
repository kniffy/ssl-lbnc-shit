#include <stdio.h>

#include "lion.h"
#include "relay.h"
#include "lbnc.h"
#include "client.h"
#include "server.h"
#include "data.h"




void data_check_ready(relay_s *node)
{

	if (lbnc_debug)
		printf("[data] check_ready\n");

	// check if both sides are ready, ie, if no
	// SSL, and both connected, good.
	// if SSL, then make sure it is on.
	if (!node->client_data_handle ||
		!lion_isconnected(node->client_data_handle)) {

		if (lbnc_debug)
			printf("       client is not connected.\n");
		return;
	}

	if (lbnc_debug)
		printf("       client is connected.\n");

	if (node->client_prot_level &&
		!lion_ssl_enabled(node->client_data_handle)) {
        if (node->server_data_handle) {
            if (lbnc_debug)
                printf("    disabling server_data, waiting for SSL.\n");
            //lion_disable_read(node->server_control_handle);
            lion_disable_read(node->server_data_handle);
            // The only way to get SSL through, is to have reading enabled
            if (lbnc_debug)
                printf("    enabling client_data, waiting for SSL.\n");
            lion_enable_read(node->client_data_handle);
        }
		return;
	}

	if (lbnc_debug)
		printf("       client is no-SSL, or SSL is active\n");



	if (!node->server_data_handle) {

        if (lbnc_debug)
            printf("       server is NOT connected.\n");

        if (!lion_isconnected(node->server_data_handle)) {
            if (lbnc_debug)
                printf("       enabling server data\n");
            lion_enable_read(node->server_data_handle);
        }
        return;
    }


	if (lbnc_debug)
		printf("       server is connected.\n");

	if (node->server_prot_level &&
		!lion_ssl_enabled(node->server_data_handle)) {
        if (node->client_data_handle) {
            if (lbnc_debug)
                printf("    disabling client_data, waiting for SSL.\n");
            lion_disable_read(node->client_data_handle);
        }
        return;
    }

	if (lbnc_debug)
		printf("       server is no-SSL, or SSL is active\n");

	if (lbnc_debug)
		printf("       Releasing both server_data and client_data\n");


	lion_enable_read(node->client_data_handle);
	lion_enable_read(node->server_data_handle);
    //lion_enable_read(node->server_control_handle);

}


















//
// This file has:
//
// * client PASV handler
// * client PORT handler
// * server PASV handler
// * server PORT handler
//


int data_client_pasv_handler(lion_t *handle, void *user_data,
						int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;
    unsigned long host;
	int port;


	if (lbnc_debug && (status != LION_BINARY))
		printf("[data] client pasv handler %p/%p %d\n",
			   handle,
			   user_data,
			   status);


	if (!node) return 0;



	switch(status) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[data] connection failed: %d:%s\n",
				   size, line);

		//client_data_reply(node, 0, line);

		/* fall through */

	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[data] connection %p/%p closed.\n",
				   handle, user_data);

		node->client_data_handle = NULL;
		client_data_reply(node, 0, line);

		if (node->server_data_handle)
			lion_close(node->server_data_handle);

		break;

	case LION_CONNECTION_NEW:
		node->client_data_handle = lion_accept(handle,
											   1,
											   LION_FLAG_FULFILL,
											   (void *) node,
											   NULL,
											   NULL);
		// accpet does not inherit handler.
		lion_set_handler(node->client_data_handle, data_client_pasv_handler);
		lion_setbinary(node->client_data_handle);
		break;

	case LION_CONNECTION_CONNECTED:
		lion_getpeername(node->client_data_handle, &host, &port);

		if (lbnc_debug)
			printf("[data] client data connected %s:%d\n",
				   lion_ntoa(host), port);

		// If data should be SSL, fire that up.
		if (node->client_prot_level) {

			if (lbnc_debug)
				printf("[data] client requesting SSL as %s\n",
                       (node->client_sscn|node->client_ccsn) ?
                       "CLIENT(sscn/ccsn)" : "SERVER(normal)");

			lion_ssl_set(node->client_data_handle,
						 (node->client_sscn|node->client_ccsn) ?
						 LION_SSL_CLIENT : LION_SSL_SERVER);

		} else {
            // We need to let SSL communicate, so only disable read until that
            // is done, the SSL function disables read.
            lion_disable_read(node->client_data_handle);
        }
			//data_check_ready(node);
		// 2: }

		// We have conncted to the client side, enable server's data now.
		// That is, if it was PASV (Laststage of phase, us connecting to
		// client).
		// Otherwise, it is PORT, and it is the first step, then we start
		// server side.

		// This is enabling things before the client is ready, which is wrong.
		// lets call check_ready instead.
		//lion_enable_read(node->server_data_handle);
		if (lbnc_debug) printf("[data] data_check_ready 1\n");
		data_check_ready(node);

		break;


	case LION_BINARY:
		if (node->server_data_handle)
			lion_output(node->server_data_handle, line, size);
		break;


	case LION_BUFFER_USED:
		if (node->server_data_handle)
			lion_disable_read(node->server_data_handle);
		break;

	case LION_BUFFER_EMPTY:
		if (node->server_data_handle)
			lion_enable_read(node->server_data_handle);
		break;

	case LION_CONNECTION_SECURE_FAILED:
		if (lbnc_debug)
			printf("[data] client SSL failed.\n");
		if (SSL_client_data == SSL_DATA_SECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\n");
			lion_disconnect(handle);
		}
		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 2\n");
		data_check_ready(node);
		break;

	case LION_CONNECTION_SECURE_ENABLED:
		if (lbnc_debug)
			printf("[data] client SSL successful, disable read\n");

		if (SSL_client_data == SSL_DATA_INSECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel DISABLED\n");
			lion_disconnect(handle);
		}
		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 3\n");
		data_check_ready(node);
		break;

	default:
		break;

	}



	return 0;
}










int data_client_port_handler(lion_t *handle, void *user_data,
							 int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;
    unsigned long host;
	int port;


	if (lbnc_debug && (status != LION_BINARY))
		printf("[data] client port handler %p/%p %d\n",
			   handle,
			   user_data,
			   status);


	if (!node) return 0;



	switch(status) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[data] connection failed: %d:%s\n",
				   size, line);

		client_data_reply(node, 0, line);

		/* fall through */

	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[data] connection %p/%p closed.\n",
				   handle, user_data);

		node->client_data_handle = NULL;
		if (node->server_data_handle)
			lion_close(node->server_data_handle);

		break;



	case LION_CONNECTION_CONNECTED:
		lion_getpeername(node->client_data_handle, &host, &port);

		if (lbnc_debug)
			printf("[data] client PORT data connected %s:%d\n",
				   lion_ntoa(host), port);

		// If data should be SSL, fire that up.
		if (node->client_prot_level) {

			if (lbnc_debug)
				printf("[data] client PORT requesting SSL as %s\n",
						 (node->client_sscn|node->client_ccsn) ?
                       "CLIENT(sscn/ccsn)" : "SERVER(normal)");

			lion_ssl_set(node->client_data_handle,
						 (node->client_sscn|node->client_ccsn) ?
						 LION_SSL_CLIENT : LION_SSL_SERVER);

		} else {

            if (node->client_data_handle)
                lion_disable_read(node->client_data_handle);

        }

		if (lbnc_debug) printf("[data] data_check_ready 4\n");
		data_check_ready(node);
		// 2: }

		// We have conncted to the client side, enable server's data now.
		// That is, if it was PASV (Laststage of phase, us connecting to
		// client).
		// Otherwise, it is PORT, and it is the first step, then we start
		// server side.
		server_start_data( node, 1 ); // 1 suggest we came in as pasv.

		break;


	case LION_BINARY:
		if (node->server_data_handle)
			lion_output(node->server_data_handle, line, size);
		break;


	case LION_BUFFER_USED:
		if (node->server_data_handle)
			lion_disable_read(node->server_data_handle);
		break;

	case LION_BUFFER_EMPTY:
		if (node->server_data_handle)
			lion_enable_read(node->server_data_handle);
		break;

	case LION_CONNECTION_SECURE_FAILED:
		if (lbnc_debug)
			printf("[data] client SSL failed.\n");
		if (SSL_client_data == SSL_DATA_SECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\n");
			lion_disconnect(handle);
		}
		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 5\n");
		data_check_ready(node);
		break;

	case LION_CONNECTION_SECURE_ENABLED:
		if (lbnc_debug)
			printf("[data] client SSL successful\n");

		if (SSL_client_data == SSL_DATA_INSECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel DISABLED\n");
			lion_disconnect(handle);
		}

		if (!handle) return 0;

		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 6\n");
		data_check_ready(node);
		break;

	default:
		break;

	}



	return 0;
}













int data_server_pasv_handler(lion_t *handle, void *user_data,
						int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;



	if (lbnc_debug && (status != LION_BINARY))
		printf("[data] server pasv handler %p/%p %d\n",
			   handle,
			   user_data,
			   status);


	if (!node) return 0;


	switch(status) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[data] connection failed: %d:%s\n",
				   size, line);

		client_data_reply(node, 0, line);
		/* fall through */

	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[data] connection %p/%p closed.\n",
				   handle, user_data);

		node->server_data_handle = NULL;
		if (node->client_data_handle)
			lion_close(node->client_data_handle);

		break;

	case LION_CONNECTION_NEW:
		node->server_data_handle = lion_accept(handle,
											   1,
											   LION_FLAG_FULFILL,
											   (void *) node,
											   NULL,
											   NULL);
		// accept does not inherit handler.
		lion_set_handler(node->server_data_handle, data_server_pasv_handler);
		lion_setbinary(node->server_data_handle);
		break;


	case LION_CONNECTION_CONNECTED:
		if (lbnc_debug)
			printf("[data_server_pasv] connected.\n");

		// Try 2.
		// disable read immediately.
		// enable SSL on if needed.
		// then deal with SSL once both sides are connected.

		// If data should be SSL, fire that up.
        if (node->server_data_handle) {

            if (node->server_prot_level) {
                if (lbnc_debug)
                    printf("[data] server requesting SSL as CLIENT\n");
                lion_ssl_set(node->server_data_handle, LION_SSL_CLIENT);
            }

            // 2: else {
            lion_disable_read(node->server_data_handle);

        }

		if (lbnc_debug) printf("[data] data_check_ready 7\n");
		data_check_ready(node);
		// 2: }

		// This will potentially call reply twice if server is doing
		// PORT method. But since client_state is not set 2nd time it is
		// ignored. But we enable client data here if it was off.
		client_data_reply(node, 1, NULL);
		break;


	case LION_BINARY:
		if (node->client_data_handle)
			lion_output(node->client_data_handle, line, size);
		break;

	case LION_BUFFER_USED:
		if (node->client_data_handle)
			lion_disable_read(node->client_data_handle);
		break;

	case LION_BUFFER_EMPTY:
		if (node->client_data_handle)
			lion_enable_read(node->client_data_handle);
		break;

	case LION_CONNECTION_SECURE_FAILED:
		if (lbnc_debug)
			printf("[data] server SSL failed.\n");

		if (SSL_server_data == SSL_DATA_SECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\n");
			client_data_reply(node, 0, "500 SECURE data channel enforced.\n");
			//lion_disconnect(handle);
		}

		// We need to pause reading here until we are sure the other side is
		// also ready.
		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 8\n");
		data_check_ready(node);
		break;

	case LION_CONNECTION_SECURE_ENABLED:
		if (lbnc_debug)
			printf("[data] server SSL successful\n");

		if (SSL_server_data == SSL_DATA_INSECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel DISABLED\n");
			client_data_reply(node, 0, "500 SECURE data channel DISABLED.\n");
			//lion_disconnect(handle);
		}

		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 10\n");
		data_check_ready(node);
		break;



	default:
		break;

	}



	return 0;
}






int data_server_port_handler(lion_t *handle, void *user_data,
						int status, int size, char *line)
{
	relay_s *node = (relay_s *) user_data;



	if (lbnc_debug && (status != LION_BINARY))
		printf("[data] server port handler %p/%p %d\n",
			   handle,
			   user_data,
			   status);


	if (!node) return 0;


	switch(status) {

	case LION_CONNECTION_LOST:
		if (lbnc_debug)
			printf("[data] connection failed: %d:%s\n",
				   size, line);

		client_data_reply(node, 0, line);
		/* fall through */

	case LION_CONNECTION_CLOSED:
		if (lbnc_debug)
			printf("[data] connection %p/%p closed.\n",
				   handle, user_data);

		node->server_data_handle = NULL;
		if (node->client_data_handle)
			lion_close(node->client_data_handle);

		break;

	case LION_CONNECTION_NEW:
		node->server_data_handle = lion_accept(handle,
											   1,
											   LION_FLAG_FULFILL,
											   (void *) node,
											   NULL,
											   NULL);
		// accpet does not inherit handler.
		lion_set_handler(node->server_data_handle, data_server_port_handler);
		lion_setbinary(node->server_data_handle);
		break;


	case LION_CONNECTION_CONNECTED:
		if (lbnc_debug)
			printf("[data] connected.\n");

		// If data should be SSL, fire that up.
		if (node->server_prot_level) {
			if (lbnc_debug)
				printf("[data] server PORT requesting SSL as CLIENT\n");
			lion_ssl_set(node->server_data_handle, LION_SSL_CLIENT);
		}

		// 2: } else {
		lion_disable_read(node->server_data_handle);

		if (lbnc_debug) printf("[data] data_check_ready 11\n");
		data_check_ready(node);
		// 2: }

		// This will potentially call reply twice if server is doing
		// PORT method. But since client_state is not set 2nd time it is
		// ignored. But we enable client data here if it was off.
		client_data_reply(node, 1, NULL);
		break;


	case LION_BINARY:
		if (node->client_data_handle)
			lion_output(node->client_data_handle, line, size);
		break;

	case LION_BUFFER_USED:
		if (node->client_data_handle)
			lion_disable_read(node->client_data_handle);
		break;

	case LION_BUFFER_EMPTY:
		if (node->client_data_handle)
			lion_enable_read(node->client_data_handle);
		break;

	case LION_CONNECTION_SECURE_FAILED:
		if (lbnc_debug)
			printf("[data] server SSL failed.\n");

		if (SSL_server_data == SSL_DATA_SECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel enforced.\n");
			client_data_reply(node, 0, "500 SECURE data channel enforced1.\n");
			//lion_disconnect(handle);
		}
		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 12\n");
		data_check_ready(node);
		break;

	case LION_CONNECTION_SECURE_ENABLED:
		if (lbnc_debug)
			printf("[data] server SSL successful\n");

		if (SSL_server_data == SSL_DATA_INSECURE) {
			lion_printf(node->client_control_handle,
						"500 SECURE data channel DISABLED\n");
			lion_disconnect(handle);
		}
		lion_disable_read(handle);

		if (lbnc_debug) printf("[data] data_check_ready 13\n");
		data_check_ready(node);
		break;



	default:
		break;

	}



	return 0;
}

