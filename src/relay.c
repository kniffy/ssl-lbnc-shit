#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#endif

#include "lion.h"
#include "misc.h"
#include "relay.h"






relay_s *relay_new( void )
{
	relay_s *result;

	result = (relay_s *) malloc(sizeof(*result));

	if (!result) return NULL;

	memset(result, 0, sizeof(*result));

	return result;

}


void relay_free(relay_s *node)
{

	if (node->client_control_handle) 
		printf("[relay] client_control_handle %p not NULL\n", 
			   node->client_control_handle);
	if (node->server_control_handle) 
		printf("[relay] server_control_handle %p not NULL\n", 
			   node->server_control_handle);
	if (node->client_data_handle) 
		printf("[relay] client_data_handle %p not NULL\n", 
			   node->client_data_handle);
	if (node->server_data_handle) 
		printf("[relay] server_data_handle %p not NULL\n", 
			   node->server_data_handle);

	if (node->ident_handle) 
		printf("[relay] ident_handle %p not NULL\n", 
			   node->ident_handle);

	SAFE_FREE(node->saved_line);
	
	SAFE_FREE(node->ident);

	SAFE_FREE(node);

}


