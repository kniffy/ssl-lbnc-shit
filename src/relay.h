#ifndef RELAY_H_INCLUDED
#define RELAY_H_INCLUDED


#include "lion.h"
#include <time.h>


enum client_state_enum {
	CLIENT_NONE,
	CLIENT_TOSEND_220,
	CLIENT_SSL,
	CLIENT_GOT_PASV,
	CLIENT_GOT_EPSV,
	CLIENT_GOT_PORT,
	CLIENT_RELAY
};

enum server_state_enum {
	SERVER_NONE,
	SERVER_WANT_220,
	SERVER_WANT_SSL,
	SERVER_SSL_CMD1,
	SERVER_SSL_PROT,
	SERVER_SENT_PASV,
	SERVER_SENT_PORT,
	SERVER_RELAY
};






struct relay_struct {
	lion_t *client_control_handle;
	lion_t *server_control_handle;

	lion_t *client_data_handle;
	lion_t *server_data_handle;

	int server_state;
	int client_state;

	unsigned long client_host;
	int           client_port;

	unsigned long server_host;
	int           server_port;

	unsigned long server_data_host;
	int           server_data_port;

	unsigned long client_data_host;
	int           client_data_port;

	char *saved_line;

	int server_prot_level;
	int client_prot_level;

	lion_t *ident_handle;
	time_t ident_start;
	char *ident;

	unsigned int feat;
	unsigned int client_sscn;
	unsigned int client_ccsn;

};

typedef struct relay_struct relay_s;






relay_s      *relay_new     ( void );
void          relay_free    ( relay_s * );






#endif
