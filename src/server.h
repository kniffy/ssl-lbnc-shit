#ifndef SERVER_H_INCLUDED
#define SERVER_H_INCLUDED

#include "relay.h"





void     server_new        ( relay_s * );
int      server_handler    ( lion_t *, void *, int, int, char * );
void     server_input      ( relay_s *, char * );
void     server_relay      ( relay_s *, char * ); 
void     server_start_data ( relay_s *, int );

#endif
