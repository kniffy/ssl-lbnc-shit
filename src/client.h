#ifndef CLIENT_H_INCLUDED
#define CLIENT_H_INCLUDED

#include "lion.h"
#include "relay.h"




















void  client_input      ( relay_s *, char * );
int   client_pasv       ( relay_s * );
int   client_epsv       ( relay_s * );
int   client_port       ( relay_s *, char * );
void  client_sscn       ( relay_s *, char * );
void  client_ccsn       ( relay_s *, char * );

void  client_data_reply ( relay_s *, int, char * );

int   client_handler    ( lion_t *, void *, int, int, char * );





#endif
