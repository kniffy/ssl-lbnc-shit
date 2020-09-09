#ifndef LISTENER_H_INCLUDED
#define LISTENER_H_INCLUDED

#include "lion.h"





















void       listener_init        ( void );
void       listener_free        ( void );

int        listener_handler     ( lion_t *, void *,	int, int, char * );



#endif
