#ifndef IDENT_H_INCLUDED
#define IDENT_H_INCLUDED


#define IDENT_PORT 113
#define IDENT_TIMEOUT 10




void   ident_new               ( relay_s * );
void   ident_periodical        ( void );
void   ident_reply             ( relay_s *, char * ); 

#endif
