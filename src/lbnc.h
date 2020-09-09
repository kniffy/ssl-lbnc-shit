#ifndef LBNC_H_INCLUDED
#define LBNC_H_INCLUDED

/* Defines */

#define VERSION_MAJOR  0
#define VERSION_MINOR  1
#define PROTOCOL_MAJOR 1
#define PROTOCOL_MINOR 0


enum SSL_control {
	SSL_CONTROL_OPTIONAL,
	SSL_CONTROL_ENFORCED,
	SSL_CONTROL_DISABLED
};

enum SSL_data {
	SSL_DATA_OPTIONAL,
	SSL_DATA_INSECURE,
	SSL_DATA_SECURE
};


/* Variables */

extern int   local_port;
extern int   lbnc_debug;
extern char *relay_host;
extern int   relay_port;
extern int   SSL_server_control;
extern int   SSL_server_data;
extern int   lbnc_sendident;

extern int   SSL_client_control;
extern int   SSL_client_data;

extern int   lbnc_onlypasv;
extern int   lbnc_onlyport;
extern int   server_nodata;
extern int   server_useident;

extern unsigned long lbnc_fakeipclient;
extern unsigned long lbnc_bindcontrolif;
extern unsigned long lbnc_binddataif;







/* Functions */









int        main         ( int, char ** );
void       arguments    ( int, char ** );


#endif
