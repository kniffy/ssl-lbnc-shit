#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif


#include "lion.h"
#include "lbnc.h"
#include "listener.h"
#include "client.h"
#include "ident.h"

#include "version.h"


#ifdef WIN32
extern int getopt();
extern char *optarg;
extern int optind;
// over-ride main, so we can do Service feature
#define main realmain
int windows_service = 0;
#endif



__RCSID("$lbnc: lbnc.c,v 1.15 2003/04/23 08:32:03 lundman Exp $");





static int master_switch = 0;



// Information of where we are to connect
char *relay_host = "localhost";
int   relay_port = 8080;
int   local_port = 2121;




int lbnc_debug         = 0;                      // debug printings?
int lbnc_master_switch = 0;                      // exit the program

int SSL_server_control = SSL_CONTROL_OPTIONAL;   // SSL level set
int SSL_server_data    = SSL_DATA_SECURE;        // we try to be secure

int SSL_client_control = SSL_CONTROL_OPTIONAL;   // SSL level set
int SSL_client_data    = SSL_DATA_OPTIONAL;      // client decides

int lbnc_onlypasv      = 0;                      // Change PORT into PASV 
int lbnc_onlyport      = 0;                      // Change PASV into PORT

int lbnc_sendident     = 0;                      // Send non-RFC IDEN user@ip

int server_nodata      = 0;                      // Only relay control.

int server_useident    = 0;                      // look up ident for -a IDEN 

unsigned long lbnc_fakeipclient  = 0;
unsigned long lbnc_bindcontrolif = 0;
unsigned long lbnc_binddataif    = 0;





RETSIGTYPE exit_interrupt(RETSIGVALUE)
{

	master_switch = 1;

}












int main(int argc, char **argv)
{

	// Set default pem file, arguments can over-ride
	lion_ssl_rsafile("lbnc.pem");

#ifndef WIN32
	arguments(argc, argv);
#endif


	printf("[SSL]-lbnc FTP Relay Server.\n");

	printf("Version %u.%u Protocol %u.%u build %u (%s@%s) - %s\n\n",
		   VERSION_MAJOR,
		   VERSION_MINOR,
		   PROTOCOL_MAJOR,
		   PROTOCOL_MINOR,
		   VERSION_BUILD,
		   VERSION_USER,
		   VERSION_HOST,
		   VERSION_DATE);
	

	// If they send us INTR or HUP, lets shut down cleanly.
	signal(SIGINT, exit_interrupt);
#ifdef SIGHUP
	signal(SIGHUP, exit_interrupt);
#endif



	printf("Initialising Network...\n");

	lion_init();

	printf("Network Initialised.\n");


#ifdef WITH_SSL

	printf("Initialising SSL...\n");

#if 0
	printf("SSL/TLS Initialised successfully. Server SSL %s, Client SSL %s\n",
		   server_SSL ? "enabled" : "disabled",
		   client_SSL ? "enabled" : "disabled");
#endif
	

#endif




	// Create an initial game
		
	printf("Initialising Socket...\n");


	listener_init();

	
	printf("Running...\n");

        if (!lbnc_debug) {
           if (fork()) exit(0);
           setsid();
        }

	while( !master_switch ) {

		lion_poll(0, IDENT_TIMEOUT);     // This blocks. (by choice, FYI).

		if (server_useident)
			ident_periodical();

	}
	printf("\n");


	printf("Releasing Socket...\n");


	listener_free();


	printf("Socket Released.\n");


	lion_free();

	printf("Network Released.\n");

	printf("Done\n");

	return 0; // Avoid warning
}







void arguments(int argc, char **argv)
{
	int opt;
	
	if (argc <= 1) {
		
		printf("ssl-lbnc - A(nother) FTP Relay Program.\n");
		printf("ssl-lbnc [options] host port\n\n");
		printf("host is best put in IP dot-notation.\n\n");
		printf("  options:\n");
		printf("  -p        : Only use PASV to server (Change clients PORT to PASV)\n");
		printf("  -o        : Only use PORT to server (Change clients PASV to PORT)\n");
		printf("  -d        : debug print\n");
		printf("  -l [port] : Set local listen port\n");
		printf("  -i [ip]   : Force use of 'ip' to reply to PASV to clients (for NATed hosts)\n");
		printf("  -a        : Send non-standard IDEN packet to FTPD (-aa for IDNT)\n");

		printf("  -t        : Enable internal 'SITE STaT' command to view internal state\n");

		printf("  -D        : Dumb mode - do not relay data traffic. [1]\n");

		printf("  -I        : Ident mode - request ident lookup for -a\n");


#ifdef WITH_SSL
		printf("\n***** SERVER SETTINGS (lbnc <=--=> FTP server) *****\n");
		printf("  -s        : Disable SSL on lbnc <--> FTP server connection \n");
		printf("  -S        : Force   SSL on lbnc <--> FTP server connection \n");
		printf("  -v        : Force SSL on Server Data sessions OFF\n");
		printf("  -V        : Force SSL on Server Data sessions ON\n");
		printf("  Default setting is to attempt SSL both on control and data, and fall back\n");
		printf("  to plain if not successful.\n");


		printf("\n***** CLIENT SETTINGS (FTP client <=--=> lbnc) *****\n");

		printf("  -c        : Disable SSL on FTP client <--> lbnc connection \n");
		printf("  -C        : Force   SSL on FTP client <--> lbnc connection \n");
		printf("  -b        : Force SSL on Client Data sessions OFF\n");
		printf("  -B        : Force SSL on Client Data sessions ON\n");
		printf("  Default setting is to allow client to attempt SSL, and to chose PROT level\n");
		printf("  for data sessions.\n");

		printf("\n");
		printf("  -w [ip]   : Optional bind interface for control sessons\n");
		printf("  -W [ip]   : Optional bind interface for data sessons\n");
		printf("\n");

		printf("  -e [path] : Specify egd socket for systems without /dev/random\n");
		printf("  -r [path] : Specify SSL PEM certificate file (lbnc.pem)\n");
		printf("  -L [list] : Specify SSL ciphers wanted\n");
#endif
		printf("\n [1] - Insecure if your aim is to mask the IP of the FTPD\n");
#ifdef WIN32
        fprintf(stderr,"\t -A        - Add as Win32 Service\r\n");
        fprintf(stderr,"\t -U        - Uninstall Win32 Service\r\n");
        fprintf(stderr,"\t(-S pwd    - Start as Win32 Service in pwd)\r\n");
        fprintf(stderr,"\tWarning, option -A [other options] must be specified first\r\n");
#endif


		printf("\n");
		exit(0);
	}


	while ((opt=getopt(argc, argv, 
					   "hpl:odi:atDIw:W:"
#ifdef WITH_SSL
					   "sScCvVbBe:r:L:"
#endif
#ifdef WIN32
					   "AUP:"
#endif
					   )) != -1) {

		switch(opt) {
		case 'p':
			lbnc_onlypasv ^= 1;
			lbnc_onlyport = !lbnc_onlypasv;
			break;

		case 'o':
			lbnc_onlyport ^= 1;
			lbnc_onlypasv = !lbnc_onlyport;
			break;

		case 'd':
			lbnc_debug ^= 1;
			break;

		case 'a':
			lbnc_sendident += 1;
			if (lbnc_sendident > 2)
				lbnc_sendident = 0;
			break;

		case 'l':
			local_port = atoi( optarg );
			break;

		case 'i':
			lbnc_fakeipclient = lion_addr(optarg);
			break;

		case 't':
			//			lbnc_extrastat ^= 1;
			break;

		case 'w':
			lbnc_bindcontrolif = lion_addr(optarg);
			break;

		case 'W':
			lbnc_binddataif = lion_addr(optarg);
			break;

		case 'D':
			server_nodata ^= 1;
			break;

		case 'I':
			server_useident ^= 1;
			break;

#ifdef WITH_SSL
		case 's':
			SSL_server_control = SSL_CONTROL_DISABLED;
			break;
		case 'S':
			SSL_server_control = SSL_CONTROL_ENFORCED;
			break;
		case 'c':
			SSL_client_control = SSL_CONTROL_DISABLED;
			break;
		case 'C':
			SSL_client_control = SSL_CONTROL_ENFORCED;
			break;

		case 'v':
			SSL_server_data = SSL_DATA_INSECURE;
			break;
		case 'V':
			SSL_server_data = SSL_DATA_SECURE;
			break;
		case 'b':
			SSL_client_data = SSL_DATA_INSECURE;
			break;
		case 'B':
			SSL_client_data = SSL_DATA_SECURE;
			break;
		case 'e':
			lion_ssl_egdfile( optarg );
			break;
		case 'r':
			lion_ssl_rsafile( optarg );
			break;
		case 'L':
			lion_ssl_ciphers( optarg );
			break;
#endif

#ifdef WIN32
		case 'A':
			// When started as service, we demand -P dir before the rest, which
			// includes the -A we have to ignore.
			if (!windows_service) {
				windows_service = 1;
				InstallService(argc,argv);
				_exit(0);
			}
			break;
		case 'U':
			UninstallService();
			exit(0);
			break;
		case 'P':
			windows_service = 1;
			chdir(optarg); // change to the workingdir. Services
			//should really let you specify this
			break;
#endif

		case 'h':
			arguments(0, NULL);
			exit(0);
			break;

		default:
			printf("Unknown option.\n");
			break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if (argc == 2) {
		
		relay_host = argv[0];
		relay_port = atoi(argv[1]);
		
	} else {
		
		printf("Also need host and port\n");
		
		exit(0);
	}
	

	// If DUMB mode is set, force both data and control secure off
	// otherwise we would issue PROT on authentication.
	if (server_nodata) {
		SSL_server_data = SSL_DATA_INSECURE;
		SSL_client_data = SSL_DATA_INSECURE;
	}
	
}




//
// This is the default handler for lion. This function should never
// be called since each item in lion will have their own handler set.
//
int lion_userinput( lion_t *handle, void *user_data, 
					int status, int size, char *line)
{

	printf("[lbnc] WARNING! Default lion handler called: %p/%p %d %d:%s\n",
		   handle, user_data,
		   status, 
		   size, line);

	return 0;

}




