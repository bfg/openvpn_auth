/**
 * Copyright (c) 2006, Branko F. Gracnar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * + Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 * + Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 * + Neither the name of the Branko F. Gracnar nor the names of its contributors
 *   may be used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * $Id:openvpn_auth_client.c 188 2007-03-29 11:39:03Z bfg $
 * $LastChangedRevision:188 $
 * $LastChangedBy:bfg $
 * $LastChangedDate:2007-03-29 13:39:03 +0200 (Thu, 29 Mar 2007) $
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <getopt.h>
#include <stdarg.h>
#include <syslog.h>
#include <ctype.h>
#include <signal.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <termio.h>

#define VERSION "0.11"

#define CRED_BUF_SIZE 512
#define GEN_BUF_SIZE 1024
#define CONF_FILE_MAXLINES 1000
#define STR_SEP "="

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 1559
#define DEFAULT_AUTH_TIMEOUT 10

/**
 * Global configuration variables
 */
char hostname[GEN_BUF_SIZE];					/** authentication server hostname or unix domain socket */
int port = DEFAULT_PORT;						/** authentication server listening port */
int timeout = DEFAULT_AUTH_TIMEOUT;				/** default authentication timeout */
int verbose = 0;

/**
 * Other runtime variables
 */
char *MYNAME = NULL;

/**
 * authentication data structure
 */
struct auth {
	char	*username;
	char	*password;
	char	*common_name;
	char	*untrusted_ip;
	int		untrusted_port;
};

int server_socket = 0;

char var_buf[GEN_BUF_SIZE];
char val_buf[GEN_BUF_SIZE];

char *config_files[] = {
	"/etc/openvpn_authc.conf",
	"/etc/openvpn/openvpn_authc.conf",
	"/usr/local/etc/openvpn_authc.conf",
	"/usr/local/etc/openvpn/openvpn_authc.conf",
	".openvpn_authc.conf"
};

void chomp (char *str) {
	int len = 0;
	len = strlen(str);
	int i = len - 1;

	while (i >= 0) {
		if (str[i] == '\f' || str[i] == '\r' || str[i] == '\n') {
			str[i] = '\0';
			i--;
		}
		else
			break;
	}
}

/**
 * logs message and optionally prints it to STDERR
 * @param char * printf(3) format string
 * @param printf arguments
 * @returns void
 */
void log_msg (const char *str, ...) {
	va_list args;
	
	/** print to syslog */
	openlog(MYNAME, (LOG_PID|LOG_ODELAY), LOG_AUTHPRIV);
	va_start(args, str);
	vsyslog(LOG_INFO, str, args);
	va_end(args);
	closelog();

	/** print to stderr */
	if (verbose) {
		va_start(args, str);
		vfprintf(stderr, str, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * initializes authentication structure
 */
struct auth * authstruct_init (void) {
	struct auth *ptr;
	if ((ptr = malloc(sizeof(struct auth))) == NULL) return NULL;

	/* we have a basic structure, allocate memory for internal properties */
	ptr->username = (char *) malloc(CRED_BUF_SIZE);
	if (ptr->username == NULL) {
		free(ptr);
		log_msg("Unable to allocate memory for authentication structure.");
		return NULL;
	}

	ptr->password = (char *) malloc(CRED_BUF_SIZE);
	if (ptr->password == NULL) {
		free(ptr->username);
		free(ptr);
		log_msg("Unable to allocate memory for authentication structure.");
		return NULL;
	}
	
	/** wipe memory */
	memset(ptr->username, '\0', CRED_BUF_SIZE);
	memset(ptr->password, '\0', CRED_BUF_SIZE);

	return ptr;
}

void authstruct_destroy (struct auth *ptr) {
	if (ptr != NULL) {
		if (ptr->username != NULL) free(ptr->username);
		if (ptr->password != NULL) free(ptr->password);		
		/* destroy structure */
		free(ptr);
	}
}

/**
 * prints help message
 */
void printhelp (void) {
	int i;

	fprintf(stderr, "Usage: %s [OPTIONS] [FILE]\n\n", MYNAME);
	fprintf(stderr, "This is a OpenVPN --auth-user-pass-verify helper program, which contacts OpenVPN\n");
	fprintf(stderr, "custom authentication server. All messages are logged into syslog.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "OPTIONS:\n");
	fprintf(stderr, "  -c   --config           Specifies configuration file\n");
	fprintf(stderr, "  -d   --default-config   Prints out default configuration file.\n");
	fprintf(stderr, "  -H   --hostname         Authentication server hostname or UNIX\n");
	fprintf(stderr, "                          domain socket (Default: \"%s\")\n", hostname);
	fprintf(stderr, "  -p   --port             Authentication server listening port if not using\n");
	fprintf(stderr, "                          UNIX domain socket as hostname (Default: %d)\n", port);
	fprintf(stderr, "  -t   --timeout          Authentication timeout in seconds (Default: %d)\n", timeout);
	fprintf(stderr, "\n");

	fprintf(stderr, "CONFIGURATION FILE AUTO LOAD ORDER:\n");
	fprintf(stderr, "Becouse of specifics of openvpn(8) daemon, this program automatically\n");
	fprintf(stderr, "tries to load configuration files in the following order:\n\n");	
	for (i = 0; i < 5; i++)
		fprintf(stderr, "\t%s\n", config_files[i]);
	fprintf(stderr, "\n");
	fprintf(stderr, "Process of parsing configuration files stops when first\n");
	fprintf(stderr, "first existing file has been successfully parsed.\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "TEST MODE OPTIONS:\n");
	fprintf(stderr, "You can use \"test mode\" to test client's credentials from\n");
	fprintf(stderr, "command line.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  -U   --user             Username\n");
	fprintf(stderr, "  -P   --pass             User's password\n");
	fprintf(stderr, "  -C   --cn               Certificate common name\n");
	fprintf(stderr, "  -X   --client-ip        VPN client's IP address\n");
	fprintf(stderr, "  -Y   --client-port      VPN client's connection source port number\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "OTHER OPTIONS:\n");
	fprintf(stderr, "  -h   --help             This little help\n");
	fprintf(stderr, "  -V   --version          Prints out program version\n");
}

void print_default_config (void) {
	printf("#\n");
	printf("# WHAT: openvpnc sample configuration file\n");
	printf("#\n");
	printf("# NOTES: \n");
	printf("# - empty lines are ignored.\n");
	printf("# - lines started with hash (#) are ignored.\n");
	printf("# - invalid parameters are ignored.\n");
	printf("#\n");
	printf("\n");
	printf("# Authentication server IP address, full qualified domain name (FQDN) or socket file\n");
	printf("# Type: string\n");
	printf("# Default: %s\n", DEFAULT_HOSTNAME);
	printf("hostname = %s\n", DEFAULT_HOSTNAME);
	printf("\n");
	printf("\n");
	printf("# Authentication server listening port.\n");
	printf("# NOTE: this option is silently ignored if\n");
	printf("# hostname is path to unix domain socket file\n");
	printf("#\n");
	printf("# Type: integer\n");
	printf("# Default: %d\n", DEFAULT_PORT);
	printf("port = %d\n", DEFAULT_PORT);
	printf("\n");
	printf("# Authentication timeout in seconds\n");
	printf("# Assume, that authentication has failed\n");
	printf("# if authentication server has not replied\n");
	printf("# in specified amount of seconds.\n");
	printf("#\n");
	printf("# Type: integer\n");
	printf("# Default: %d\n", DEFAULT_AUTH_TIMEOUT);
	printf("timeout = %d\n", DEFAULT_AUTH_TIMEOUT);
	printf("\n");
	printf("# EOF\n");
}

int sigh_alrm (int num) {
	log_msg("Authentication timeout (%d seconds) exceeded.", timeout);
	exit(1);
}

char * config_get_param (char *str) {
	char *ptr;
	int i;

	if (str == NULL) return NULL;
	/** empty string? */
	if (strlen(str) < 1 || str[0] == '\n' || strcmp(str, "\r\n") == 0) return NULL;

	ptr = str;
	
	/** comments? */
	if (str[0] == '#') return NULL;
	/** first alpha character */
	while (ptr != NULL && ! isalpha(*ptr))
		ptr++;

	/** overwrite alpha chars */
	memset(var_buf, '\0', sizeof(var_buf));
	i = 0;
	while(ptr != NULL && isalnum(*ptr)) {
		var_buf[i] = *ptr;
		i++;
		ptr++;
	}

	if (strlen(var_buf) < 1) return NULL;
	return var_buf;
}

char * config_get_value (char *str) {
	char *ptr;
	int i = 0;

	if (str == NULL) return NULL;
	if (strlen(str) < 1) return NULL;
	
	/** find '=' char */
	ptr = str;
	while (ptr != NULL && (*ptr) != '=')
		ptr++;
	ptr++;
	
	/** skip whitespaces **/
	while (ptr != NULL && ! isgraph(*ptr))
		ptr++;

	/** no value found? */
	if (ptr == NULL) return NULL;

	/** overwrite alpha chars */
	memset(val_buf, '\0', sizeof(val_buf));
	while(ptr != NULL && isgraph(*ptr)) {
		val_buf[i++] = *ptr;
		ptr++;
	}

	if (strlen(val_buf) < 1) return NULL;
	return val_buf;
}

/**
 * loads configuration file
 * @param configuration file
 * @return 1 on success, otherwise false
 */
int load_config_file (char *file) {
	FILE *fd;
	char buf[GEN_BUF_SIZE];
	char *var, *val;

	if (file == NULL) {
		log_msg("Unspecified configuration file (file == NULL)");
		return 0;
	}
	else if ((fd = fopen(file, "r")) == NULL) {
		/** log_msg("Unable to open configuration file '%s': %s", file, strerror(errno));
		*/
		return 0;
	}

	int lines = 0;
	
	/* read and parse config */
	while (lines < CONF_FILE_MAXLINES) {
		memset(buf, '\0', sizeof(buf));
		if (fgets(buf, sizeof(buf), fd) == NULL) break;
		lines++;
		
		var = config_get_param(buf);
		if (var == NULL) continue;
		val = config_get_value(buf);
		if (val == NULL) continue;
		
		if (strcmp(var, "hostname") == 0) {
			strncpy(hostname, val, sizeof(hostname));
		}
		else if (strcmp(var, "port") == 0)
			port = (val != NULL) ? atoi(val) : DEFAULT_PORT;
		else if (strcmp(var, "timeout") == 0)
			timeout = (val != NULL) ? atoi(val) : DEFAULT_AUTH_TIMEOUT;
		else
			log_msg("Warning: unknown configuration parameter '%s' in configuration file '%s' line %d.", var, file, lines);
	}

	fclose(fd);
	return 1;
}

/**
 * search for first valid configuration file
 */
void load_config_files (void) {
	int i;
	for (i = 0; i < 5; i++) {
		if (load_config_file(config_files[i])) {
			/** printf("Configuration file %s has been successfully parsed.\n", config_files[i]); */
			break;
		}
	}
}


/**
 * Fetches username and password
 * @param username
 * @param password
 * @param file
 * @return 1 on success, otherwise 0
 */
int credentials_retr (struct auth *ptr, char *file) {
	FILE *fd;
	char *tmp;
	char fbuf[CRED_BUF_SIZE];
	int len = 0;
	
	if (file == NULL) {
		tmp = getenv("username");
		if (tmp != NULL)
			strncpy(ptr->username, tmp, CRED_BUF_SIZE);

		tmp = getenv("password");
		if (tmp != NULL)
			strncpy(ptr->password, tmp, CRED_BUF_SIZE);

	} else {
		if ((fd = fopen(file, "r")) == NULL) {
			log_msg("Unable to open credentials file %s: %s", file, strerror(errno));
			return 0;
		}

		/* read username */
		if (fgets(fbuf, sizeof(fbuf), fd) == NULL) {
			log_msg("Unable to read username from file: %s", strerror(errno));
			return 0;
		}

		len = strlen(fbuf);
		if (fbuf[len - 1] == '\n') fbuf[len - 1] = '\0';
		strncpy(ptr->username, fbuf, sizeof(fbuf));

		/* read password */
		if (fgets(fbuf, sizeof(fbuf), fd) == NULL) {
			log_msg("Unable to read password from file: %s", strerror(errno));
			return 0;
		}
		len = strlen(fbuf);
		if (fbuf[len - 1] == '\n') fbuf[len - 1] = '\0';
		strncpy(ptr->password, fbuf, sizeof(fbuf));

		/** close file */
		fclose(fd);
	}

	/* retrieve other stuff from environment */
	ptr->common_name = getenv("common_name");
	if (ptr->common_name == NULL) {
		log_msg("Warning: environmental variable common_name is not set.");
		ptr->common_name = "";
	}
	ptr->untrusted_ip = getenv("untrusted_ip");
	if (ptr->untrusted_ip == NULL) {
		log_msg("Warning: environmental variable untrusted_ip is not set.");
		ptr->untrusted_ip = "";
	}

	tmp = getenv("untrusted_port");
	if (tmp == NULL) {
		log_msg("Warning: environmental variable untrusted_port is not set.");
		ptr->untrusted_port = 0;
	} else
		ptr->untrusted_port = atoi(tmp);

	return 1;
}

/**
 * Connects to authentication server
 * @return FILE* server socket filehandle on success, otherwise NULL
 */
FILE * srv_connect (void) {
	FILE *socketfd = NULL;	/** socket-wrapped filedescriptor */
	struct sockaddr_un server_addr_un;
	struct sockaddr_in local_addr, server_addr;

	/* inet or unix domain socket? */
	if (hostname[0] == '/') {
		log_msg("Connecting to authentication server using UNIX domain socket %s.", hostname);
		/** create unix socket */
		if ((server_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			log_msg("Unable to create UNIX domain socket: %s (errno %d).", strerror(errno), errno);
		}
		server_addr_un.sun_family = AF_UNIX;
		strncpy(server_addr_un.sun_path, hostname, 108);
		
		int len = sizeof(server_addr_un.sun_family) + strlen(server_addr_un.sun_path);
	
		/** connect to server */
		if (connect(server_socket, (const struct sockaddr *) &server_addr_un, len) < 0) {
			log_msg("Unable to connect to %s: %s (errno %d).", hostname, strerror(errno), errno);
			close(server_socket);
			return NULL;
		}
	} else {
		log_msg("Connecting to authentication server %s:%d using TCP socket.", hostname, port);
		struct hostent *h;		/** hostentry */
		/** resolve */
		if ((h = gethostbyname(hostname)) == NULL) {
			log_msg("Unable resolve %s: %s (errno %d).", hostname, strerror(errno), errno);
			return NULL;
		}

		if (h == NULL) {
			log_msg("do_it(), line %d: (h->h_addr_list[0] == NULL) This is weird and should never happen!", __LINE__);
			return NULL;
		}

		server_addr.sin_family = h->h_addrtype;
		memcpy((char *) &server_addr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
		server_addr.sin_port = htons(port);

		/** create inet socket */
		if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			log_msg("Unable to create INET socket: %s (errno %d).", strerror(errno), errno);
		}

		/** bind any port number */
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		local_addr.sin_port = htons(0);

		if (bind(server_socket, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
			log_msg("Unable to bind %s:%d sock: %s (errno %d).", hostname, port, strerror(errno), errno);
		}

		/** connect to server */
		if (connect(server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
			log_msg("Unable to connect to %s:%d: %s (errno %d).", hostname, port, strerror(errno), errno);
			close(server_socket);
			return NULL;
		}
	}

	/** wrap socket to filedescriptor */
	if ((socketfd = fdopen(server_socket, "r+")) == NULL) {
		log_msg("Unable to create stream fd: %s (errno %d).", strerror(errno), errno);
		close(server_socket);
		return NULL;
	}

	return socketfd;
}

void srv_disconnect (FILE *socketfd) {
	fclose(socketfd);
	close(server_socket);
}

/**
 * performs authentication
 * @param ptr authentication structure
 * @return integer 1 on success, otherwise 0
 */
int authenticate (struct auth *ptr) {
	char write_buf[GEN_BUF_SIZE];	/** socket fd write buffer */
	char read_buf[GEN_BUF_SIZE];	/** socket fd read buffer */
	FILE *sock = NULL;
	char srv_code[4];
	int result = 0;
	
	/** connect to server */
	if ((sock = srv_connect()) == NULL)
		return 0; 

	/** format authentication string */
	snprintf(
		write_buf,
		sizeof(write_buf),
		"username=%s\npassword=%s\ncommon_name=%s\nhost=%s\nport=%d\n\n",
		ptr->username,
		ptr->password,
		ptr->common_name,
		ptr->untrusted_ip,
		ptr->untrusted_port
	);

	/** send it to server and flush buffers */
	fprintf(sock, "%s", write_buf);
	fflush(sock);

	/* read response from server */
	if (! fgets(read_buf, sizeof(read_buf), sock)) {
		log_msg("No response read from authentication server: %s (errno %d)", strerror(errno), errno);
		goto outta_func;
	}
	else if (strlen(read_buf) < 3) {
		log_msg("Invalid response from server: %s", read_buf);
		goto outta_func;
	}

	/** chop result code and message */
	memset(srv_code, '\0', sizeof(srv_code));
	chomp(read_buf);
	strncpy(srv_code, read_buf, 2);

	if (strcasecmp(srv_code, "OK") != 0)
		log_msg("Authentication FAILED for user '%s': %s", ptr->username, read_buf);
	else {
		log_msg("Authentication SUCCEEDED for user '%s'", ptr->username);
		result = 1;
	}

	outta_func:

	/* close socket */
	srv_disconnect(sock);

	return result;
}

/**
 * main routine
 */
int main (int argc, char **argv) {
	/** command line parsing */
	extern char *optarg;
	extern int optind;
	char *tmp;
	struct auth *auth_str;
	struct sigaction act;
	struct termio tty, oldtty;
	int cred_from_cmdl = 0;

	MYNAME = basename(argv[0]);
	strncpy(hostname, DEFAULT_HOSTNAME, sizeof(hostname));

	/** try to load configuration files */
	load_config_files();

	/** initialize authentication structure */
	if ((auth_str = authstruct_init()) == NULL) {
		log_msg("Unable to initialize authentication structure... Possibly out of memory.");
		return 1;
	}

	/* configure command line parser */
	static struct option long_options[] = {
		/* These options set a flag. */
		{"default-config", no_argument, NULL, 'd'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{"help", no_argument, NULL, 'h'},

		/* These options require argument */
		{"config", required_argument, NULL, 'c'},
		{"hostname", required_argument, NULL, 'H'},
		{"port", required_argument, NULL, 'p'},

		{"user", required_argument, NULL, 'U'},
		{"pass", required_argument, NULL, 'P'},
		{"cn", required_argument, NULL, 'C'},
		{"client-ip", required_argument, NULL, 'X'},
		{"client-port", required_argument, NULL, 'Y'},
	};

	
	/* parse command line */
	int r = 1;
	int opt_idx = 0;		/* option index */
	while (r) {
		int c = 0;			/* option character */
		c = getopt_long(argc, argv, "c:H:p:U:P:C:X:Y:vhdV", long_options, &opt_idx);

		switch (c) {
			case 'c':
				if (! load_config_file(optarg)) {
					fprintf(stderr, "Unable to parse config file '%s': %s\n", optarg, strerror(errno));
					return 1;
				}
				break;
			case 'H':
				strncpy(hostname, optarg, sizeof(hostname));
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'U':
				strncpy(auth_str->username, optarg, CRED_BUF_SIZE);
				cred_from_cmdl = 1;
				break;
			case 'P':
				strncpy(auth_str->password, optarg, CRED_BUF_SIZE);
				cred_from_cmdl = 1;
				break;
			case 'C':
				auth_str->common_name = optarg;
				cred_from_cmdl = 1;
				break;
			case 'X':
				auth_str->untrusted_ip = optarg;
				cred_from_cmdl = 1;
				break;
			case 'Y':
				auth_str->untrusted_port = atoi(optarg);
				cred_from_cmdl = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'd':
				print_default_config();
				return 0;
				break;
			case 'h':
				printhelp();
				return 0;
				break;
			case 'V':
				printf("%s %s\n", MYNAME, VERSION);
				return 0;
				break;
			case '?':
				log_msg("Invalid command line options. Run %s --help for instructions\n", basename(argv[0]));
				return 1;
				break;
			default:
				r = 0;
				break;
		}
	}

	/** check if we're really called as openvpn argument */
	if ((tmp = getenv("script_type")) == NULL || (strcmp(tmp, "auth-user-pass-verify") != 0 && strcmp(tmp, "user-pass-verify") != 0)) {
		log_msg("Program is not executed as --auth-user-pass-verify openvpn server argument. Environment variable \"script_type\" != \"(auth-)?user-pass-verify\" (%s)", tmp);
		cred_from_cmdl = 1;
	}

	/** openvpn server mode? */
	if (! cred_from_cmdl) {
		/** retrieve credentials */
		if (! credentials_retr(auth_str, argv[optind]))
			return 1;
	}
	/** testing mode? */
	else {
		verbose = 1;
		log_msg("Program invoked in TEST mode.");
		
		/** no provided password? */
		if (strlen(auth_str->password) < 1 ) {
			printf("No password was given from command line.\n");
			printf("Password: ");
			
			/**
			 ** Save the old tty settings, and get rid of echo
			 ** for the new tty settings
			 **/
			ioctl(0, TCGETA, &oldtty);
			tty = oldtty;
			tty.c_lflag    &= ~(ICANON|ECHO|ECHOE|ECHOK|ECHONL);
			tty.c_cc[VMIN]  = 1;
			tty.c_cc[VTIME] = 0;
			ioctl(0, TCSETA, &tty);
			
			/** read password */
			fgets(auth_str->password, CRED_BUF_SIZE, stdin);
			chomp(auth_str->password);
			
			/** reset old tty settings */
			ioctl(0, TCSETA, &oldtty);
			printf("\n");
		}

		fprintf(stderr, "\n--- VERBOSE OUTPUT ---\n");
	}
	
	/** install signal handler */
	act.sa_handler = sigh_alrm;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGALRM, &act, NULL) != 0) {
		fprintf(stderr, "Unable to install ALRM (authentication timeout) signal handler: %s\n", strerror(errno));
		return 1;
	}
	alarm(timeout);

	/** perform authentication */
	r = authenticate(auth_str);
	
	if (cred_from_cmdl) {
		fprintf(stderr, "--- VERBOSE OUTPUT ---\n\n");
		printf("Authentication %s.\n", ((r) ? "SUCCEEDED" : "FAILED"));
	}

	/** cleanup */
	authstruct_destroy(auth_str);

	return (! r);
}
