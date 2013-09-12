/*
	Proxy HTTP throw cisco telnet.
--------------------------------------------------------------------------------
	Command line parameters :
	<local ip>		- ip use to connect to telnet, may be some Eth or aliases ;
	<cisco ip>		- remote cisco ip address ;
	<host ip>		- what ip address or interfece use cisco to telnet to host;
	<device ip>		- remote host ip address ;
	<proxy http port>	- browser send requiest port, default 8080 for not root ;
	<time-out>		- time-out to wait from remote host in seconds;
	<log on/off>- 	1/0 create on/off text log file

	Alternative version of command strting with getoptlong():
	-l <local ip>		- ip use to connect to telnet, may be some Eth or aliases ;
	-c <cisco ip>		- remote cisco ip address ;
	-h <host ip>		- what ip address or interfece use cisco to telnet to host;
	-r <device ip>		- remote host ip address ;
	-p {proxy http port}	- browser send requiest port, default 8080 for not root ;
	-t {time-out}		- time-out to wait from remote host in seconds;
	-l {log on/off}		- 1/0 create on/off text log file;

--------------------------------------------------------------------------------
	Use forked as child standardt telnet program to connect cisco terminal.
	Parent part listen() for one http tcp request, accept(), receive tcp
	packet and send to telnet via pipe
	This version program asks login/password/enable from console.
	Telnet result view on terminal without echo.
--------------------------------------------------------------------------------
	http		->	pipe_0[N_OUTPUT]	->	dup2(n_pipe_0[N_INPUT], 0)	->	telnet stdin;
				^
	stdin		------>|
	http		<-	pipe_1[N_INPUT]	<-	dup2(n_pipe_1[N_OUTPUT], 1)	<-	telnet stdout;
	stdout	<------|
--------------------------------------------------------------------------------
	Main TCP process listen for connection from browser or telnet pipe.
	On receive listen accept http socket, receive all buffer if framents on tcp parts.
	Send http buffer to telnet pipe.
	If http status is active after receive request and from cisco telnet was received :
	- "[Connection to "  close by foreing host ;
	- chumked \n\n line end;
	- time-out ;
	send telnet receive buffer to http socket, close socket.
*/

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/file.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<string.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<time.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>
#include	<sys/ipc.h>
#include	<sys/shm.h>

#if defined(__linux__)
#include	<malloc.h>
#include	<getopt.h>
#endif

#include	<termios.h>	// local echo off/on;

//--------------------------------------------------------------------------------
//	DEBUG Log file ;
#define		_DBG_LOG		1
//--------------------------------------------------------------------------------
#define	SZ_MAX_SIZE		256
#define	SZ_MAX_SIZE_1		255

#define	N_MAX_TIMEOUT	1000			// time-out step in mseconds;
#define	N_INPUT			0			// stdin pipe index;
#define	N_OUTPUT			1			// stdout pipe index;

#define	TEST_HTTP_PORT		8080		// default http listen port;
#define	TEST_TELNET_TIMEOUT	1		// time-out step in seconds;
#define	N_MAX_LISTEN			1		// number socket to accept;
#define	N_HTTP_BF_SIZE		(64*1024)	// in/out http tcp buffer in bytes;
#define	N_HTTP_BF_SIZE_1	(N_HTTP_BF_SIZE - 1)
									// command line arg indexes;
#define	N_MIN_ARGC			4
#define	N_ARG_LOCAL_IP		1
#define	N_ARG_CISCO_IP		2
#define	N_ARG_HOST_IP			3
#define	N_ARG_DEVICE_IP		4
#define	N_ARG_DEVICE_PORT		5
#define	N_ARG_TIMEOUT		6
#ifdef	_DBG_LOG						// if _DBG_LOG, look for agr[7] in coomand line ;
	#define	N_ARG_LOG_FILE_KEY		7
#endif

#define	N_SOCKET_NOT_ALLOW	-1		// use to for closed socket;

#define	SZ_TEMP_TEST			256
#define	SZ_TEMP_TEST_1		255
									// end-of chunked http receive case line; 
#define	SZ_CHUNKED_FIN		"\x0a\x30\x0d\x0a\x0d\x0a"
#define	N_CHUNKED_FIN_SIZE_1	5
#define	N_CHUNKED_FIN_SIZE	6
									// cisco "connection to x.x.x.x closed by foreign host" message
									//  - end of remote telnet session;
#define	SZ_CONNECT_FIN		"[Connection to "
#define	N_CONNECT_FIN_SIZE_1	14
#define	N_CONNECT_FIN_SIZE	15

//--------------------------------------------------------------------------------
void echo_off(void);
void echo_on(void);
void	set_signal_handler();
void	signal_close_app(int signal);
int	allocate_http_buffers();
void	call_telnet_client(char *sz_cisco_ip);
int	telnet_2_http();
int	read_telnet_pipe();
int	process_http();
int	create_listen_http();
void	set_select_field();
int	process_stdin();
int	accept_http();
int	recv_http();
void	send_telnet_connect_http(char *sz_host_ip, char *sz_device_ip);
//int	find_host_ip(char *p_bf, int *p_length_1, int *p_length_2,
//			     int n_bf_length, char *sz_ip);
void	close_http_socket();
int	process_http_pipe();
void	find_telnet_wait();
int	get_arg(int argc, char **argv);
//void	http_filtr_http_header(char *p_bf_in, char *p_bf_out,
//				char *p_bf_temp, int *p_bf_size);
int	test_print(char c);
//	From RADIUS.util.c, UINT4 set (unsigned int);
void ipaddr2str(char *buffer, unsigned int ipaddr);
unsigned int ipstr2long(char *ip_str);
char *strNcpy(char *dest, char *src, int n);

//--------------------------------------------------------------------------------
//						Global variables;
	char	c_temp;				// temp input from telnet pipe;
	int	n_cancel_signal = 0;		// close siglan from signal_handler;

	int		n_pipe_0[2];		// duplex pipe - telnet stdin;
	int		n_pipe_1[2];		// duplex pipe - telnet stdoput;
	pid_t		n__telnet_pid;		// tlenet process id;

	fd_set	n_read_fds;		// common (http tcp, telnet pipe fd)  select() parameters;
	struct timeval	tm_val;
	int		n_select;
	int		n_time_out;
							// http tcp sockets;
	int 		n_listen_socket = N_SOCKET_NOT_ALLOW;
	int		n_http_socket = N_SOCKET_NOT_ALLOW;
							// ;
	char		*p_http_bf_in;		// http buffers	- receive from browser;
	char		*p_http_bf_out;		// 			- receive from telnet stdout and send to browser;
//	char		*p_http_bf_temp;	// 			- was used to parse http header;

//	char		sz_temp[SZ_MAX_SIZE];
//	char		sz_http_send[SZ_MAX_SIZE];

	int		n_exit;			// global exit() code;
	int		n_wait_http;		// set 1 after accetp() http socket, receive http, set 0 after send http and close accept() socket;
							// indicate to telnet - READY to get remote device and send to http; 
//	int		n_load_http;
	int		n_http_ndx;		// number of bytes received from telnet and send to http set 0 on receive http packet;
	int		n_http_size;		// number of tcp bytes received from http,set 0 on accept(),close() socet;
//	int		n_cmp_size;
//	int		n_temp_length_1;
//	int		n_temp_length_2;

	FILE		*fd_telnet_pipe;		// file descriptor telnet stdin pipe, use to flush(); 

	char		sz_local_host[SZ_TEMP_TEST];		// duplicate of ARGV[N_ARG_LOCAL_IP];
	char		sz_cisco_ip[SZ_TEMP_TEST];			// duplicate of ARGV[N_ARG_CISCO_IP];
	char		sz_remote_host[SZ_TEMP_TEST];	// duplicate of ARGV[N_ARG_HOST_IP];
	char		sz_remote_device[SZ_TEMP_TEST];	// duplicate of ARGV[N_ARG_DEVICE_IP];
	char		sz_temp_connect[SZ_TEMP_TEST];	// use as FIFO to compare end-of-http answer from remote device - case
										// of chunk, cisco telnet  "connection to x.x.x.x closed by foreign host"

	int		n_browser_port = TEST_HTTP_PORT;		// tcp proxy port, read from ARGV[5];
	int		n_char_time_out;	// number of select() time-out to look for end of remote telnetsession; 
	int		n_wait_select;		// global number of time-out from select();
	
#ifdef	_DBG_LOG				// debug log file;
	FILE		*fd_test_log;
	int		n_log_file_key=0;
#endif

//--------------------------------------------------------------------------------
// Main as int.
//--------------------------------------------------------------------------------
int	main(int argc, char **argv)
{
	int		n_rc;				// temp retun code;;
							// init global variables, duplicate static def;
	n_exit = -1;
	n_cancel_signal = 0;
#ifdef	_DBG_LOG
	fd_test_log = (FILE *)NULL;
#endif
	n_listen_socket = N_SOCKET_NOT_ALLOW;
	n_http_socket = N_SOCKET_NOT_ALLOW;
	p_http_bf_in = NULL;
	n_listen_socket = -1;
	n_pipe_0[N_INPUT] = -1;
	n_pipe_0[N_OUTPUT] = -1;
	n_pipe_1[N_INPUT] = -1;
	n_pipe_1[N_OUTPUT] = -1;
	fd_telnet_pipe = (FILE *)NULL;
	n__telnet_pid = -1;
	n_wait_http = 0;
	n_http_ndx = 0;
	n_http_size = 0;
	memset(sz_temp_connect, (char)0, SZ_TEMP_TEST);
	n_browser_port = TEST_HTTP_PORT;
	n_char_time_out = TEST_TELNET_TIMEOUT;
	n_wait_select = 0;

	if(get_arg(argc, argv))		// command line arguments, 
		exit(-1);				// 4 are nessosary;

	set_signal_handler();			// change default signal handle, for SIGABRT, SIGTERM, SIGPIPE;

#ifdef	_DBG_LOG
	if(n_log_file_key)
	{
		fd_test_log = (FILE *)NULL;
		fd_test_log = fopen("test.log", "wb");
		if(fd_test_log == (FILE *)NULL)
		{
			perror("Temp file create error.");
			exit(-2);
		}
	}
#endif
	// create 2 half duplex pipe ;
	//
	// n_pipe_0 - from main to telnet ;
	// n_pipe_1 - from telnet to main ;
	//
	// p0[1] ---> p0[0] 0 stdin;
	// p1[0] <--- p1[1] 1 stdout;
	//
	n_rc = pipe(n_pipe_0);	// http[1] -> telnet[0] ;
	if(n_rc <0)
	{
		perror("\n Error to pipe() http->telnet.");
		n_exit = -3;
		goto	to_return;
	}

	n_rc = pipe(n_pipe_1);	// http[0] <- telnet[1];
	if(n_rc <0)
	{
		perror("\n Error to pipe() http<-telnet.");
		n_exit = -4;
		goto	to_return;
	}

	if(allocate_http_buffers())
		goto	to_return;

	n__telnet_pid = fork();
	if(n__telnet_pid <0)
	{
		perror("\n Error to fork() to telnet.");
		n_exit = -5;
		goto	to_return;
	}

	if(n__telnet_pid == (pid_t)0)			// telnet child process ;
	{
//		call_telnet_client(argv[N_ARG_CISCO_IP]);
		call_telnet_client(sz_cisco_ip);
	}

	// restrict local terminal echo, echo only from telnet - "stty -echo";
	echo_off();

	telnet_2_http();

	// wait telnet process ;
	waitpid(n__telnet_pid, NULL, 0);

	n_exit = 0;

to_return:							// clear globar resource;
	echo_on();						// echo mode ON;
#ifdef	_DBG_LOG
	if(n_log_file_key)				// close LOG file;
	{
		if(fd_test_log != (FILE *)NULL)
		{
			fclose(fd_test_log);
			fd_test_log = (FILE *)NULL;
		}
	}
#endif
	if(p_http_bf_in != NULL)			// malloc() buffers;
	{
		free(p_http_bf_in);
		p_http_bf_in = NULL;

	}
	if(n_listen_socket)				// listen() http socket;
	{
		close(n_listen_socket);
		n_listen_socket = -1;
	}
	if(n_pipe_0[N_OUTPUT] >= 0)		// parent stdout pipe;
	{
		close(n_pipe_0[N_OUTPUT]);
		n_pipe_0[N_OUTPUT] = -1;
	}
	if(n_pipe_1[N_INPUT] >= 0)		// parent stdin pipe;
	{
		close(n_pipe_1[N_INPUT]);
		n_pipe_0[N_OUTPUT] = -1;
	}
	if(fd_telnet_pipe != NULL)			// fd duplicate of telnet pipe;
	{
		fclose(fd_telnet_pipe);
		fd_telnet_pipe = NULL;
	}
	return	0;
}


//--------------------------------------------------------------------------------
// Set echo mode OFF/ON like stty proc;
//--------------------------------------------------------------------------------
static	struct	termios stored;
static	int		n_term_change = 0;

void echo_off(void)
{
	struct termios new;
	tcgetattr(0,&stored);
	memcpy(&new, &stored, sizeof(struct termios));
	new.c_lflag &= (~ECHO);			// echo off ;
	new.c_lflag &= (~ICANON);		// set buffer to 1,
	new.c_cc[VTIME] = 0;				// no time-out ;
	new.c_cc[VMIN] = 1;
	tcsetattr(0,TCSANOW,&new);
	n_term_change = 1;
	return;
}

void echo_on(void)
{
	if(n_term_change)
	tcsetattr(0,TCSANOW,&stored);		// restore terminal seeting ;
	n_term_change = 0;
	return;
}

//--------------------------------------------------------------------------------
// Allocate one big buffer and set addresses of all buffers.
// For root address use global p_http_bf_in. 
//--------------------------------------------------------------------------------
int	allocate_http_buffers()
{
	p_http_bf_in = NULL;
	p_http_bf_in = (char *)malloc(4*N_HTTP_BF_SIZE);
	if(p_http_bf_in == NULL)
	{
		printf("\n Allocate http buffer error.");
		return	-1;
	}
//	memset(p_http_bf_in, (char)0, 3*N_HTTP_BF_SIZE);	// if temp_bf on;
	memset(p_http_bf_in, (char)0, 2*N_HTTP_BF_SIZE);
	p_http_bf_out = p_http_bf_in + 2*N_HTTP_BF_SIZE;
//	p_http_bf_temp = p_http_bf_in + 3*N_HTTP_BF_SIZE;

	return	0;
}

//--------------------------------------------------------------------------------
// Set pipe_0 for stdin, pipe_1 for stdout
// and create telnet client in child process.
//--------------------------------------------------------------------------------
void	call_telnet_client(char *sz_cisco_ip)
{								// stdin pipe;
		close(n_pipe_0[N_OUTPUT]);
		dup2(n_pipe_0[N_INPUT], 0);
								// stdout pipe;
		close(n_pipe_1[N_INPUT]);
		dup2(n_pipe_1[N_OUTPUT], 1);

		// telnet to cisco ;
		// - "/usr/kerberos/bin/telnet" - ARGV[0] - may be program path, not empty;
		// - "-8" - telnet useTELNET BINARY mode;
		// - sz_cisco_ip - global string, remote ciso ip address;
		// - 0 - = (char)NULL;
		execlp("telnet", "/usr/kerberos/bin/telnet", "-8", sz_cisco_ip, 0);

		return;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	telnet_2_http()
{
	int		n_rc;				// temp retun code;;

	// close main unused half pipe ;
	close(n_pipe_0[N_INPUT]);
	close(n_pipe_1[N_OUTPUT]);
	// make file stream for main_to_telnet pipe to flush http buffer;
	fd_telnet_pipe = fdopen(n_pipe_0[N_OUTPUT], "w");

	n_select = 0;
	n_time_out = N_MAX_TIMEOUT;
	n_wait_http = 0;

	if(create_listen_http())
		goto	to_return;

	while(n_cancel_signal == 0)
	{
		set_select_field();
		n_rc=select(n_select, &n_read_fds, (fd_set *)NULL,
				(fd_set *)NULL, &tm_val);
		if(n_rc<0)
			perror("Select() error. \n");
		if(n_rc==0)					// select() time-out;
			find_telnet_wait();			// look for end of remote telnet session;

		if(FD_ISSET(0, &n_read_fds))
		{
			if(process_stdin())
				goto	to_return;
		}

		// input from telnet;
		if(FD_ISSET(n_pipe_1[N_INPUT], &n_read_fds))
		{
			if(read_telnet_pipe())
				goto	to_return;
		}

		// http socket ready ;
		// number accept allow is 1, so
		// event from accept or http socket;
		//
		// http socket ready ;
		if(n_http_socket != N_SOCKET_NOT_ALLOW)
		{
			if(FD_ISSET(n_http_socket, &n_read_fds))
			{
				process_http();
			}
		}
		else
		// accep socket ready ;
		{
			if(FD_ISSET(n_listen_socket, &n_read_fds))
				accept_http();
		}
	}	// end of http sockets if ;

to_return:
	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	read_telnet_pipe()
{
	int		n_rc;				// temp retun code;;
	int		n_temp_8;			// temp convert not ASCII from char8;
	char		sz_temp_16[16];	// to show as %02X;

	// read from telnet pipe;
	n_rc = read(n_pipe_1[N_INPUT], &c_temp, 1);
	if(n_rc == 0)
		return	0;

	if(n_rc < 0)
	{
		perror("read pipe telnet->http");
		return	1;
	}

	// if debug, write to debug log file;
#ifdef	_DBG_LOG
	if(n_log_file_key)
	{
		n_rc = fwrite(&c_temp, sizeof(char), 1, fd_test_log);
		if(n_rc < 1)
		{
			perror("write test file");
		}
	}
#endif
	// write to terminal as ASCII ;
	if(test_print(c_temp))
	{
		n_rc = write(1, &c_temp, 1);
	}
	else
	{
		n_temp_8 = (int)c_temp & 0xff;
		sprintf(sz_temp_16, "%%%02X", n_temp_8);
		n_rc = write(1, sz_temp_16, 3);
	}

	if(n_rc < 1)
	{
		perror("write pipe_1");
		return	2;
	}
	// if HTTP process on, move to http_buffer ;
	if(n_wait_http)
	{
		process_http_pipe();
	}

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	process_http()
{
	if(recv_http())
		return	0;

	if(n_wait_http == 0)
	{
		send_telnet_connect_http(sz_remote_host, sz_remote_device);
	}
#ifdef	_DBG_LOG
	if(n_log_file_key)
	{
		fprintf(fd_test_log, "\n\n--------- Receive from Browser : %d :\n", n_http_size);
		fwrite(p_http_bf_in, sizeof(char), n_http_size, fd_test_log);
	}
#endif
//	p_http_bf_in[n_http_size]=(char)0;
//	http_filtr_http_header(p_http_bf_in, p_http_bf_out,
//					p_http_bf_temp, &n_http_size);
//	memcpy(p_http_bf_in, p_http_bf_out, n_http_size);
#ifdef	_DBG_LOG
	if(n_log_file_key)
	{
		fprintf(fd_test_log, "\n\n--------- Send to TELNET : %d :\n", n_http_size);
		fwrite(p_http_bf_in, sizeof(char), n_http_size, fd_test_log);
	}
#endif
	write(n_pipe_0[N_OUTPUT], p_http_bf_in, n_http_size);
	fflush(fd_telnet_pipe);

	if(n_wait_http == 0)
	{
		memset(p_http_bf_out, (char)0, N_HTTP_BF_SIZE);
//		memset(sz_temp_chunked, 0, SZ_MAX_SIZE);
		memset(sz_temp_connect, 0, SZ_TEMP_TEST);
		n_wait_http = 1;
		n_http_ndx = 0;
//		n_load_http = 0;
		n_wait_select = 0;
	}

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	create_listen_http()
{
	int		n_optval;
	int		n_port;
	struct sockaddr_in	n_sockaddr;

	n_listen_socket = socket(PF_INET, SOCK_STREAM, 0);
	if(n_listen_socket < 0)
	{
		perror("\n Listen soclet create error.");
		return	-1;
	}

	n_optval = 1;
//	n_port = TEST_HTTP_PORT;
	n_port = n_browser_port;
	if (setsockopt(n_listen_socket, SOL_SOCKET, SO_REUSEADDR,
			(char *)&n_optval, sizeof (n_optval)) < 0)
	{
		printf("\n Set sock opt listen soclet error.");
		return	-2;
	}

	memset((char *)&n_sockaddr, 0, sizeof(n_sockaddr));
	n_sockaddr.sin_family = AF_INET;
	n_sockaddr.sin_port = htons((unsigned short)n_port);
	n_sockaddr.sin_addr.s_addr = ipstr2long(sz_local_host);
//	n_sockaddr.sin_addr.s_addr = INADDR_ANY;

	if(bind(n_listen_socket, (struct sockaddr *)&n_sockaddr,
		 sizeof(n_sockaddr)))
	{
		perror("\n Bind listen soclet error.");
		return	-3;
	}

	if( (listen(n_listen_socket, N_MAX_LISTEN)) <0)
	{
		perror("\n Listen soclet error.");
		return	-4;
	}

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
void	set_select_field()
{
	int	n_temp_socket;

	if(n_http_socket != N_SOCKET_NOT_ALLOW)
		n_temp_socket = n_http_socket;
	else
		n_temp_socket = n_listen_socket;

	FD_ZERO(&n_read_fds);
	FD_SET(0, &n_read_fds);
	FD_SET(n_pipe_1[N_INPUT], &n_read_fds);
	FD_SET(n_temp_socket, &n_read_fds);

//	n_select = 32;
	n_select = 0;

	if(n_pipe_1[N_INPUT] > n_temp_socket)
		n_select = n_pipe_1[N_INPUT];
	else
		n_select = n_temp_socket;
	n_select++;

	tm_val.tv_sec = n_time_out/1000;
	tm_val.tv_usec = n_time_out%1000;

	return;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	process_stdin()
{
	int	n_rc;

	read(0, &c_temp, 1);
	n_rc = write(n_pipe_0[N_OUTPUT], &c_temp, 1);
	if(n_rc < 1)
	{
		perror("write pipe_0");
		return	-1;
	}

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	accept_http()
{
	struct sockaddr_in	n_sockaddr;
	int		n_length;

printf("\n accept_http().\n!!!\n");
	memset(&n_sockaddr, 0, sizeof(n_sockaddr));
	n_length = sizeof(n_sockaddr);
	n_http_socket = accept(n_listen_socket,
				 (struct sockaddr *)&n_sockaddr,
				 &n_length);
	if(n_http_socket <0)
	{
		perror("\n Accept error.");
		n_http_socket = N_SOCKET_NOT_ALLOW;
		return	-1;
	}

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	recv_http()
{
	int	n_rc;

	memset(p_http_bf_in, (char)0, N_HTTP_BF_SIZE);

	n_rc = recv(n_http_socket, p_http_bf_in, N_HTTP_BF_SIZE, 0);
	if(n_rc<=0)
	{
		n_http_size = 0;
		close_http_socket();
		return	-1;
	}

//	printf("\n\n Recv %d bytes.\n!!!\n", n_rc);
//	if(n_rc)
//		printf("\n\n%s\n\n", p_http_bf_in);
#ifdef	_DBG_LOG
	if(n_rc)
	{
		if(n_log_file_key)
		{
			fprintf(fd_test_log, "\n\n--------- Receive from HTTP : %d :", n_rc);
			fwrite(p_http_bf_in, sizeof(char), n_rc, fd_test_log);
		}
	}
#endif
	n_http_size = n_rc;

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
void	send_telnet_connect_http(char *sz_host_ip, char *sz_device_ip)
{
	char	sz_temp[SZ_MAX_SIZE];
	int	n_rc;

	memset(sz_temp, (char)0, SZ_MAX_SIZE);
	strcat(sz_temp, "connect ");
	strcat(sz_temp, sz_device_ip);
	if( (isdigit(*sz_host_ip)) || ((*sz_host_ip) == '*') ) 
	{
		strcat(sz_temp, " 80 /stream /noecho\n");
	}
	else
	{
		strcat(sz_temp, " 80 /stream /noecho /source-interface ");
//		strcat(sz_temp, " 8080 /stream /noecho /source-interface ");
		strcat(sz_temp, sz_host_ip);
		strcat(sz_temp, "\n");
	}

	n_rc = write(n_pipe_0[N_OUTPUT], sz_temp, strlen(sz_temp));
	memset(sz_temp, (char)0, SZ_MAX_SIZE);

	return;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
void	close_http_socket()
{
	if(n_http_socket != N_SOCKET_NOT_ALLOW)
	{
printf("\n Close HTTP socket.\n!!!\n");
		close(n_http_socket);
		n_http_socket = N_SOCKET_NOT_ALLOW;
		n_wait_http = 0;
	}

	return;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	process_http_pipe()
{
	int	n_rc;

//	c_temp &= 0x7f;

	if(n_http_ndx <N_HTTP_BF_SIZE_1)
	{
		p_http_bf_out[n_http_ndx] = c_temp;
		n_http_ndx++;
	}

	memmove(sz_temp_connect, sz_temp_connect+1, SZ_TEMP_TEST_1);
	sz_temp_connect[SZ_MAX_SIZE_1]=c_temp;

	n_rc = strncmp(sz_temp_connect+SZ_TEMP_TEST-N_CHUNKED_FIN_SIZE,
					SZ_CHUNKED_FIN, N_CHUNKED_FIN_SIZE);
	if(n_rc == 0)
	{
		p_http_bf_out[n_http_ndx] = (char)0;
		if(n_http_socket != N_SOCKET_NOT_ALLOW)
		{
			if(n_http_ndx)
			{
#ifdef	_DBG_LOG
				if(n_log_file_key)
				{
					fprintf(fd_test_log, "\n\n--------- Send to HTTP : %d :\n", n_http_ndx);
					fwrite(p_http_bf_out, sizeof(char), n_http_ndx, fd_test_log);
				}
#endif
			}
			send(n_http_socket, p_http_bf_out, n_http_ndx, 0);
			close_http_socket();
		}
		n_wait_http = 0;

		return	0;
	}

	n_rc = strncmp(sz_temp_connect+SZ_TEMP_TEST-N_CONNECT_FIN_SIZE,
					 SZ_CONNECT_FIN, N_CONNECT_FIN_SIZE);
	if(n_rc == 0)
	{
//		n_load_http = 0;
		n_http_ndx -= N_CONNECT_FIN_SIZE;	// remove "[Connection to ";
		p_http_bf_out[n_http_ndx] = (char)0;
		if(n_http_socket != N_SOCKET_NOT_ALLOW)
		{
			if(n_http_ndx)
			{
#ifdef	_DBG_LOG
				if(n_log_file_key)
				{
					fprintf(fd_test_log, "\n\n--------- Send to HTTP : %d :\n", n_http_ndx);
					fwrite(p_http_bf_out, sizeof(char), n_http_ndx, fd_test_log);
				}
#endif
			}

			send(n_http_socket, p_http_bf_out, n_http_ndx, 0);
			close_http_socket();
		}
		n_wait_http = 0;

		return	0;
	}

	return	0;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
void	find_telnet_wait()
{
	if(n_wait_http)
	{
//		if(n_wait_select < 1)
		if(n_wait_select < n_char_time_out)
		{
			n_wait_select++;
		}
		else
		{
printf("\nWait time-out : %d:\n!!!", n_wait_select);
			if(n_http_socket != N_SOCKET_NOT_ALLOW)
			{
				send(n_http_socket, p_http_bf_out, n_http_ndx, 0);
				close_http_socket();
			}
			n_wait_http = 0;
		}
	}

	return;
}

//--------------------------------------------------------------------------------
//
//--------------------------------------------------------------------------------
int	get_arg(int argc, char **argv)
{
	int	n_length;

	if(argc <N_MIN_ARGC)
	{
		//			   argv[1]	argv[2]		argv[3]	argv[4]
#ifdef	_DBG_LOG
		printf("\n Use ... <local ip> <cisco ip> <host ip> <device ip> {8080} {time-out} {log on/off}");
#else
		printf("\n Use ... <local ip> <cisco ip> <host ip> <device ip> {8080} {time-out}");
#endif
		return	1;
	}

	n_length = strlen(argv[N_ARG_LOCAL_IP]);
	if(n_length >= SZ_TEMP_TEST)
		n_length = SZ_TEMP_TEST_1;
	memset(sz_local_host, (char)0, SZ_TEMP_TEST);
	strncpy(sz_local_host, argv[N_ARG_HOST_IP], n_length);

	n_length = strlen(argv[N_ARG_CISCO_IP]);
	if(n_length >= SZ_TEMP_TEST)
		n_length = SZ_TEMP_TEST_1;
	memset(sz_cisco_ip, (char)0, SZ_TEMP_TEST);
	strncpy(sz_cisco_ip, argv[N_ARG_CISCO_IP], n_length);

	n_length = strlen(argv[N_ARG_HOST_IP]);
	if(n_length >= SZ_TEMP_TEST)
		n_length = SZ_TEMP_TEST_1;
	memset(sz_remote_host, (char)0, SZ_TEMP_TEST);
	strncpy(sz_remote_host, argv[N_ARG_HOST_IP], n_length);

	n_length = strlen(argv[N_ARG_DEVICE_IP]);
	if(n_length >= SZ_TEMP_TEST)
		n_length = SZ_TEMP_TEST_1;
	memset(sz_remote_device, (char)0, SZ_TEMP_TEST);
	strncpy(sz_remote_device, argv[N_ARG_DEVICE_IP], n_length);

	n_browser_port = TEST_HTTP_PORT;
	if(argc > 5)
	{	if( (sscanf(argv[N_ARG_DEVICE_PORT], "%d", &n_browser_port)) != 1)
		{
			printf("\n Error to get browser port : %s,\n use 8080", argv[N_ARG_DEVICE_PORT]);
			return	2;
		}
	}

	n_char_time_out = TEST_TELNET_TIMEOUT;
	if(argc > 6)
	{
		if( (sscanf(argv[N_ARG_TIMEOUT], "%d", &n_char_time_out)) != 1)
		{
			printf("\n Error to get telnet timeout : %s,\n use 1", argv[N_ARG_TIMEOUT]);
			return	3;
		}
	}
#ifdef	_DBG_LOG
	n_log_file_key = 0;
	if(argc > 7)
	{
		if( (sscanf(argv[N_ARG_LOG_FILE_KEY], "%d", &n_log_file_key)) != 1)
		{
			printf("\n Error to get log file key : %s,\n use 1 to create log file.", argv[N_ARG_LOG_FILE_KEY]);
			return	4;
		}
	}
#endif

	return	0;
}

//--------------------------------------------------------------------------------
//  Local isprint() version.
//--------------------------------------------------------------------------------
static char sz_print[]={" ~`!@#$%^&*()_-+=[{]};:'\x22,<.>/?\\|\r\n\t"};

int	test_print(char c)
{
	int	n_c;
	int	i;

	n_c = ((int)c) & 0xff;

	if(isalnum(n_c))
		return	1;
	for(i=0;i<sizeof(sz_print);i++)
		if(c == sz_print[i])
			return	1;

	return	0;
}

//--------------------------------------------------------------------------------
//  Set main program signal handler.
//--------------------------------------------------------------------------------
void	set_signal_handler()
{
	signal(SIGINT,	(void(*)(int)) signal_close_app); // interrupt
	signal(SIGABRT,	(void(*)(int)) signal_close_app); // abnormal termination triggered by abort call
	signal(SIGTERM,	(void(*)(int)) signal_close_app); // Software termination signal from kill
	signal(SIGFPE,	(void(*)(int)) signal_close_app); // floating point exception
	signal(SIGILL,	(void(*)(int)) signal_close_app); // illegal instruction - invalid function image
	signal(SIGSEGV,	(void(*)(int)) signal_close_app); // segment violation
#ifdef _MS_WINDOWS
	signal(SIGBREAK,(void(*)(int)) signal_close_app); // Ctrl-Break sequence
#endif
	return;
}
/* ---------------------------------------------------------------
 *	Set up signal hook.
 *	Exit on any signal.
 */
void	signal_close_app(int signal)
{
	switch(signal)
	{
		case	SIGINT:
				n_cancel_signal = 1;
				printf("\n Signal case : SIGINT");
			break;
		case	SIGABRT:
				n_cancel_signal = 2;
				printf("\n Signal case : SIGABRT");
			break;
		case	SIGTERM:
				n_cancel_signal = 3;
				printf("\n Signal case : SIGTERM");
			break;
		case	SIGFPE:
				n_cancel_signal = 4;
				printf("\n Signal case : SIGFPE");
			break;
		case	SIGILL:
				n_cancel_signal = 5;
				printf("\n Signal case : SIGILL");
			break;
		case	SIGSEGV:
				n_cancel_signal = 6;
				printf("\n Signal case : SIGSEGV");
			break;
#ifdef _MS_WINDOWS
		case	SIGBREAK:
				n_cancel_signal = 7;
				printf("\n Signal case : SIGBREAK");
			break;
#endif
		default:
				n_cancel_signal = 8;
				printf("\n Signal case : default");
			return;
	}

	return;
}

/* ---------------------------------------------------------------
 *	From RADIUS.util.c
 *	Return an IP address in standard dot notation for the
 *	provided address in host long notation.
 */
void ipaddr2str(char *buffer, unsigned int ipaddr)
{
	int	addr_byte[4];
	int	i;
	unsigned int	xbyte;

	for(i = 0;i < 4;i++) {
		xbyte = ipaddr >> (i*8);
		xbyte = xbyte & (unsigned int)0x000000FF;
		addr_byte[i] = xbyte;
	}
	sprintf(buffer, "%u.%u.%u.%u", addr_byte[3], addr_byte[2],
		addr_byte[1], addr_byte[0]);
}


/* ---------------------------------------------------------------
 *	From RADIUS.util.c
 *	Return an IP address in host long notation from
 *	one supplied in standard dot notation.
 */
unsigned int ipstr2long(char *ip_str)
{
	char	buf[6];
	char	*ptr;
	int	i;
	int	count;
	unsigned int	ipaddr;
	int	cur_byte;

	ipaddr = (unsigned int)0;
	for(i = 0;i < 4;i++) {
		ptr = buf;
		count = 0;
		*ptr = '\0';
		while(*ip_str != '.' && *ip_str != '\0' && count < 4) {
			if(!isdigit(*ip_str)) {
				return((unsigned int)0);
			}
			*ptr++ = *ip_str++;
			count++;
		}
		if(count >= 4 || count == 0) {
			return((unsigned int)0);
		}
		*ptr = '\0';
		cur_byte = atoi(buf);
		if(cur_byte < 0 || cur_byte > 255) {
			return((unsigned int)0);
		}
		ip_str++;
		ipaddr = ipaddr << 8 | (unsigned int)cur_byte;
	}
	return(ipaddr);
}

/* ---------------------------------------------------------------
 *	From RADIUS.util.c
 *	Like strncpy, but makes sure that the string
 *	always ends with a trailing \0
 */
char *strNcpy(char *dest, char *src, int n)
{
	if (n > 0)
		strncpy(dest, src, n);
	else
		n = 1;
	dest[n - 1] = 0;

	return dest;
}

//--------------------------------------------------------------------------------
//	Eof.
//--------------------------------------------------------------------------------
