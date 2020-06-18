#define _GNU_SOURCE /* RTLD_NEXT */
#include <dlfcn.h> /* dlsym */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>
#include <radamsa.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define sif_debug(fmt, ...) \
	do { if (VERBOSE) fprintf(stderr, "%s" fmt "\n", "[SIF][Info] ", __VA_ARGS__); } while (0)

#define sif_error(fmt, ...) \
	do { fprintf(stderr, "%s" fmt "\n", "[SIF][Error] ", __VA_ARGS__); } while (0)


static int (*sif_bind)(int socket, const struct sockaddr *address, socklen_t address_len) = NULL;
static int (*sif_socket)(int domain, int type, int protocol) = NULL;
static int (*sif_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static ssize_t (*sif_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static ssize_t (*sif_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*sif_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;
static ssize_t (*sif_sendmsg)(int sockfd, const struct msghdr *msg, int flags) = NULL;
static ssize_t (*sif_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

static int INIT = 0;
static time_t START_TIME;


/* CONTROL FUZZING */

/**
 * print info
 */
static int VERBOSE = 0;

/**
 * fuzzing is enabled
 */
static int FUZZ = 1;

/**
 * recv packet dumping is enabled
 */
static int DUMP = 0;

/**
 * output file for dumped packets data
 */
static FILE* DUMP_FILE = NULL;

/**
 * buffer size for fuzzed packet
 */
static unsigned int BUFSIZE = 1024;

/**
 * skip X packets before fuzzing starts
 */
static int SKIP = 0;

/**
 * chance 1-100 for fuzzing a packet
 */
#define CHANCE_MAX 100
#define CHANCE_MIN 1
static int CHANCE = CHANCE_MAX;

/**
 * wait X seconds before fuzzing starts
 */
static int WAIT = 0;

/**
 * file that serves as switch (if exists - fuzzing ON, else fuzzing OFF)
 */
static char* SWITCH_FILE = NULL;

/**
 * repeat (fuzz and send) a packet X times
 */
static unsigned int REPEAT = 0;

/**
 * fuzz only specific TARGET_IP (default 127.0.0.1), TARGET_PORT (optional)
 */
static uint32_t* TARGET_IP = NULL;
static unsigned short* TARGET_PORT = NULL;

/**
 * radamsa initial seed. otherwise random
 */
static unsigned int seed;


static void parse_options(char* options) {
	seed = rand();
	TARGET_IP = malloc(sizeof(*TARGET_IP));
	inet_pton(AF_INET, "127.0.0.1", TARGET_IP);

	if (options == NULL)
		return;

	char* token = strtok(options, ":");
	char* value = NULL;

	while (token != NULL) {
		value = strchr(token, '=');
		if (value != NULL) {
			*value++ = '\0';
			if (strcmp(token, "verbose"))
			{
				int decision = strtol(value, NULL, 0);
				VERBOSE = decision ? 1 : 0;
			}
			else if (strcmp(token, "fuzz")) 
			{
				int decision = strtol(value, NULL, 0);
				FUZZ = decision ? 1 : 0;
			}
			else if (strcmp(token, "dump"))
			{
				int decision = strtol(value, NULL, 0);
				DUMP = decision ? 1 : 0;
			}
			else if (strcmp(token, "dump_output"))
			{
				char* path = malloc(strlen(value) + 1 + (2*19) + 1);// long = 19 digits
				pid_t pid = getpid();
				sprintf(path, "%s.%d.%ld", value, pid, START_TIME);
				DUMP_FILE = fopen(path, "w");
				if (DUMP_FILE == NULL) {
					sif_error("Cannot create dump output file = %s", path);
					exit(-1);
				}
				free(path);
			}
			else if (strcmp(token, "seed"))
			{
				seed = strtoul(value, NULL, 0);
			} 
			else if (strcmp(token, "skip"))
			{
				SKIP = strtol(value, NULL, 0);
			} 
			else if (strcmp(token, "repeat"))
			{
				REPEAT = strtoul(value, NULL, 0);
			}
			else if (strcmp(token, "wait"))
			{
				WAIT = strtol(value, NULL, 0);
			}
			else if (strcmp(token, "switch_file"))
			{
				SWITCH_FILE = strdup(value);
			}
			else if (strcmp(token, "target_ip"))
			{
				TARGET_IP = malloc(sizeof(*TARGET_IP));
				if (!inet_pton(AF_INET, value, TARGET_IP)) {
					sif_error("%s", "Invalid TARGET_IP");
					exit(-1);
				}
			}
			else if (strcmp(token, "target_port"))
			{
				TARGET_PORT = malloc(sizeof(*TARGET_PORT));
				unsigned short port = strtoul(value, NULL, 0);
				*TARGET_PORT = htons(port);
			}
			else if (strcmp(token, "chance"))
			{
				int chance = strtoul(value, NULL, 0);
				if (chance >= CHANCE_MIN && chance <= CHANCE_MAX) {
					CHANCE = chance;
				} 
			}
		}
		token = strtok(NULL, ":");
	}
}

/**
 * initialize fuzzing environment:
 * 	- initialize radamsa
 * 	- parse settings
 */
static void try_init(void) {
	if (INIT == 1)
		return;
	INIT = 1;
	srand(time(NULL));
	time(&START_TIME);
	char *options = getenv("SIF_OPTIONS");
	parse_options(options);
	radamsa_init();
}


/** HOOKS **/

int socket(int domain, int type, int protocol) {
	try_init();

	if (sif_socket == NULL) {
		sif_socket = dlsym(RTLD_NEXT, "socket");
	}

	int s = sif_socket(domain, type, protocol);
	sif_debug("new socket (%d)", s);

	return s;
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len) {
	try_init();

	if (sif_bind == NULL) {
		sif_bind = dlsym(RTLD_NEXT, "bind");
	}

	int r = sif_bind(socket, address, address_len);
	sif_debug("binding socket (%d) to port (%u)", socket, htons(((struct sockaddr_in*)address)->sin_port));
	
	return r;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	try_init();

	if (sif_connect == NULL) {
		sif_connect = dlsym(RTLD_NEXT, "connect");
	}

	int c = sif_connect(sockfd, addr, addrlen);
	struct sockaddr_in* addrin = (struct sockaddr_in*)addr;
	char *s = malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(addrin->sin_addr), s, INET_ADDRSTRLEN);
	sif_debug("connecting (%d) to %s:%u", sockfd, s, htons(addrin->sin_port));
	free(s);
	
	return c;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	try_init();

	if (sif_sendto == NULL) {
		sif_sendto = dlsym(RTLD_NEXT, "sendto");
	}

	int fuzz_decision = 0;
	struct stat fbuf;

	if (FUZZ && dest_addr) {
		if (dest_addr->sa_family == AF_INET) { // IPv4
			struct sockaddr_in* addrin = (struct sockaddr_in*) dest_addr;
			if (addrin->sin_addr.s_addr == *TARGET_IP) {
				fuzz_decision = TARGET_PORT ? *TARGET_PORT == addrin->sin_port : 1;
			}
		} else if (dest_addr->sa_family == AF_INET6) { //IPv6

		}
	}

	if (fuzz_decision && SKIP) {
		SKIP--;
		sif_debug("skipping sendto (%d) (skip = %d)", sockfd, SKIP);
		fuzz_decision = 0;
	}

	if (fuzz_decision && SWITCH_FILE && stat(SWITCH_FILE, &fbuf)) {
		sif_debug("skipping sendto (%d) (fileswitch)", sockfd);
		fuzz_decision = 0;
	}

	if (fuzz_decision && WAIT) {
		int diff = (int) difftime(time(NULL), START_TIME);
		if (diff > WAIT) {
			WAIT = 0;
		} else {
			sif_debug("skipping sendto (%d) (wait = %ds)", sockfd, WAIT - diff);
			fuzz_decision = 0;
		}
	}

	if (fuzz_decision && CHANCE != CHANCE_MAX) {
		int r = random() % 100 + 1;
		if (r > CHANCE) {
			printf("skipping sendto %d (rand = %d)", sockfd, r);
			fuzz_decision = 0;
		}
	}

	if (fuzz_decision) {
		char *out = malloc(BUFSIZE); 
		int i = 0;
		for (int max = REPEAT + 1; i < max; i++) {
			int n = radamsa((uint8_t*) buf, len, (uint8_t*) out, BUFSIZE, seed++);
			ssize_t r = sif_sendto(sockfd, out, n, flags, dest_addr, addrlen);
		}
		if (VERBOSE && dest_addr->sa_family == AF_INET) {
			sif_debug("sendto (socket=%d, fuzzed=%d, ip=%s:%d)", sockfd, i-1, inet_ntoa(((struct sockaddr_in*)dest_addr)->sin_addr), htons(((struct sockaddr_in*)dest_addr)->sin_port));
		}
		free(out);
	} else {
		return sif_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	}
	
	return len;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	try_init();

	if (sif_recvfrom == NULL) {
		sif_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	}

	ssize_t r = sif_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	
	if (DUMP && r > 0) {
		int offset = 0;
		int hex_char_size = 2;
		int hexbufsize = r * hex_char_size + 1 + 1;
		unsigned char *recvbuf = (signed char*) buf;
		char *hexbuf = malloc(hexbufsize);
		hexbuf[hexbufsize-1] = '\0';

		if (src_addr->sa_family == AF_INET) { // IPv4
			struct sockaddr_in* addrin = (struct sockaddr_in*) src_addr;
			char *s = malloc(INET_ADDRSTRLEN + 1 + 5 + 1); //max port number = 5 digits (65535)
			inet_ntop(AF_INET, &(addrin->sin_addr), s, INET_ADDRSTRLEN);
			sprintf(s + strlen(s), ":%u ", htons(addrin->sin_port));
			fwrite(s, 1, strlen(s), DUMP_FILE);
			free(s);
		} else if (src_addr->sa_family == AF_INET6) { //IPv6

		}

		for (int i = 0; i < r; i++) {
			int written = sprintf(hexbuf + offset, "%02x", recvbuf[i]);
			if (written == hex_char_size)
				offset += written;
			else {
				sif_error("Unexpected number of written bytes (i=%d, written=%d)", i, written);
			}
		}
		sprintf(hexbuf + offset, "\n");
		fwrite(hexbuf, 1, strlen(hexbuf), DUMP_FILE);
		fflush(DUMP_FILE);
		free(hexbuf);
	}

	return r;
}

