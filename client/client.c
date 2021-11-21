#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define PORT "8080"

typedef int SOCKET;

//Implementation to handle errors
#define handle_error(msg) \
	do                    \
	{                     \
		perror(msg);      \
		return 1;         \
	} while (0)
#define info(msg)             \
	do                        \
	{                         \
		fprintf(stdout, msg); \
	} while (0)

struct client_config_t
{
	char port[5];
	int address_family;
} client_config = {
	.port = {'8', '0', '8', '0', '\0'},
	.address_family = AF_INET};

static struct addrinfo *get_address_info(struct client_config_t config)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = config.address_family; /* We are expecting IPv4. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	struct addrinfo *bind_address = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	if (getaddrinfo(0, config.port, &hints, &bind_address))
		return NULL;
	return bind_address;
}

static bool create_unix_socket(SOCKET *socket_listen, struct addrinfo *bind_address)
{
	*socket_listen = socket(bind_address->ai_family, bind_address->ai_socktype, bind_address->ai_protocol);
	if (*socket_listen == -1)
	{
		close(*socket_listen);
		return false;
	}
	return true;
}

static bool connect_unix_socket(SOCKET *socket_listen, struct addrinfo *bind_address)
{
	if (connect(*socket_listen, bind_address->ai_addr, bind_address->ai_addrlen))
	{
		close(*socket_listen);
		return false;
	}
	return true;
}

static bool get_name_info(struct addrinfo *bind_address, char *hostname)
{
	SOCKET s = getnameinfo(bind_address->ai_addr, bind_address->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
	if (s != 0)
		return false;
	return true;
}

int main()
{
	SOCKET socket_listen;
	struct addrinfo *bind_address = (struct addrinfo *)get_address_info(client_config);
	if (bind_address == NULL)
		handle_error("Unable to bind get remote address.");
	if (!create_unix_socket(&socket_listen, bind_address))
	{
		handle_error("Unable to bind the socket\n");
	}
	char hostname[1024];
	get_name_info(bind_address, hostname);
	if (!connect_unix_socket(&socket_listen, bind_address))
	{
		handle_error("Unable to connect");
	}
	// freeaddrinfo(bind_address);
	info("Connected:\t\n");

	while (1)
	{
		fd_set reads;
		FD_ZERO(&reads);
		FD_SET(socket_listen, &reads);
		FD_SET(fileno(stdin), &reads);

		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;

		if (select(socket_listen + 1, &reads, 0, 0, &timeout) < 0)
		{
			fprintf(stderr, "Select failed");
			return 1;
		}

		if (FD_ISSET(socket_listen, &reads))
		{
			char response[1024];
			int bytes_received = recv(socket_listen, response, 1024, 0);
			if (bytes_received < 1)
			{
				printf("Connection closed by peer.\n");
				break;
			}
			printf("Received (%d bytes)\n: %.*s",
				   bytes_received, bytes_received, response);
		}
		if (FD_ISSET(0, &reads))
		{
			char request[4096];
			if (!fgets(request, 4096, stdin))
				break;
			printf("Sending: %s", request);
			int bytes_send = send(socket_listen, request, strlen(request), 0);
			
		}
	}

	return 0;
}