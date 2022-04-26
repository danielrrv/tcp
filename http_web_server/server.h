#ifndef H_SERVER_HTTP
#define H_SERVER_HTTP

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>

#include <time.h>


//https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1
static volatile int server_socket = 0;

#define BUFFER_SIZE 1024
#define handle_error(msg) \
	do                    \
	{                     \
		perror(msg);      \
		exit(1);          \
	} while (0)
// Implementation to print informative messages.
#define info(msg)             \
	do                        \
	{                         \
		fprintf(stdout, msg); \
	} while (0)
typedef int socket_t;

const static char *methods[] = {
	"GET",
	"POST",
	"PUT",
	"HEAD",
	"OPTIONS",
	"DELETE",
	"CONNECT",
	"TRACE",
};

typedef struct
{
	char *method;
	char headers[BUFFER_SIZE];
	char body[BUFFER_SIZE];
	char *path;
} request_t;

typedef struct
{
	socket_t _socket;
	char headers[BUFFER_SIZE];
	char body[BUFFER_SIZE];
	uint16_t status;
} response_t;

typedef struct
{
	socket_t socket;
	void (*callback)(request_t *req, response_t *res);
	fd_set *master;
} server_t;

static struct addrinfo *get_address_info(char *host, const char *port, int socket_type)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = socket_type;
	hints.ai_flags = AI_PASSIVE;
	struct addrinfo *bind_address = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	if (getaddrinfo(host, port, &hints, &bind_address))
	{
		fprintf(stderr, "Unable to obtain address information\n");
		exit(1);
	}
	return bind_address;
}

static socket_t create_socket(struct addrinfo *bind_address)
{
	socket_t socket_listen = socket(bind_address->ai_family, bind_address->ai_socktype, bind_address->ai_protocol);
	if (socket_listen == -1)
	{
		perror("Unable to create the socket()");
		exit(1);
	}
	return socket_listen;
}

static void bind_socket_to_address(socket_t socket_listen, struct addrinfo *bind_address)
{
	if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen))
	{
		handle_error("Error binding the socket_listen to address.\n");
		close(socket_listen);
	}
	server_socket = socket_listen;
	freeaddrinfo(bind_address);
}

static void listen_on(socket_t socket_listen)
{
	if (listen(socket_listen, 10) < 0)
	{
		handle_error("Unable to listen for new connections\n");
		close(socket_listen);
	}
}

void wait_for_client_on(server_t *server, const char *http_port, void(callback)(void))
{

	struct addrinfo *bind_address = get_address_info(0, http_port, SOCK_STREAM);
	socket_t socket_listen = create_socket(bind_address);
	bind_socket_to_address(socket_listen, bind_address);
	listen_on(socket_listen);
	server->socket = socket_listen;
	info("Connected Ready...\n");
	fd_set master;
	FD_ZERO(&master);
	FD_SET(server->socket, &master);
	int max_socket = server->socket;
	callback();
	while (1)
	{
		fd_set reads;
		reads = master;
		if (select(max_socket + 1, &reads, 0, 0, 0) < 1)
		{
			handle_error("Unable to monitor reads set of file descriptors");
			exit(1);
		}
		socket_t i;
		for (i = 0; i <= max_socket; i++)
		{
			if (FD_ISSET(i, &reads))
			{
				server->master = &master;
				if (i == server->socket)
				{
					info("New client \n");
					struct sockaddr_storage client_address;
					socklen_t client_len = sizeof(client_address);
					socket_t socket_client = accept(server->socket, (struct sockaddr *)&client_address, &client_len);
					if (socket_client == -1)
					{
						handle_error("Unable to accept connections");
					}
					FD_SET(socket_client, &master);
					if (socket_client > server->socket)
					{
						max_socket = socket_client;
					}
				}
				else
				{
					request_t request;
					response_t response;
					response._socket = i;
					info("Reading the request...\n");
					// char request[BUFFER_SIZE];
					/*recv will read the content on the socket_client. request contains all user agent request data.*/
					int bytes_received = recv(i, request.body, BUFFER_SIZE, 0);
					if (bytes_received < 1)
					{
						FD_CLR(i, &master);
						close(i);
						continue;
					}
					fprintf(stdout, "Bytes Received: %d\n", bytes_received);

					server->callback(&request, &response);

					sprintf(response.headers, "HTTP/1.1 %d OK\r\n", response.status);
					sprintf(response.headers + strlen(response.headers), "Connection: close\r\n");
					sprintf(response.headers + strlen(response.headers), "Content-Type: text/plain\r\n\r\n");

					info("Sending respose...\n");

					char stream[BUFFER_SIZE];
					memset(stream, '\0', BUFFER_SIZE);
					strncpy(stream, response.headers, strlen(response.headers));
					strncpy(stream + strlen(stream), response.body, strlen(response.body));
					// /*What it does: Write the response over the socket client file descriptor*/
					int bytes_sent = send(response._socket, stream, strlen(response.headers) + strlen(response.body), 0);
					fprintf(stdout, "Bytes sent: %d\n", bytes_sent);
					// // Implementation to pull out the date&time and convert it to string

					fprintf(stdout, "Bytes sent: %d\n", bytes_sent);
					FD_CLR(i, &master);
					close(i);
				}
			}
		}
	}
}

void serve(server_t *server, void(callback)(request_t *req, response_t *res))
{
	server->callback = callback;
}

// void status(response_t * response, uint16_t status){
// 	response->headers
// }

void send_to_client(response_t *res, char *message, uint16_t status)
{
	memcpy(res->body, message, strlen(message));
	res->status = status;
}

void close_server(int _)
{

	close(server_socket);
	printf("Closing server!!!...\n");
}
#endif // H_SERVER_HTTP