#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "/home/daniel/tcp/http_web_server/server.h"

int main(int argc, char *argv[])
{
	uint8_t *hostname = argv[1], *port = argv[2];
	char * err = NULL;
	if (hostname == NULL || port == NULL)
	{
		fprintf(stderr, "Error: Please provide port and hostname\n");
		exit(1);
	}

	/**
	 * SSL_library_init() registers the available SSL/TLS ciphers and digests.
	 */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	/**
	 * @brief 
	 * SSL_CTX_new() initializes the list of ciphers, 
	 * the session cache setting, the callbacks, 
	 * the keys and certificates and the options to its default values.
	 * 
	 * Throws: 
	 * The creation of a new SSL_CTX object failed. Check the error stack to find out the reason.
	 *  Returns: 
	 * The Pointer to an SSL_CTX object.
	 * 	
	 */
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	if (!ctx)
	{
		fprintf(stderr, "SSL_CTX_new() failed.\n");
		goto error;
		return 1;
	}

	if (!SSL_CTX_use_certificate_file(ctx, "ca.crt", SSL_FILETYPE_PEM) || !SSL_CTX_use_PrivateKey_file(ctx, "ca.key", SSL_FILETYPE_PEM))
	{
		fprintf(stderr, "SSL_CTX_use_certif                                                                                                                                                                                    icate_file() failed.\n");
		goto error;
	}

	struct addrinfo *bind_address = get_address_info(hostname, port, SOCK_STREAM);

	socket_t socket_server = create_socket(bind_address);
	bind_socket_to_address(socket_server, bind_address);
	listen_on(socket_server);

	while (1)
	{

		printf("Waiting for connection...\n");
		struct sockaddr_storage client_address;
		socklen_t client_len = sizeof(client_address);
		socket_t socket_client = accept(socket_server,
										(struct sockaddr *)&client_address, &client_len);
		if (!socket_client)
		{
			fprintf(stderr, "accept() failed. ()\n");
			return 1;
		}
		printf("Client is connected... ");
		char address_buffer[100];
		getnameinfo((struct sockaddr *)&client_address,
					client_len, address_buffer, sizeof(address_buffer), 0, 0,
					NI_NUMERICHOST);
		printf("%s\n", address_buffer);

		SSL *ssl = SSL_new(ctx);
		if (!ctx)
		{
			fprintf(stderr, "SSL_new() failed.\n");
			// goto error;
			return 1;
		}
		
		SSL_set_fd(ssl, socket_client);

		printf("SSL connection using %s\n", SSL_get_cipher(ssl));

		if (SSL_accept(ssl) <= 0)
		{
			fprintf(stderr, "SSL_accept() failed.\n");
			// ERR_print_errors_fp(stderr);
			
			SSL_shutdown(ssl);
			close(socket_client);
			SSL_free(ssl);
			ERR_print_errors_fp(stderr);
			// goto error;

			continue;
		}

		printf("Reading request...\n");
		char request[1024];
		int bytes_received = SSL_read(ssl, request, 1024);
		printf("Received %d bytes.\n", bytes_received);
		 printf("Received (%d bytes): '%.*s'\n",
               bytes_received, bytes_received, request);

		printf("Sending response...\n");
		const char *response =
			"HTTP/1.1 200 OK\r\n"
			"Connection: close\r\n"
			"Content-Type: text/plain\r\n\r\n"
			"Local time is: ";
		int bytes_sent = SSL_write(ssl, response, strlen(response));
		printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(response));
		
        printf("Closing connection...\n");
        SSL_shutdown(ssl);
    	close(socket_client);
        SSL_free(ssl);
	}

	SSL_CTX_free(ctx);
	close(server_socket);

	error:
		ERR_print_errors_fp(stderr);
		// printf("|%s\n", err);
		// free(err);
		exit(1);
	return 0;
}