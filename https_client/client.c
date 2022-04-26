#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
// gcc server.c  -lcrypto  -lssl -o server.o

int main(int argc, char *argv[])
{

     uint8_t *hostname = argv[1], *port = argv[2], * self_signed = argv[3];


    if (hostname == NULL || port == NULL)
    {
        fprintf(stderr, "Error: Please provide port and hostname\n");
        exit(1);
    }

    printf("OpenSSL version: %s\n", OpenSSL_version(SSLEAY_VERSION));

    /**
     * SSL_library_init() registers the available SSL/TLS ciphers and digests.
     */
    SSL_library_init();

    /**
     * @brief
     * OpenSSL keeps an internal table of digest algorithms and ciphers.
     *  It uses this table to lookup ciphers via functions such as EVP_get_cipher_byname().
     */
    OpenSSL_add_all_algorithms();

    /**
     * 
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
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    
    /* Set for server verification*/
    if (!ctx)
    {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
        goto error;
        return 1;
    }
    /**
     * @brief Set the list of trusted CAs based on the file and/or directory provided.
     * 
     * 
     * Returns
     *  0: The operation failed because CAfile and CApath are NULL or the processing at one of the locations specified failed.
     *      Check the error stack to find out the reason.
     *  1: The operation succeeded.
     * 
     */
    if (SSL_CTX_load_verify_locations(ctx, "/home/daniel/tcp/https_server/ca.crt", "/usr/lib/ssl/certs") < 1)
    {
        printf("Error setting CA verify location\n");
        goto error;
    }


    /**
     * @brief Set for server verification
     * SSL_CTX_set_verify() sets the verification flags for ctx to be mode 
     *  and specifies the verify_callback function to be use
     * 
     * SSL_VERIFY_NONE
     *  Client_mode: if not using an anonymous cipher (by default disabled), 
     *  the server will send a certificate which will be checked.
     * 
     *  verify the  TLS/SSL handshake SSL_get_verify_result()
     * 
     * SSL_VERIFY_PEER
     * 
     * client_mode:  The server certificate is verified.
     * If the verification process fails, the TLS/SSL handshake is immediately terminated with 
     * an alert message containing the reason for the verification failure.
     * If no server certificate is sent, because an anonymous cipher is used, SSL_VERIFY_PEER is ignored.
     *  
     */
    if(!self_signed)SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

   

    printf("Connecting to %s on port %s... ", hostname, port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *bind_address = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    getaddrinfo(hostname, port, &hints, &bind_address);

    int server_fd = socket(bind_address->ai_family, bind_address->ai_socktype, bind_address->ai_protocol);
    if (server_fd == -1)
    {
        close(server_fd);
        fprintf(stderr, "failed\n");
        exit(1);
    }

    if (connect(server_fd, bind_address->ai_addr, bind_address->ai_addrlen))
    {
        close(server_fd);
        fprintf(stderr, "failed\n");
        return 1;
    }
    printf("connected TCP\n");

    printf("Initializing SSL/TLS handshake ... \n");

    /**
     * @brief creates a new SSL structure which is needed to hold the data for a TLS/SSL connection
     */
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        SSL_CTX_free(ctx);
        close(server_fd);
        fprintf(stderr, "Unable to start SSL handshake with %s\n", hostname);
        
        exit(1);
    }
    /**
     * @brief 
     *  function should only be called on SSL objects that will act as clients
     * 
     * If a servername has been set via a call to SSL_set_tlsext_host_name()
     *  then it will return that servername.
     * 
     * Otherwise it returns NULL.
     */
    if (!SSL_set_tlsext_host_name(ssl, hostname))
    {
        fprintf(stderr, "SSL_set_tlsext_host_name() failed.\n");
        exit(1);
    }
    /**
     * Connect the SSL object with a file descriptor.
     * 
     * SSL_set_fd() sets the file descriptor fd as the input/output facility for the TLS/SSL (encrypted) side of ssl
     * 
     * Returns
     * 
     * 0: The operation failed. Check the error stack to find out why.
     * 1: The operation succeeded.
     */
     if(SSL_set_fd(ssl, server_fd) < 1){
         fprintf(stderr, "SSL binding failed\n");
     };

    /**
     *  Initiate the TLS/SSL handshake with an TLS/SSL server
     * 
     * If the underlying BIO is blocking, 
     * SSL_connect() will only return once the handshake has been finished or an error occurred.
     */
    if (SSL_connect(ssl) == -1)
    {
        fprintf(stderr, "SSL_connect() failed.\n");
        goto error;
    }
    printf("SSL/TLS using %s\n", SSL_get_cipher(ssl));

    if (SSL_CTX_set_default_verify_paths(ctx))
    {
        printf("Verified!");
    }
    
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        fprintf(stderr, "SSL_get_peer_certificate() failed.\n");
        exit(1);
    }

    char *tmp;
    if (tmp = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0))
    {
        printf("subject: %s\n", tmp);
        OPENSSL_free(tmp);
    }

    if (tmp = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0))
    {
        printf("issuer: %s\n", tmp);
        OPENSSL_free(tmp);
    }
    long vp = SSL_get_verify_result(ssl);
    if (vp == X509_V_OK)
    {
        printf("Certificates verified successfully.\n");
    }
    else
    {
        printf("Could not verify certificates: %ld\n", vp);
    }

    char buffer[2048];

    sprintf(buffer, "GET / HTTP/1.1\r\n");
    sprintf(buffer + strlen(buffer), "Host: %s:%s\r\n", hostname, port);
    sprintf(buffer + strlen(buffer), "Connection: close\r\n");
    sprintf(buffer + strlen(buffer), "User-Agent: https_simple\r\n");
    sprintf(buffer + strlen(buffer), "\r\n");

    SSL_write(ssl, buffer, strlen(buffer));

    while (1)
    {
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received < 1)
        {
            printf("\nConnection closed by peer.\n");
            break;
        }

        printf("Received (%d bytes): '%.*s'\n",
               bytes_received, bytes_received, buffer);
    }

    X509_free(cert);
    close(server_fd);
    SSL_free(ssl);

    error:
		ERR_print_errors_fp(stderr);

    return 0;
}