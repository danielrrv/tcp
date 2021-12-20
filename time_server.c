#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

//Implementation to handle errors
#define handle_error(msg)\
    do{perror(msg);return 1;} while(0)

//Implementation to print informative messages.
#define info(msg)\
    do{fprintf(stdout, msg);}while(0)

#define BUFFER_SIZE 1024
#define PORT "8080"

typedef int  SOCKET;


int main(){
    info("Configuring local address...\n");
    /**
     * getaddrinfo() requires a struct we are looking for in the address we indicated.
     * so, hints is the struct that shape the information we want.
     * 
    */
    struct addrinfo hints;
    memset(&hints,0, sizeof(hints));
    hints.ai_family = AF_INET;/* We are expecting IPv4. */
    hints.ai_socktype = SOCK_STREAM; /* We are going to use TCP reliable connection */
    hints.ai_flags = AI_PASSIVE; /* wildcard address. Get the address to use bind */
    /**
     * bind_address will hold the address information we query through getaddrinfo.
     * 
     * 
     * getaddrinfo() returns one or more addrinfo structs.Zero on Success. Different from zero on error.
     * getaddrinfo() allocates a linked list of addrinfo structs.
     * getaddrinfo( int node, const char * service, const struct addrinfo hints, struct ** addrinfo bind_address)
     * Where node - hostname or a IPv4 address in standard dot notation. 
     * Null or zero implies 127.0.0.1 or 0.0.0.0. It depends on the hints flags.
     * Where service - PORT.
     * Where hints - structure desired.
     * Where bind_address  -  struct pointer that receives the addresses.
    */
    struct addrinfo * bind_address;
    /* what it does: Translates the network interface to data structure that can be manipulated by programs */
    int s = getaddrinfo(0, PORT,  &hints,  &bind_address);
    if( s != 0){
        handle_error("getaddrinfo failed!%s\n");
    }
    /**
     * Creates an endpoint for communication between systems / process.
     * 
     * socket(family, socketype, and protocol) returns the sockfd.
     * 
    */
    info("Creating socket...\n");
    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family, bind_address->ai_socktype, bind_address->ai_protocol);
    if(socket_listen == -1 )handle_error("listen socket creation failed!\n");

    info("binding the socket_listen to the address\n");
    /**
     * bind(int sockdf, const struct sockaddr * addr, socklen_t addrlen )
     * returns zero on success; on error -1.
     * 
     * Binds the name to a sockfd
     * Binds the sockfd to the network interface described by bind_address
    */
    if(bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)){
        handle_error("Error binding the socket_listen to address.\n");
        close(socket_listen);
    }
   
    //Implementation to query the address name. Let's find out if local IPv4 or remote one. 
    char hostname[BUFFER_SIZE];
    s = getnameinfo(bind_address->ai_addr, bind_address->ai_addrlen,hostname, NI_MAXHOST, NULL, 0,NI_NUMERICHOST);
    if(s!=0)handle_error("Error: Unable to obtain address name");
     /* No longer needed because the socket is already bound to the address. Bind_addres only represents the address but it not the network interface itself.*/
    freeaddrinfo(bind_address);

    info("Listening...on: ");
    fprintf(stdout, "%s:%s\n", hostname, PORT);
    /**
     * 
     * listen(int sockfd, int backlog)
     * Where sockfd a socket that will be used to accept incoming connection requests using accept(2).
     * Where backlog defines the maximun length to which the queue of pending connections  sockfd may grow.
     * 
     * If queue is full, the connections will be rejected  ECONNREFUSED. If TCP, the protocol will retransmit datagrams.
     * 
     * Returns zero on success; on error -1
     * 
     * Listens for a connection on the sockfd we created on socket(...) above.
    */
    if(listen(socket_listen, 10) < 0){
        handle_error("Unable to listen for new connections\n");
        close(socket_listen);
    }

    info("Waiting for connections...\n");
    /**
     * We need to map the client's address somehow. Then create a socket through we can
     * accept(sockfd, sockaddr client_address, client_len) returns the file descriptor.
     * socket_listen is used to query the first queued requests and  create a socket on that address
     * The socket_listen contains the address of the client that is requiring connection.
     * accept(...) will map client_address and client len with the request network information.
     * returns -1 on error.
    */
    struct sockaddr_storage client_address;
    //The address length must be filled before calling accept.
    socklen_t client_len  = sizeof(client_address);
    SOCKET socket_client = accept(socket_listen, (struct sockaddr*)&client_address, &client_len);
    if(socket_client == -1)handle_error("Invalid socket at establishing comunication with client socket.\n");

    info("Client is connected...\n");
    char address_buffer[BUFFER_SIZE];
    /* Let's find out what the client network address interface.*/
    s = getnameinfo((struct sockaddr*)&client_address, client_len, address_buffer, sizeof(address_buffer), 0, 0, NI_NUMERICHOST);
    if(s!=0 && strlen(address_buffer) == 0){
        handle_error("Error: Unable to obtain address name");
        close(socket_client);
        close(socket_listen);
    }
    fprintf(stdout, "client: %s\n", address_buffer);

    info("Reading the request...\n");
    char request[BUFFER_SIZE];
    /*recv will read the content on the socket_client. request contains all user agent request data.*/
    int bytes_received = recv(socket_client, request, 1024, 0);
    fprintf(stdout, "Request content: %s", request);
    fprintf(stdout, "Bytes Received: %d\n", bytes_received);

    info("Sending respose...\n");

    char response[BUFFER_SIZE];
    sprintf(response, "HTTP/1.1 200 OK\r\n" );
    sprintf(response + strlen(response), "Connection: close\r\n");
    sprintf(response + strlen(response), "Content-Type: text/plain\r\n\r\n");
    sprintf(response + strlen(response), "Local time is: ");
    /*What it does: Write the response over the socket client file descriptor*/
    int bytes_sent = send(socket_client, response, strlen(response), 0);
    fprintf(stdout,"Bytes sent: %d\n", bytes_sent);
    //Implementation to pull out the date&time and convert it to string
    time_t timer;
    time(&timer);
    char *time_msg = ctime(&timer);
    /*What it does: Write the response over the socket client file descriptor*/
    bytes_sent = send(socket_client, time_msg, (int)strlen(time_msg), 0);
    fprintf(stdout,"Bytes sent: %d\n", bytes_sent);
    /*What is it for: Close the process file descriptor for client request. It terminates the request */
    close(socket_client);
    /*What is it for: Close the file descriptor for listening incoming requests*/
    close(socket_listen);
    info("Request finished!\n");
    //Termines the program.
    return 0;
}