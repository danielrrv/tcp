

/**
 * @brief  Implementation for DNS client under RFC 1035 DOMAIN NAMES.
 * 
 * https://datatracker.ietf.org/doc/html/rfc1035
 * 
 * Copyright (C) 2021, Daniel Rodriguez <drodrigo@gmail.com>
 * 
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

/**
 * Definition based on https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1 
 */
#define HEADER_LENGTH 12

// Albitrary Buffer size.
enum
{
	BUFFER_SIZE = 1024

};

typedef int socket_t;

typedef enum
{
	NO_ERROR = 0x00,
	FORMAT_ERROR = 0x01,
	SERVER_ERROR = 0x02,
	NAME_ERROR = 0x03,
	NO_IMPLEMENTED = 0x04,
	REFUSED = 0x05
} r_code_t;

typedef struct
{

	uint8_t *data;
	size_t length;

} dns_package_t;

uint8_t header[12] = {
	0xdb, //ID
	0x42, //ID
	0x01, //QR-OPCODE-AA-RD
	0x00, //RA-Z-RCODE
	0x00, //QDCOUNT
	0x01, //QDCOUNT
	0x00, //ANCOUNT
	0x00, //ANCOUNT
	0x00, //NSCOUNT
	0x00, //NSCOUNT
	0x00, //ARCOUNT
	0x00, //ARCOUNT
};

uint8_t question[4] = {
	0x00, //QTYPE
	0x01, //QTYPE
	0x00, //QCLASS
	0x01  //QCLASS
};
/**
 * @brief Construct the cname under https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
 * 
 * @param hostname 
 * @return uint8_t* 
 */
static uint8_t *capture_hostname(uint8_t *hostname)
{
	//hostname pointer must not be NULL. TODO close the process.
	if (hostname == NULL)
		return NULL;
	size_t len = strlen(hostname);
	//Implementation to allocate the memory block required to store cname.
	uint8_t *cname = (uint8_t *)malloc(BUFFER_SIZE * sizeof(uint8_t));
	//What it is for: To avoid any bug associated with memory corruption.
	memset(cname, '\0', BUFFER_SIZE * sizeof(uint8_t));
	//Add the zero for the end of the message.
	cname[len + 1] = 0x00;
	//Track the number  of char counted up to the dot.
	uint8_t point = 0;
	//Implementatio to iterate inversely the host name starting from the end to start.
	uint8_t *ptr = hostname + len - 1;
	do
	{
		//Case #1: dot. Then append the count of chars so far and continue.
		if (*ptr == '.')
		{
			cname[len] = point;
			point = 0;
			continue;
		}
		//Case #2:append the char in the location indicated.
		cname[len] = *ptr;
		//Implementation to increment the number char counter up to the next poiint.
		point++;
	} while ((hostname != ptr--) && --len);
	//Adppend the last count for the latest portion of the hostname/webname.
	cname[0] = point;
	return cname;
}

/**
 * @brief constructs the message for DNS query.
 * 
 * @param  hostname 
 * @return dns_package_t* 
 */
static dns_package_t *package_f(uint8_t *hostname)
{
	//What it does: initialize the package structure.
	dns_package_t *package = (dns_package_t *)malloc(sizeof(dns_package_t));
	//What it does: allocate the memory for store the data of the message.
	package->data = (uint8_t *)malloc(BUFFER_SIZE * sizeof(uint8_t));
	//What is it for: To avoid bug and clear the memory block.
	memset(package->data, '\0', BUFFER_SIZE);
	//What it does: copy the header memory block into package->data pointer through 12 bytes.
	memcpy(package->data, &header, HEADER_LENGTH);
	//What it it for: To carry the lenght of the question so far.
	package->length += HEADER_LENGTH;
	//Implementation to construct the question  https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
	uint8_t *cname = capture_hostname(hostname);
	//what it does: Copy cname in the pointer after the 12 Bytes of header.
	memcpy(package->data + HEADER_LENGTH, cname, strlen(cname) + 1);
	//Add up the bytes recently added plus a byte for zero of the end of cname.
	package->length += strlen(cname) + 1;
	//Map the question type according to https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2 and
	//https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
	memcpy(package->data + HEADER_LENGTH + strlen(cname) + 1, &question, sizeof(question));
	// Carry the length.
	package->length += sizeof(question);
	return package;
}

/**
 * @brief Display the NAME from the answer section.
 * 
 * @param current_ptr 
 * @param end_message 
 */
void print_message(uint8_t *current_ptr, const uint8_t *end_message)
{
	//Recursive condition:  Until the current pointer reachs out the end, iterate recursively.
	if (current_ptr == end_message)
	{
		fprintf(stdout, "End of the message\n");
		exit(0);
	}

	//The https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4 indicates the message pointer starts by 1100000 or 0xC0.
	if (*current_ptr == 0xC0)
	{	
		//The next block of memory according to https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4 indicates the offset from the
		//start of the message [0xC0] through the next address Type value of this implementation [A - host address].
		uint8_t offset = current_ptr[1];
		//Just to the start of the address.
		print_message(current_ptr + offset, end_message);
	}
	else
	{
		//Implementation to avoid to place a for the ipv4 octect. Instead new line is placed.
		if (&current_ptr[1] == end_message || current_ptr[1] == 0xC0)
			printf("%d\n", *current_ptr);
		else
			//Otherwise place the octect along with the corresponding dot for ipv4.
			printf("%d.", *current_ptr);
		//Keep iterating.
		print_message(current_ptr + 1, end_message);
	}
}

static void read_answer(uint8_t *response, int bytes_received, int question_length)
{
	//What is it for: Keep the pointer for moving through it along the response.
	uint8_t *ptr = response;
	//Implementation to declare the end of the message based on the len of the UDP response.
	uint8_t *end_message = response + bytes_received;
	//Move to the next memory block.
	ptr++;
	//What it is for: To validate that the IDs(the first 2 octect) are what were sent in the question.
	if ((*response & 0xdb) != 0xdb || (*ptr & 0x42 != 0x42))
	{
		fprintf(stderr, "Incorrect IDs\n");
		exit(1);
	}
	//Move to the next memory block.
	ptr++;
	//What it does: Obtain the following properties in the header.
	// - QR: A one bit field that specifies whether this message.
	// - OPCODE:A four bit field that specifies kind of query in this message.
	// - TC- TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel

	uint8_t qr = (*ptr >> 0x07) & 0x01;
	uint8_t opcode = (*ptr >> 0x03) & 0xF;
	uint8_t tc = (*ptr >> 0x01) & 0x01;
	// Validation: Truncate must be zero if UDP trasmission channel was enough to carry the datagram(s).
	if (tc == 1)
	{
		fprintf(stderr, "Message truncated. Upgrate protocol\n");
		exit(1);
	}
	// What is it: The recursion desired on the query. This implemention does want it.
	uint8_t rq =  *ptr & 0xF;
	//Move to the next memory block.
	ptr++;
	//What is it for: To obtain the RCODE from header response 
	uint8_t rcode = *ptr & 0xF;
	switch (*ptr & 0xF)
	{
	case NO_ERROR:
		fprintf(stdout, "-- No error(s) --\n");
		break;
	case FORMAT_ERROR:
		fprintf(stdout, "Format Error\n");
		exit(1);
	case SERVER_ERROR:
		fprintf(stdout, "Server failure\n");
		exit(1);
	case NAME_ERROR:
		fprintf(stdout, "Name error\n");
		exit(1);
	case REFUSED:
		fprintf(stdout, "Refused\n");
		exit(1);
	default:
		break;
	}
	// Move to the next memory block.
	ptr++;
	//No. Questions sent.
	uint8_t qd_question = (*(ptr + 1) & 0x7F);
	// Move to the next 2 memory block.
	ptr++;
	ptr++;
	//No. Answers received.
	uint8_t an_question = (*(ptr + 1) & 0x7F);
	// Move to the next 2 memory block.
	ptr++;
	ptr++;
	//  the number of name server resource.
	uint8_t ns_question = (*(ptr + 1) & 0x7F);
	// Move to the next 2 memory block.
	ptr++;
	ptr++;
	//The number of resource records in the additional records section.
	uint8_t ar_question = (*(ptr + 1) & 0x7F);

	printf("Truncated: %s\n", tc == 0x01 ? "T" : "F");
	printf("Recursivity: %s\n", rq == 0x01 ? "T" : "F");
	printf("No. Question(s): %d\n", qd_question);
	printf("No. Answer(s): %d\n", an_question);
	// Move to the next memory block.
	ptr++;//We are at the end of the HEADER.
	// Declare the answer section based on the question length seccion.
	uint8_t *answer = ptr + question_length;

	//Implementation to display the answer from response.
	print_message(++answer, end_message);
	//https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
}

static struct addrinfo *get_address_info(char *host, char *port, int socket_type)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socket_type;
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

static const char usage[] = "Usage: ./dns hostname";

int main(int argc, char *argv[])
{

	if (argc < 2)
	{
		fprintf(stderr, "Error: Hostname is required\n");
		fprintf(stdout, "%s\n", usage);
		exit(1);
	}

	//Construct the message under https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
	dns_package_t *package = package_f(argv[1]);

	//Binding the query to Google DNS server under UDP.
	struct addrinfo *bind_address = get_address_info("8.8.8.8", "53", SOCK_DGRAM);
	// UPD Family address for the desired address
	socket_t socket_server_dns = create_socket(bind_address);

	fprintf(stdout, "Querying...%s to Google DNS server [8.8.8.8/UDP]\n", argv[1]);

	//Implementation to send the datagram to DNS server.
	int bytes_sent = sendto(socket_server_dns,
							package->data, package->length, 0,
							bind_address->ai_addr,
							bind_address->ai_addrlen);

	fprintf(stdout, "Bytes sent: %d\n", bytes_sent);
	uint8_t read[BUFFER_SIZE];
	memset(read, '\0', BUFFER_SIZE);
	//Implementation to receive datagram fron DNS server.
	int bytes_received = recvfrom(socket_server_dns, read, BUFFER_SIZE, 0., 0, 0);
	fprintf(stdout, "Bytes received: %d\n", bytes_received);

	//Implementation to process the message and display the answser.
	read_answer(read, bytes_received, package->length - HEADER_LENGTH);

	return 0;
}