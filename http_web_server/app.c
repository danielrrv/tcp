
#include "./server.h"


const char port[] ="8080";

void hello(request_t *req, response_t *res)
{
	printf("%s\n", req->body);

	send_to_client(res, "Hoy ya es lunes", 200);
}

void listening(){
	printf("Listening on %s\n", port);
}

int main()
{

	server_t server;

	serve(&server, hello);

	wait_for_client_on(&server, port, listening);
	
	return 0;
}
