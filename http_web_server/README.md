
Simple HTTP server


>It doesn't support more than 1024 user connected!




```c

const char port[] ="3000";

void hello(request_t *req, response_t *res)
{
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


```