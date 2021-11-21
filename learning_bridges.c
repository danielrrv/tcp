
#include <stdlib.h>
#include <stdio.h>


#define BRIDGE_SIZE_TABLE 1024
#define MAX_TTL 120

// typedef struct MacAddr{};
// typedef struct Binding{};

typedef struct{
	// struct MacAddr * destionation;
	int ifnumber;
	u_short TTL;
	// struct Binding * binding;

} BridgeEntry;


int numberEntries = 0;



 BridgeEntry  bridge_map[BRIDGE_SIZE_TABLE * sizeof(BridgeEntry)];


 int main()
 {

	bridge_map[1] = {}BridgeEntry
	printf("Hello world!\n");
	 /* code */
	 return 0;
 }
 
