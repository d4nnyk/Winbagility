#include "stdafx.h"
#include "windows.h"

#include "kd.h"
#include "mmu.h"
#include "dissectors.h"
#include "utils.h"
#include "kdserver.h"
#include "kdproxy.h"

//TODO: !
void usage(){

}


//TODO: take arguments !!
int _tmain(int argc, _TCHAR* argv[]){

#if 1
	//This structure contains all information needed for windbg
	analysisContext_t curContext;

	//DEBUGGED RAW DMP
	//char fileName[] = "C:\\8_1_x64_DEBUG.dmp";
	//curContext.curMode = DEBUGGED_IMAGE_TYPE;

	//UNDEBUGGED RAW DMP
	char fileName[] = "C:\\8_1_x64_STOCK.dmp";
	curContext.curMode = STOCK_IMAGE_TYPE;

	//UNDEBUGGED WINDOWS IN FDP COMPLIANT VM
	//char fileName[] = "\\\\.\\pipe\\debugger"; //FDP named Pipe
	//curContext.curMode = STOCK_VBOX_TYPE;

	//LET'S START !!!
	curContext.dmpFileName = fileName;
	if (initKDServer(&curContext) == false){
		printf("Unable to initialize KD Server !\n");
		system("pause");
	}
	startKDServer();
#else
	//TODO ...
	startKDProxy();
#endif

	return 0;
}

