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


	wchar_t fileName[] = L"C:\\8_1_x64_DEBUG.dmp";
	//wchar_t fileName[] = L"C:\\8_1_x64_STOCK.dmp";
	if (initKDServer(AUTO_IMAGE_TYPE, fileName) == false){
		printf("Unable to initialize KD Server !\n");
		system("pause");
	}
	startKDServer();

	//TODO ...
	//startKDProxy();

	return 0;
}

