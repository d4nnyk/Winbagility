// NamedPipeProxy.cpp : Defines the entry point for the console application.
//


#include "stdafx.h"
#include "windows.h"

#include "kd.h"
#include "mmu.h"
#include "dissectors.h"
#include "utils.h"
#include "kdserver.h"
#include "kdproxy.h"


int _tmain(int argc, _TCHAR* argv[]){

	initKDServer();
	startKDServer();


	//startKDProxy();

	return 0;
}

