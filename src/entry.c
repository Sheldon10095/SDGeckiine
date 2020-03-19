#include <string.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "common/common.h"
#include "main.h"
#include "gecko/tcpgecko/main_gecko.h"
#include "gecko/tcpgecko/tcp_gecko.h"

int __entry_menu(int argc, char **argv)
{
    //! *******************************************************************
    //! *                 Jump to our application                    *
    //! *******************************************************************


    if (isRunningAllowedTitleID())
    {
        InitOSFunctionPointers();
        InitSocketFunctionPointers();
        InitGX2FunctionPointers();

        //log_init(COMPUTER_IP_ADDRESS);
        //log_print("OSGetTitleID checks passed...\n");
        startTCPGecko();
        Menu_Main();

        return EXIT_RELAUNCH_ON_LOAD;
    }

    InitOSFunctionPointers();

    int gecko = Menu_Main_gecko();
    if (gecko != EXIT_SUCCESS)
    {
        return Menu_Main();
    }
    else 
    {
        //OSForceFullRelaunch();
        
        return EXIT_SUCCESS;
    }
}
