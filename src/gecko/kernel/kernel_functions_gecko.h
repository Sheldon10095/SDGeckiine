#ifndef __KERNEL_FUNCTIONS_H_
#define __KERNEL_FUNCTIONS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "common/kernel_defs.h"
#include "syscalls.h"

extern ReducedCosAppXmlInfo cosAppXmlInfoStruct;

void SetupKernelCallback_gecko(void);

void KernelSetDBATs_gecko(bat_table_t * table);
void KernelRestoreDBATs_gecko(bat_table_t * table);

#ifdef __cplusplus
}
#endif

#endif // __KERNEL_FUNCTIONS_H_
