#include <gctypes.h>
#include "retain_vars.h"
char ipFromSd[16] __attribute__((section(".data")));
u8 hasReadIP __attribute__((section(".data"))) = 0;
u8 gAppStatus __attribute__((section(".data"))) = 0;
volatile u8 gSDInitDone __attribute__((section(".data"))) = 0;
FileReplacer * replacer __attribute__((section(".data"))) = NULL;
char selectedMultiModPackFolder[FS_MAX_ENTNAME_SIZE] __attribute__((section(".data"))) = "/\0";

struct fs_patcher_utils fspatchervars __attribute__((section(".data")));
