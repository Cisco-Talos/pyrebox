/* Common test header */

/* So the __seh prefixed macros are not used accidentally in the tests */
#define LIBSEH_PREFIX_MACROS_ONLY

#include <seh.h>
#include <windows.h>
#include "tests.h"

DWORD exc_filter(DWORD code, DWORD filtercode)
{
    if(code == filtercode)
        return EXCEPTION_EXECUTE_HANDLER;

    return EXCEPTION_CONTINUE_SEARCH;
}


