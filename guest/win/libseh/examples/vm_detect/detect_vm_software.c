
#include <seh.h>
#include <windows.h>
#include <stdio.h>

/* Detect if this program is running in a VMWare guest. */
int detect_vmware(unsigned int* version)
{
    if(version) {
        *version = 0;
    }

    unsigned int ver = 0, resp = 0;
    int ret = 0;

    __seh_try
    {
        /*
         * VMWare uses an existing instruction that is not normally allowed in 
         * userspace and alters the behavior of the instruction (using other register inputs and outputs.)
         */
        asm ("in %%dx, %%eax;" 
            : "=a" (ver), "=b" (resp) 
            : "a" (0x564d5868), "b" (0), "c" (10), "d" (0x5658));

        if(resp == 0x564d5868)
        {
            ret = 1;
            if(version)
                *version = ver;
        }
    }
    __seh_except(GetExceptionCode() == EXCEPTION_PRIV_INSTRUCTION)
    {
        ret = 0;
    }
    __seh_end_except

    return ret;
}

/* Detect if this program is running in a MS Virtual PC guest. */
int detect_virtual_pc()
{
    int ret = 1;

    __seh_try
    {
        /* 
         * Virtual PC uses a custom opcode for communication to VPC within
         * the guest.
         */
        asm (".byte 0x0f, 0x3f, 0x07, 0x0b;"
             :
             : "a" (0x1));
    }
    __seh_except(GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        ret = 0;
    }
    __seh_end_except

    return ret;
}

int main()
{
    unsigned int vmware_version = 0;

    if(detect_vmware(&vmware_version))
    {
        printf("VMWare detected.  VMWare version: %d.\n", vmware_version);
    }
    else
    {
        puts("VMWare not detected.");
    }

    if(detect_virtual_pc())
    {
        puts("MS Virtual PC detected.");
    }
    else
    {
        puts("MS Virtual PC not detected.");
    }

    return 0;
}

