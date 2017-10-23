
#include <seh.h>
#include <windows.h>
#include <stdio.h>

/* Detect whether or not CPU has SSE support and whether OS has enabled support for SSE instructions and registers */
int sse_instructions_supported()
{
    unsigned int cpuFeatures = 0, cpuFeatures2 = 0;

    /* SSE bit is bit 25 in %edx register after CPUID call function 0x1 */
    asm (" cpuid; " : "=d" (cpuFeatures), "=c" (cpuFeatures2) : "a" (0x1) : "ebx");
    int sse_cpu = !!(cpuFeatures & (1 << 25));
    int sse_supported = sse_cpu;
    
    /* 
     * Because SSE adds new registers, SSE requires specific OS support for saving and restoring
     * registers with context switches. 
     */
    if(sse_cpu) 
    {
        __seh_try 
        {
            /* If SSE is not enabled by the OS, an EXCEPTION_ILLEGAL_INSTRUCTION exception will be raised. */
            asm (" pshufd $0xe4, %xmm0, %xmm0; ");
        }
        __seh_except(GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION) 
        {
            sse_supported = 0;
        }
        __seh_end_except
    }

    return sse_cpu | (sse_supported << 1);
}

int main()
{
    int sse_support = sse_instructions_supported();
    const char* yes = "yes";
    const char* no = "no";

    printf("CPU supports SSE instructions: %s\n", (sse_support & 1 ? yes : no));
    printf("OS has enabled SSE instructions (if supported): %s\n", ((sse_support >> 1) & 1 ? yes : no));

    return 0;
}



