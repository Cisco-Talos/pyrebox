
/*******************************************************************************
 *                                                                             *
 * seh.s - Platform specific SEH functions for i486+ (32-bit)                  *
 *                                                                             *
 * LIBSEH - Structured Exception Handling compatibility library.               *
 * Copyright (c) 2008 Tom Bramer < tjb at postpro dot net >                    *
 *                                                                             *
 * Permission is hereby granted, free of charge, to any person                 *
 * obtaining a copy of this software and associated documentation              *
 * files (the "Software"), to deal in the Software without                     *
 * restriction, including without limitation the rights to use,                *
 * copy, modify, merge, publish, distribute, sublicense, and/or sell           *
 * copies of the Software, and to permit persons to whom the                   *
 * Software is furnished to do so, subject to the following                    *
 * conditions:                                                                 *
 *                                                                             *
 * The above copyright notice and this permission notice shall be              *
 * included in all copies or substantial portions of the Software.             *
 *                                                                             *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,             *
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES             *
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                    *
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT                 *
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,                *
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING                *
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR               *
 * OTHER DEALINGS IN THE SOFTWARE.                                             *
 *                                                                             *
 *******************************************************************************/

// SEH library functions... very platform specific

#if defined(__WIN32__) || defined(__CYGWIN32__)
#define SYMBOL(x, y) _ ## x ##@## y
#define BARE_SYMBOL(x) _ ## x
#else
#define SYMBOL(x, y) x
#define BARE_SYMBOL(x) x
#endif

.global SYMBOL(__seh_register,4)
.global SYMBOL(__seh_restore_context,8)

/*
 * __seh_register: registers give __seh_buf object, while initializing it at 
 *                 the same time.
 *
 * Arguments: in __seh_buf*: Address of __seh_buf object which must be located
 *                           on the stack.
 *
 * Return value: 0 if returning from this function, or 1 if returning from 
 *               __seh_restore_context.
 *
 * Notes: This function implements a setjmp style non-local jump.  It may even
 *        be possible to use setjmp itself here, though that would not save one 
 *        from platform specific details.
 *
 *        The __seh_buf structure is a superset of the EXCEPTION_REGISTRATION 
 *        type used normally to register an exception handler.  Microsoft C
 *        also uses an extended version of this structure to implement SEH
 *        in the compiler.
 *
 */

SYMBOL(__seh_register,4):
    movl %ebx, %eax;
    movl %ebx, -0x4(%esp);
    popl %edx;   /* Return address */
    popl %ebx;   /* Pointer to SEH buffer */
    subl $0xc, %esp;
    
    /* Note: on Linux, the exception handler stack is maintained in __seh_init_buf */
    movl %esi, 12(%ebx);
    movl %edi, 16(%ebx);
    movl %eax, 20(%ebx);
    movl %edx, 24(%ebx);
    movl %ebp, 28(%ebx);
    movl %esp, 32(%ebx);

    /* Initialize everything else */
    pushl %ebx;
    pushl %ebx;
    call BARE_SYMBOL(__seh_init_buf);
    popl %ebx;
    popl %ebx;
    movl 24(%ebx), %edx;

    popl %ebx;
    addl $0x8, %esp;

    movl $0, %eax;
    jmp *%edx;

/*
 * __seh_restore_context: an over-glorified longjmp-like function.  
 *
 * Arguments: in __seh_buf*: Address of __seh_buf object which must be located
 *                           on the stack.
 *            in int:        Return value to give to the caller of __seh_register
 *
 */
SYMBOL(__seh_restore_context,8):
    popl %edx;   /* Return address... we don't need it. */
    popl %ebx;   /* Context buffer */
    popl %eax;   /* Return value */
    movl 12(%ebx), %esi;
    movl 16(%ebx), %edi;
    movl 20(%ebx), %ecx;
    movl 24(%ebx), %edx;
    movl 28(%ebx), %ebp;
    movl 32(%ebx), %esp;
    movl %ecx, %ebx;
    jmp *%edx;


/* Everything else is implemented in C for Linux. */    
