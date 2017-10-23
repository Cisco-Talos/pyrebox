
/*******************************************************************************
 *                                                                             *
 * seh.s - Platform specific SEH functions for i486+ (32-bit)                  *
 *                                                                             *
 * LIBSEH - Structured Exception Handling compatibility library.               *
 * Copyright (c) 2011 Tom Bramer < tjb at postpro dot net >                    *
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

#include "../../../../common/config.h"

#if defined(LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL)

#define STDCALL_SYM(x, y)  _ ## x ##@## y
#define CDECL_SYM(x) _ ## x

.global STDCALL_SYM(__libseh_register,4);
.global STDCALL_SYM(__libseh_restore_context,8);
.global STDCALL_SYM(__libseh_do_finally_block,8);
.global STDCALL_SYM(__libseh_query_filter_func,8);
.global STDCALL_SYM(__libseh_unregister,4);
.global STDCALL_SYM(__libseh_end_finally_blk,4);
.global STDCALL_SYM(__libseh_get_registration,0);
.global STDCALL_SYM(__libseh_set_registration,4);
.global STDCALL_SYM(__libseh_pop_registration,0);
.global STDCALL_SYM(__libseh_unwind_up_to,4);

/*
 * __libseh_register: registers give __libseh_buf object, while initializing it at 
 *                    the same time.
 *
 * Parameters: in __libseh_buf*: Address of __libseh_buf object which must be located
 *                               on the stack.
 *
 * Return value: 0 if returning from this function, or 1 if returning from 
 *               __libseh_restore_context.
 *
 * Notes: This function implements a setjmp style non-local jump.  It may even
 *        be possible to use setjmp itself here, though that would not save one 
 *        from platform specific details.
 *
 *        The __libseh_buf structure is a superset of the EXCEPTION_REGISTRATION 
 *        type used normally to register an exception handler.  Microsoft C
 *        also uses an extended version of this structure to implement SEH
 *        in the compiler.
 *
 *        %fs:0 is the first double word in the thread information block.  
 *        A linked-list of exception handler registration blocks is formed here,
 *        with %fs:0 pointing to the most recently added handler.
 * 
 */

STDCALL_SYM(__libseh_register,4):
    popl %edx;              
    popl %eax;
    movl %esi, 12(%eax);
    movl %edi, 16(%eax);
    movl %ebx, 20(%eax);
    movl %edx, 24(%eax);
    movl %ebp, 28(%eax);
    movl %esp, 32(%eax);

    movl %fs:0, %ecx;
    movl %ecx, 0(%eax);
    movl %eax, %fs:0;

    leal CDECL_SYM(__libseh_exception_handler), %ecx;
    movl %ecx, 4(%eax);

    /*
     * Apparently, functions created by GCC own the area of the stack where
     * arguments are provided.  As such, data on the stack in this area
     * cannot be assumed to be unchanged.
     */
    pushl %eax;
    pushl %eax;
    call ___libseh_init_buf;
    addl $4, %esp;
    popl %eax;

    movl 24(%eax), %edx;
    xorl %eax, %eax;
    jmp *%edx;


/*
 * __libseh_restore_context: an over-glorified longjmp-like function.  
 *
 * Parameters: in __libseh_buf*: Address of __libseh_buf object which must be located
 *                               on the stack.
 *             in int:           Return value to give to the caller of __libseh_register
 *
 */
STDCALL_SYM(__libseh_restore_context,8):
    addl $4, %esp;        /* Return address... we don't need it. */
    popl %ebx;            /* Context buffer */
    popl %eax;            /* Return value */
    movl 12(%ebx), %esi;
    movl 16(%ebx), %edi;
    movl 20(%ebx), %ecx;
    movl 24(%ebx), %edx;
    movl 28(%ebx), %ebp;
    movl 32(%ebx), %esp;
    movl %ecx, %ebx;
    jmp *%edx;

/*
 * __libseh_do_finally_block: an over-glorified longjmp-like function.  
 *                            Also fills in return jump context for
 *                            finally block execution.
 *
 * Parameters: in __libseh_buf*: Address of __libseh_buf object which must be located
 *                               on the stack.
 *             in int:           Return value to give to the caller of __libseh_register
 *
 */
STDCALL_SYM(__libseh_do_finally_block,8):
    popl %edx;            /* Return address */
    popl %eax;            /* Context buffer */
    addl $4, %esp;
    
    /* Fill in jump context for return. */
    movl %esi, 36(%eax);
    movl %edi, 40(%eax);
    movl %ebx, 44(%eax);
    movl %edx, 48(%eax);
    movl %ebp, 52(%eax);
    movl %esp, 56(%eax);

    movl %eax, %ebx;

    /* Return value */
    movl -4(%esp), %eax;

    movl 12(%ebx), %esi;
    movl 16(%ebx), %edi;
    movl 20(%ebx), %ecx;
    movl 28(%ebx), %ebp;
    movl 28(%ebx), %edx;
    subl 32(%ebx), %edx;
    subl %edx, %esp;
    movl 24(%ebx), %edx;
    movl %ecx, %ebx;
    jmp *%edx;

/*
 * __libseh_query_filter_func: like __libseh_restore_context, but with many specific aspects
 *                             for evaluating a filter function.   
 *
 * Parameters: in __libseh_buf*: Address of __libseh_buf object which must be located
 *                               on the stack.
 *             in int:           Return value to give to the caller of __libseh_register
 *
 * This function restores the execution state stored by __libseh_register (as in, a longjmp 
 * to the point right after the function call), except that %esp and %ebp are modified such 
 * that any writes relative to %esp or %ebp do not modify anything on the stack that was
 * in use prior to an exception being raised.  This function also provides a return jmpctx
 * as only the filter expression can be executed outside of context (as there are rules that 
 * the filter expression must follow).
 *
 */
STDCALL_SYM(__libseh_query_filter_func,8):
    pushl %ebp;
    movl %esp, %ebp;

    /*
     * Create the return jmpctx.
     */

    movl 8(%ebp),  %eax;
    addl $36,      %eax;

    movl %esi,     0(%eax);
    movl %edi,     4(%eax);
    movl %ebx,     8(%eax);
    movl $ret_jmp, 12(%eax);
    movl %ebp,     16(%eax);
    movl %esp,     20(%eax);
    
    /*
     * Load context for jumping to filter expression eval
     */

    subl $24,      %eax;

    movl 0(%eax),  %esi;
    movl 4(%eax),  %edi;
    movl 8(%eax),  %ebx;
    movl 12(%eax), %edx;

    /* %ebp is restored via return jump. */
    movl 16(%eax), %ebp;
    movl 16(%eax), %ecx;
    subl 20(%eax), %ecx;
    movl 12(%esp), %eax;
    subl %ecx,     %esp;
    jmp *%edx;

ret_jmp:
    /*
     * Clean up and return result.  
     * Result remains in %eax register.
     */
    popl %ebp;
    ret $8;


/*
 * __libseh_unregister: pops the last registered handler off the handler stack,
 *                      also releasing any resources that it may be holding on to that
 *                      aren't needed anymore.
 *
 * Parameters: none
 *
 */

STDCALL_SYM(__libseh_unregister,4):
    pushl %ebp;
    movl %esp, %ebp;

    /*
     * Apparently, functions created by GCC own the area of the stack where
     * arguments are provided.  As such, data on the stack in this area
     * cannot be assumed to be unchanged.
     */

    pushl 8(%ebp);
    call CDECL_SYM(__libseh_fini_buf);
    addl $4, %esp;

    movl 8(%ebp), %eax;
    movl 0(%eax), %eax;
    movl %eax, %fs:0;
    popl %ebp;
    ret $4;

/*
 * __libseh_end_finally_blk: pops the last registered handler off the handler stack,
 *                           also releasing any resources that it may be holding on to that
 *                           aren't needed anymore.  Also, if called for cleanup of a __finally
 *                           block when unwinding the stack due to an exception, this function
 *                           jumps back into the internal exception handling code.
 *
 * Parameters: none
 *
 */

STDCALL_SYM(__libseh_end_finally_blk,4):
    /*
     * Apparently, functions created by GCC own the area of the stack where
     * arguments are provided.  As such, data on the stack in this area
     * cannot be assumed to be unchanged.
     */

    pushl %ebp;
    movl %esp, %ebp;

    pushl 8(%ebp);
    call CDECL_SYM(__libseh_fini_buf);
    addl $4, %esp;

    movl 8(%ebp), %eax;
    btl $2, 60(%eax);
    jc 1f;
    
    /* FLAG_FINAL_BLOCK_CALL not set.  Jump back to handler. */
    movl 36(%eax), %esi;
    movl 40(%eax), %edi;
    movl 44(%eax), %ebx;
    movl 48(%eax), %edx;
    movl 52(%eax), %ebp;
    movl 56(%eax), %esp;
    jmp *%edx;

1:  pushl %ebx;
    movl 0(%eax), %ebx;
    movl %ebx, %fs:0;
    popl %ebx;
    popl %ebp;
    ret $4;

/*
 * __libseh_get_registration: returns the last registered handler registration off the
 *                            handler stack.
 *
 * Return value: __libseh_buf*  pointer to the handler block.
 *
 */

STDCALL_SYM(__libseh_get_registration,0):
    movl %fs:0, %eax;
    ret;

/*
 * __libseh_set_registration: sets the registration handler to the given argument.  Linked
 *                            list of exception handlers must be maintained by the caller.
 *
 * Parameters: in __libseh_buf*  the new exception handler registration structure.
 *
 */

STDCALL_SYM(__libseh_set_registration,4):
    movl 4(%esp), %eax;
    movl %eax, %fs:0;
    xorl %eax, %eax;
    ret $4;


/*
 * __libseh_pop_registration: like __libseh_unregister, but does not release any resources associated
 *                            with the registration block.
 *
 * Return value: __libseh_buf*  pointer to the new top of the handler stack.
 *
 */

STDCALL_SYM(__libseh_pop_registration,0):
    movl %fs:0, %eax;
    movl 0(%eax), %eax;
    movl %eax, %fs:0;
    ret;


/*
 * __libseh_unwind_up_to: Unwinds the registration stack up to but not including the specified
 *                        registration.
 *
 * Return value: __libseh_buf*  pointer to the registration serving as the upper bound of 
 *                              the unwind procedure.
 *
 */

STDCALL_SYM(__libseh_unwind_up_to,4):
    pushl %ebp;
    movl %esp, %ebp;
    pushl %ebx;
    pushl %esi;
    pushl %edi;
    pushl $0;
    pushl $0;
    pushl $1f;
    pushl 8(%ebp);
    call STDCALL_SYM(RtlUnwind,16);
1:
    popl %edi;
    popl %esi;
    popl %ebx;
    popl %ebp;
    ret $4;
   
#endif

