
/*******************************************************************************
 *                                                                             *
 * seh-suppoprt.c - Functions used to implement SEH support at runtime.        *
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



#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "seh-support.h"
#include "../../common/stddefs.h"

#ifdef LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL

/* RtlUnwind may or may not be already defined, depending on the version of the Win32 headers. */
void WINAPI RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);

/* Internal prototypes */
DECLLANG int __attribute__((noreturn)) __stdcall __libseh_restore_context(volatile __libseh_buf* buf, int ret);
DECLLANG void __stdcall __libseh_unwind_up_to(volatile __libseh_buf* reg);
DECLLANG int __stdcall __libseh_do_finally_block(volatile __libseh_buf* buf, int ret);
DECLLANG int __stdcall __libseh_query_filter_func(volatile __libseh_buf* buf, int ret);

DECLLANG
int __libseh_exception_handler(PEXCEPTION_RECORD pRecord,
                               __libseh_buf* pReg,
                               PCONTEXT pContext,
                               PEXCEPTION_RECORD pRecord2)
{
  TRACE_START();
  _PEXCEPTION_HANDLER me = pReg->handler;

  TRACE1("Value of %%fs:0 = 0x%08x\n", __libseh_get_registration());
  TRACE1("Value of pReg = 0x%08x\n", pReg);
  TRACE1("Previous registration: 0x%08x\n", pReg->prev);
  TRACE1("Handler function: 0x%08x\n", pReg->handler);
  TRACE1("This function's address: 0x%08x\n", me);
  TRACE1("Magic number: 0x%08x\n", pReg->magic);
  TRACE1("Flags: 0x%08x\n", pReg->flags);
  TRACE1("Exception code: 0x%08x\n", pRecord->ExceptionCode);
  TRACE1("Exception address: 0x%08x\n", pRecord->ExceptionAddress);

  if (pRecord->ExceptionFlags & EXCEPTION_UNWINDING || 
      pRecord->ExceptionFlags & EXCEPTION_EXIT_UNWIND)
  {
    TRACE0("Unwinding 1 frame.\n");
    if (FLAG_IS_SET(pReg->flags, FLAG_FINALLY_BLOCK)) 
    {
      TRACE0("Calling finally block.\n");
      __libseh_do_finally_block(pReg, 3);
      TRACE0("Return from finally block.\n");
    }
    
    TRACE0("Done unwinding 1 frame.\n");

    return ExceptionContinueSearch;
  }

  if (NULL != pReg && !FLAG_IS_SET(pReg->flags, FLAG_FINALLY_BLOCK)) {
    if (pReg->handler == me && pReg->magic == SEH_MAGIC_NUMBER) {
      /* Evaluate filter function. */
      int result = pReg->const_filter_value;
      TRACE1("pReg->const_filter_value = %d\n", result);
      if (!FLAG_IS_SET(pReg->flags, FLAG_CONST_FILTER_EXPR))
      {
        TRACE0("Querying filter expression.\n");
        __libseh_info info;
        pReg->excinfo = &info;
        memcpy(&info.record, pRecord, sizeof(EXCEPTION_RECORD));
        memcpy(&info.record2, pRecord2, sizeof(EXCEPTION_RECORD));
        memcpy(&info.context, pContext, sizeof(CONTEXT));
        info.pointers.ContextRecord = &(info.context);
        info.pointers.ExceptionRecord = &(info.record);
        result = __libseh_query_filter_func(pReg, 1);
        pReg->excinfo = NULL;
      }

      TRACE1("Filter expression value: %d\n", result);

      if (result < 0)
      {
        return ExceptionContinueExecution;
      }
      else if (result != EXCEPTION_CONTINUE_SEARCH)
      {
        TRACE0("Unwinding previous frames.\n");
        __libseh_unwind_up_to(pReg);
        TRACE0("Running exception block.\n");
        __libseh_restore_context(pReg, 2);
      } 
    }
  }

  TRACE_END();

  return ExceptionContinueSearch;
}

DECLLANG 
void __libseh_init_buf(__libseh_buf* buf)
{
  TRACE_START();
  TRACE1("buf = 0x%08x\n", buf);
  buf->magic = SEH_MAGIC_NUMBER;
  buf->excinfo = NULL;
  TRACE_END();
}

DECLLANG 
void __libseh_fini_buf(__libseh_buf* buf)
{
  TRACE_START();
  buf->magic = 0x0;
  TRACE_END();
}

static DECLLANG int
__libseh_fe_exception_handler(PEXCEPTION_RECORD pRecord,
                           __libseh_fe_buf* pReg,
                           PCONTEXT pContext,
                           PEXCEPTION_RECORD pRecord2)
{
  TRACE_START();
  TRACE_END();
  return ExceptionContinueSearch;
}

static DECLLANG LONG WINAPI
__libseh_ueh_toplevel_filter(struct _EXCEPTION_POINTERS* exc_info)
{
  TRACE_START();
  __libseh_fe_buf* reg = (__libseh_fe_buf*)__libseh_get_registration();
  _PUEH_FILTER filter = reg->prev_ueh_filter;
  __libseh_set_registration(reg->real_prev);
  TRACE_END();
  return filter ? filter(exc_info) : ExceptionContinueSearch;
}

DECLLANG void __attribute__((noreturn))
__libseh_raise_fatal_exception(DWORD exc_code, DWORD exc_flags, DWORD num_arguments, const ULONG_PTR* arguments)
{
  TRACE_START();
  __libseh_buf* prev_reg = __libseh_get_registration();
  __libseh_fe_buf reg;
  reg.prev = NULL;
  reg.handler = __libseh_fe_exception_handler;
  reg.real_prev = prev_reg;
  reg.prev_ueh_filter = SetUnhandledExceptionFilter(__libseh_ueh_toplevel_filter);
  __libseh_set_registration((__libseh_buf*)&reg);
  RaiseException(exc_code, exc_flags, num_arguments, arguments);
  __LIBSEH_UNREACHABLE();
}

#endif
