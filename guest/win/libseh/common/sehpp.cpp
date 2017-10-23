
/*******************************************************************************
 *                                                                             *
 * sehpp.cpp - C++ SEH implementation.                                         *
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

/** @file sehpp.cpp
 *  Implementation of LibSEH C++ bindings.
 */

#include "../seh.h"
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include "config.h"

#include <windows.h>
#ifdef _MSC_VER
#define snprintf _snprintf
#endif

using namespace std;

namespace seh
{
  void
  __libseh_exception_translator(unsigned int code, LPEXCEPTION_POINTERS exc_info)
  {
    TRACE_START();
    LPEXCEPTION_RECORD pRecord = exc_info->ExceptionRecord;

    switch(pRecord->ExceptionCode)
    {

#define IMPLEMENT_EXCEPTION_CASE(class_name, exc_code)         \
      case exc_code:                                           \
        TRACE0("Throwing " #class_name " exception\n");        \
        throw class_name(exc_info)

      IMPLEMENT_EXCEPTION_CASE(access_violation, EXCEPTION_ACCESS_VIOLATION);
      IMPLEMENT_EXCEPTION_CASE(datatype_misalignment, EXCEPTION_DATATYPE_MISALIGNMENT);
      IMPLEMENT_EXCEPTION_CASE(array_bounds_exceeded, EXCEPTION_ARRAY_BOUNDS_EXCEEDED);
      IMPLEMENT_EXCEPTION_CASE(flt_denormal_operand, EXCEPTION_FLT_DENORMAL_OPERAND);
      IMPLEMENT_EXCEPTION_CASE(flt_divide_by_zero, EXCEPTION_FLT_DIVIDE_BY_ZERO);
      IMPLEMENT_EXCEPTION_CASE(flt_inexact_result, EXCEPTION_FLT_INEXACT_RESULT);
      IMPLEMENT_EXCEPTION_CASE(flt_invalid_operation, EXCEPTION_FLT_INVALID_OPERATION);
      IMPLEMENT_EXCEPTION_CASE(flt_overflow, EXCEPTION_FLT_OVERFLOW);
      IMPLEMENT_EXCEPTION_CASE(flt_stack_check, EXCEPTION_FLT_STACK_CHECK);
      IMPLEMENT_EXCEPTION_CASE(flt_underflow, EXCEPTION_FLT_UNDERFLOW);
      IMPLEMENT_EXCEPTION_CASE(int_divide_by_zero, EXCEPTION_INT_DIVIDE_BY_ZERO);
      IMPLEMENT_EXCEPTION_CASE(int_overflow, EXCEPTION_INT_OVERFLOW);
      IMPLEMENT_EXCEPTION_CASE(priv_instruction, EXCEPTION_PRIV_INSTRUCTION);
      IMPLEMENT_EXCEPTION_CASE(in_page_error, EXCEPTION_IN_PAGE_ERROR);
      IMPLEMENT_EXCEPTION_CASE(illegal_instruction, EXCEPTION_ILLEGAL_INSTRUCTION);
      IMPLEMENT_EXCEPTION_CASE(noncontinuable_exception, EXCEPTION_NONCONTINUABLE_EXCEPTION);
      IMPLEMENT_EXCEPTION_CASE(stack_overflow, EXCEPTION_STACK_OVERFLOW);
      IMPLEMENT_EXCEPTION_CASE(invalid_disposition, EXCEPTION_INVALID_DISPOSITION);
      IMPLEMENT_EXCEPTION_CASE(guard_page, EXCEPTION_GUARD_PAGE);
      IMPLEMENT_EXCEPTION_CASE(invalid_handle, EXCEPTION_INVALID_HANDLE);
      IMPLEMENT_EXCEPTION_CASE(ctrl_c_break, CONTROL_C_EXIT);

#undef IMPLEMENT_EXCEPTION_CASE

    }

    TRACE0("Throwing other exception\n");
    throw exception(exc_info);

    // Not reached...
    TRACE_END();
  }

#ifdef LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL
  __libsehpp_cleanup::~__libsehpp_cleanup()
  {
    __libseh_pop_registration();
  }

  int
  __libseh_exception_handler(PEXCEPTION_RECORD pRecord,
                          __libseh_buf* pReg,
                          PCONTEXT pContext,
                          PEXCEPTION_RECORD pRecord2)
  {
    TRACE_START();
    EXCEPTION_POINTERS ptrs;
    ptrs.ExceptionRecord = pRecord;
    ptrs.ContextRecord = pContext;
    
    // I suppose this is cheating...
    while (__libseh_get_registration() != pReg) 
      __libseh_pop_registration();

    __libseh_exception_translator(pRecord->ExceptionCode, &ptrs);

    // Not reached
    TRACE_END();
    return ExceptionContinueSearch;
  }

  void
  __initialize(__libseh_buf* buf)
  {
    TRACE_START();
    
    memset(buf, 0, sizeof(*buf));
    buf->prev = __libseh_get_registration();
    buf->handler = __libseh_exception_handler;
    buf->magic = SEH_MAGIC_NUMBER;
    __libseh_set_registration(buf);

    TRACE_END();
  }

#elif defined(LIBSEH_HAVE_SET_SE_TRANSLATOR)

  void
  __initialize()
  {
    TRACE_START();
    _set_se_translator(__libseh_exception_translator);
    TRACE_END();
  }

#endif


  exception::exception(LPEXCEPTION_POINTERS exc_info)
  {
    memcpy(&record_, exc_info->ExceptionRecord, sizeof(record_));
    memcpy(&context_, exc_info->ContextRecord, sizeof(context_));
    LPEXCEPTION_RECORD rec = &record_;
    while(rec->ExceptionRecord != 0) {
      LPEXCEPTION_RECORD nr = rec->ExceptionRecord;
      rec->ExceptionRecord = new EXCEPTION_RECORD;
      memcpy(rec->ExceptionRecord, nr, sizeof(record_));
      rec = rec->ExceptionRecord;
    }

    const int buffer_len = 40;
    char buffer[buffer_len];
    snprintf(buffer, buffer_len, "System exception code 0x%08lx",
             record_.ExceptionCode);
    set_msg(buffer);
  }

  const char*
  exception::what()
  {
    return msg_.c_str();
  }

  void
  exception::set_msg(const std::string& msg)
  {
    msg_ = msg;
  }

#define IMPLEMENT_EXCEPTION_CTOR(class_name, descr)                              \
  class_name::class_name(LPEXCEPTION_POINTERS exc_info) : exception(exc_info)    \
  {                                                                              \
    set_msg((descr));                                                            \
  }

  IMPLEMENT_EXCEPTION_CTOR(access_violation, "Access violation")
  IMPLEMENT_EXCEPTION_CTOR(datatype_misalignment, "Data type misalignment")
  IMPLEMENT_EXCEPTION_CTOR(array_bounds_exceeded, "Array bounds exceeded")
  IMPLEMENT_EXCEPTION_CTOR(flt_denormal_operand, "Floating point NaN operand")
  IMPLEMENT_EXCEPTION_CTOR(flt_divide_by_zero, "Floating point division by zero")
  IMPLEMENT_EXCEPTION_CTOR(flt_inexact_result, "Floating point inexact result")
  IMPLEMENT_EXCEPTION_CTOR(flt_invalid_operation, "Floating point invalid operation")
  IMPLEMENT_EXCEPTION_CTOR(flt_overflow, "Floating point overflow")
  IMPLEMENT_EXCEPTION_CTOR(flt_stack_check, "Floating point stack error")
  IMPLEMENT_EXCEPTION_CTOR(flt_underflow, "Floating point underflow")
  IMPLEMENT_EXCEPTION_CTOR(int_divide_by_zero, "Integer division by zero")
  IMPLEMENT_EXCEPTION_CTOR(int_overflow, "Integer overflow")
  IMPLEMENT_EXCEPTION_CTOR(priv_instruction, "Privileged instruction")
  IMPLEMENT_EXCEPTION_CTOR(in_page_error, "In page error")
  IMPLEMENT_EXCEPTION_CTOR(illegal_instruction, "Illegal instruction")
  IMPLEMENT_EXCEPTION_CTOR(noncontinuable_exception, "Execution after noncontinuable exception")
  IMPLEMENT_EXCEPTION_CTOR(stack_overflow, "Stack overflow")
  IMPLEMENT_EXCEPTION_CTOR(invalid_disposition, "Invalid exception disposition")
  IMPLEMENT_EXCEPTION_CTOR(guard_page, "Guard page accessed")
  IMPLEMENT_EXCEPTION_CTOR(invalid_handle, "Invalid handle")
  IMPLEMENT_EXCEPTION_CTOR(ctrl_c_break, "User-initiated break")

#undef IMPLEMENT_EXCEPTION_CTOR
  
}


