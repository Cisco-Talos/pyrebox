
/*******************************************************************************
 *                                                                             *
 * sehpp.h - C++ SEH interface.                                                *
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

/** @file sehpp.h
 *  Interface for LibSEH C++ bindings.
 */

#ifndef __LIBSEH_SEHPP_H__
#define __LIBSEH_SEHPP_H__

#if defined(__cplusplus)

#include <stdexcept>
#include "../common/config.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace seh
{
  
#if defined(LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL)

  /**
   * Upon destruction, this removes one handler from the SEH
   * handler stack.
   */
  class __libsehpp_cleanup
  {
    public:
      ~__libsehpp_cleanup();
      
      /**
       * Dummy function to stop GCC and possibly other compilers
       * from generating a warning about unused instances
       * of this class.  Calling this once with each initialization
       * should be sufficient.
       */
      void dummy() { }
  };

  /**
   * Initializes libsehpp.  This should not be called directly.  Instead,
   * use the libsehpp_initialize macro.
   *
   * @param buf   A pointer to a ___libseh_buf that is
   *              located on the stack.
   */
  void __initialize(__libseh_buf* buf);

  // Macro for initializing sehpp
#define libsehpp_initialize()                            \
    ___libseh_buf __libsehpp_handler;                    \
    seh::__initialize(&__libsehpp_handler);              \
    seh::__libsehpp_cleanup __libsehpp_cleanup_handler;  \
    __libsehpp_cleanup_handler.dummy();                  \

#elif defined(_MSC_VER)

  /**
   * Initializes libsehpp.  This should not be called directly.  Instead,
   * use the libsehpp_initialize macro.
   */
  void __initialize();

  // Macro for initializing sehpp
#define libsehpp_initialize()                \
    seh::__initialize();                     \

#else
#if defined(HAVE_COMPILER_SEH_SUPPORT)
#warning This compiler has SEH support but does not have a runtime with the _set_se_translator function!
#endif
#define libsehpp_initialize()   
#endif

  /**
   * @class exception
   * @brief The base of all sehpp exceptions.
   * @since 9-6-2008
   * @version 1.0
   */
  class exception : public std::exception
  {
    public:
      /**
       * Constructor
       *
       * @param code     The exception code.
       * @param address  The address in which the exception occurred.
       */
      explicit
      exception(LPEXCEPTION_POINTERS exc_info);

      virtual
      ~exception() throw() { }

      /**
       * Gets a description of the exception.
       *
       * @return The description of the exception.
       */
      virtual const char*
      what();

      /**
       * Get information about the exception that occurred.
       *
       * @return A pointer to the exception information.
       */
      const PEXCEPTION_RECORD
      record() { return &record_; }

      /**
       * Get information about the context in which the
       * exception occurred.
       *
       * @return A pointer to a CONTEXT structure relating to the
       *         exception that occurred.
       */
      const PCONTEXT
      context() { return &context_; }

    protected:
      /**
       * Set the exception message.
       *
       * @param msg    The exception message.
       */
      virtual void set_msg(const std::string& msg);

      explicit
      exception() { }

    private:
      std::string msg_;          ///<  The internal message buffer.
      EXCEPTION_RECORD record_;  ///<  The exception record.
      CONTEXT context_;          ///<  The exception context.
  };

#define DEFINE_EXCEPTION_CLASS(class_name)                \
  class class_name : public exception                     \
  {                                                       \
    public:                                               \
      explicit class_name(LPEXCEPTION_POINTERS exc_info); \
                                                          \
      virtual ~class_name () throw() { }                  \
  }

  /* Exception class declarations */
  DEFINE_EXCEPTION_CLASS(access_violation);
  DEFINE_EXCEPTION_CLASS(datatype_misalignment);
  DEFINE_EXCEPTION_CLASS(array_bounds_exceeded);
  DEFINE_EXCEPTION_CLASS(flt_denormal_operand);
  DEFINE_EXCEPTION_CLASS(flt_divide_by_zero);
  DEFINE_EXCEPTION_CLASS(flt_inexact_result);
  DEFINE_EXCEPTION_CLASS(flt_invalid_operation);
  DEFINE_EXCEPTION_CLASS(flt_overflow);
  DEFINE_EXCEPTION_CLASS(flt_stack_check);
  DEFINE_EXCEPTION_CLASS(flt_underflow);
  DEFINE_EXCEPTION_CLASS(int_divide_by_zero);
  DEFINE_EXCEPTION_CLASS(int_overflow);
  DEFINE_EXCEPTION_CLASS(priv_instruction);
  DEFINE_EXCEPTION_CLASS(in_page_error);
  DEFINE_EXCEPTION_CLASS(illegal_instruction);
  DEFINE_EXCEPTION_CLASS(noncontinuable_exception);
  DEFINE_EXCEPTION_CLASS(stack_overflow);
  DEFINE_EXCEPTION_CLASS(invalid_disposition);
  DEFINE_EXCEPTION_CLASS(guard_page);
  DEFINE_EXCEPTION_CLASS(invalid_handle);
  DEFINE_EXCEPTION_CLASS(ctrl_c_break);

#undef DEFINE_EXCEPTION_CLASS

}

#endif /* __cplusplus */

#endif /* __LIBSEH_SEHPP_H__ */
