/*******************************************************************************
 *                                                                             *
 * config.h - Configurable definitions.                                        *
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

#ifndef __LIBSEH_CONFIG_H__
#define __LIBSEH_CONFIG_H__

/*
 * Detect appropriate SEH implementation.
 *
 * Current implementations are:
 * LIBSEH_WIN32_SEH_IMPL: Standard LibSEH Win32 SEH implementation for GCC for 32-bit Windows targets.
 * COMPILER_SEH_IMPL: Use the compilers SEH implementation (MSVC, Digital Mars, Intel)
 *
 */

#if defined(_WIN32) && (defined(_MSC_VER) || defined(__DIGITALMARS__) || defined(__INTEL_COMPILER))
#define LIBSEH_USE_COMPILER_SEH_IMPL
#elif (defined(__MINGW32__) || defined(__CYGWIN__) || defined(__GNUWIN32__)) && !defined(__WIN64__)
#define LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL
#endif

#if defined(_MSC_VER)
#define LIBSEH_HAVE_SET_SE_TRANSLATOR
#endif

/* Warning for unsupported configurations. */
#if !defined(LIBSEH_USE_COMPILER_SEH_IMPL) && !defined(LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL) && !defined(LIBSEH_USE_LIBSEH_SIGNALS_SEH_IMPL)
#warning This compiler and/or operating system does not support structured exception \
         handling, so SEH will be disabled.
#endif

/* 
 * It is not recommended that one change the definitions below unless absolutely necessary.
 * If one simply wants different names, one should configure the section after this one.  
 * (the ones beginning with __seh as opposed to __libseh).  Changing the __libseh macro names
 * below will break the tests in the tests directory.
 */

#if defined(LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL) || defined(LIBSEH_USE_LIBSEH_SIGNALS_SEH_IMPL)

#define __libseh_try                             __LIBSEH_TRY
#define __libseh_except(x)                       __LIBSEH_EXCEPT(x)
#define __libseh_finally                         __LIBSEH_FINALLY
#define __libseh_leave                           __LIBSEH_LEAVE
#define __libseh_end_except                      __LIBSEH_END_EXCEPT
#define __libseh_end_finally                     __LIBSEH_END_FINALLY

#define __libseh_get_exception_code()            __LIBSEH_GET_EXCEPTION_CODE()
#define __libseh_get_exception_information()     __LIBSEH_GET_EXCEPTION_INFORMATION()

#elif defined(LIBSEH_USE_COMPILER_SEH_IMPL)

#define __libseh_try                             __try
#define __libseh_except(x)                       __except(x)
#define __libseh_finally                         __finally
#define __libseh_leave                           __leave
#define __libseh_end_except   
#define __libseh_end_finally  
#define __libseh_get_exception_code()            GetExceptionCode()
#define __libseh_get_exception_information()     GetExceptionInformation()

#else

#define __libseh_try                             do
#define __libseh_except(x)                       while(0); if(0) 
#define __libseh_finally                         if(1)
#define __libseh_leave                           break
#define __libseh_end_except   
#define __libseh_end_finally  
#define __libseh_get_exception_code()            0
#define __libseh_get_exception_information()     (LPEXCEPTION_POINTERS)0

#endif

#if !defined(LIBSEH_USE_COMPILER_SEH_IMPL)
#define GetExceptionCode()                       __libseh_get_exception_code()
#define GetExceptionInformation()                __libseh_get_exception_information()
#endif

/* 
 * Below are the standard bindings for LibSEH __try, __except, and __finally blocks.
 * Using the names __try, __except, __finally, and __leave is not recommended as
 * some standard libraries (libstdc++) use these names in header files.
 *
 * One may reconfigure these to one's liking or add another set of definitions that 
 * map to the __seh_* macros.
 */

#if !defined(LIBSEH_PREFIX_MACROS_ONLY)

#define __seh_try                                __libseh_try
#define __seh_except(x)                          __libseh_except(x)
#define __seh_finally                            __libseh_finally
#define __seh_leave                              __libseh_leave
#define __seh_end_except                         __libseh_end_except
#define __seh_end_finally                        __libseh_end_finally

#endif


/* Processor detection */
#if defined(_X86_) && !defined(__x86_64__)
#define LIBSEH_ARCH_X86
#define LIBSEH_ARCH "x86"
#endif

/* Does this compiler support __builtin_unreachable()? */
#if defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#define __LIBSEH_UNREACHABLE() __builtin_unreachable()
#endif
#endif

/* If not, use an infinite loop */
#if !defined(__LIBSEH_UNREACHABLE)
#define __LIBSEH_UNREACHABLE() while(1)
#endif

#endif /* __LIBSEH_CONFIG_H__ */

