
/*******************************************************************************
 *                                                                             *
 * seh-support.h - Macros used to implement SEH-like constructs in GNU C/C++   *
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

/*******************************************************************************
 *                                                                             *
 * STAR-BOX WARNING: (kind of like a FDA "black box" warning)                  *
 *                                                                             *
 * This is not complete.  Some of this might even be incorrect (I know some    *
 * of it is).  It might not ever be correct.  However, some might find it to   *
 * be useful.  This has actually yet to be tested under Linux.                 *
 *                                                                             *
 *******************************************************************************/

#ifndef __LIBSEH_LINUX_SEHSUPPORT_H__
#define __LIBSEH_LINUX_SEHSUPPORT_H__

#ifdef __cplusplus
#define DECLLANG extern "C"
#else
#define DECLLANG
#endif

#define SEH_MAGIC_NUMBER 0xDEADBEEF

#if defined(__linux__) || defined(__CYGWIN__)
#define HAVE_OS_SEH_SUPPORT
#endif

#if defined(__linux__)
#define __stdcall __attribute__((stdcall))
#endif

#if defined(__GNUC__) && defined(HAVE_OS_SEH_SUPPORT)
#define HAVE_SEH_WORKAROUND_SUPPORT
#endif

#if !defined(HAVE_COMPILER_SEH_SUPPORT) && !defined(HAVE_SEH_WORKAROUND_SUPPORT)
#warning This compiler and/or operating system does not support structured exception \
         handling, so SEH will be disabled.
#endif

#ifdef HAVE_SEH_WORKAROUND_SUPPORT

#include <pthread.h>
#include <signal.h>

typedef unsigned long __jmp_ctx[6];

struct ___seh_buf;

#define EXCEPTION_NONCONTINUABLE            1
#define EXCEPTION_MAXIMUM_PARAMETERS        15
#define MAXIMUM_SUPPORTED_EXTENSION         512
#define EXCEPTION_CONTINUE_SEARCH           0
#define EXCEPTION_EXECUTE_HANDLER           1

#define MAKE_EXCEPTION(sig, subcode)        ((sig) << 16) | (subcode)

/* Hopefully this is a somewhat accurate mapping of Windows NT exceptions to linux signals. */
/* I realize that it is not entire accurate as it is.                                       */
#define EXCEPTION_ACCESS_VIOLATION          MAKE_EXCEPTION(SIGSEGV, SEGV_ACCERR)
#define EXCEPTION_DATATYPE_MISALIGNMENT     MAKE_EXCEPTION(SIGBUS, BUS_ADRALN)
#define EXCEPTION_BREAKPOINT                MAKE_EXCEPTION(SIGTRAP, TRAP_BRKPT)
#define EXCEPTION_SINGLE_STEP               UNDEFINED_EXCEPTION
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     UNDEFINED_EXCEPTION
#define EXCEPTION_FLT_DENORMAL_OPERAND      MAKE_EXCEPTION(SIGILL, ILL_ILLOPN)
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        MAKE_EXCEPTION(SIGFPE, FPE_FLTDIV)
#define EXCEPTION_FLT_INEXACT_RESULT        MAKE_EXCEPTION(SIGFPE, FPE_FLTRES)
#define EXCEPTION_FLT_INVALID_OPERATION     UNDEFINED_EXCEPTION
#define EXCEPTION_FLT_OVERFLOW              MAKE_EXCEPTION(SIGFPE, FPE_FLTOVF)
#define EXCEPTION_FLT_STACK_CHECK           MAKE_EXCEPTION(SIGFPE, FPE_FLTSUB)
#define EXCEPTION_FLT_UNDERFLOW             MAKE_EXCEPTION(SIGFPE, FPE_FLTUND)
#define EXCEPTION_INT_DIVIDE_BY_ZERO        MAKE_EXCEPTION(SIGFPE, FPE_INTDIV)
#define EXCEPTION_INT_OVERFLOW              MAKE_EXCEPTION(SIGFPE, FPE_INTOVF)
#define EXCEPTION_PRIV_INSTRUCTION          MAKE_EXCEPTION(SIGILL, ILL_PRVOPC)
#define EXCEPTION_IN_PAGE_ERROR             MAKE_EXCEPTION(SIGSEGV, SEGV_MAPERR)
#define EXCEPTION_ILLEGAL_INSTRUCTION       MAKE_EXCEPTION(SIGILL, ILL_ILLOPC)
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  UNDEFINED_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW            UNDEFINED_EXCEPTION
#define EXCEPTION_INVALID_DISPOSITION       UNDEFINED_EXCEPTION
#define EXCEPTION_GUARD_PAGE                UNDEFINED_EXCEPTION
#define EXCEPTION_INVALID_HANDLE            UNDEFINED_EXCEPTION

typedef unsigned long DWORD;
typedef void*         PVOID;
typedef unsigned char BYTE;

typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];

} EXCEPTION_RECORD, *PEXCEPTION_RECORD, *LPEXCEPTION_RECORD;

typedef struct _FLOATING_SAVE_AREA {
  DWORD   ControlWord;
  DWORD   StatusWord;
  DWORD   TagWord;
  DWORD   ErrorOffset;
  DWORD   ErrorSelector;
  DWORD   DataOffset;
  DWORD   DataSelector;
  BYTE    RegisterArea[80];
  DWORD   Cr0NpxState;

} FLOATING_SAVE_AREA;


typedef struct _CONTEXT {
  DWORD ContextFlags;
  DWORD Dr0;
  DWORD Dr1;
  DWORD Dr2;
  DWORD Dr3;
  DWORD Dr6;
  DWORD Dr7;
  FLOATING_SAVE_AREA FloatSave;
  DWORD SegGs;
  DWORD SegFs;
  DWORD SegEs;
  DWORD SegDs;
  DWORD Edi;
  DWORD Esi;
  DWORD Ebx;
  DWORD Edx;
  DWORD Ecx;
  DWORD Eax;
  DWORD Ebp;
  DWORD Eip;
  DWORD SegCs;
  DWORD EFlags;
  DWORD Esp;
  DWORD SegSs;
  BYTE ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];

} CONTEXT, *PCONTEXT, *LPCONTEXT;

typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT ContextRecord;

} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS, *LPEXCEPTION_POINTERS;


typedef int (*_PEXCEPTION_HANDLER)
  (struct _EXCEPTION_RECORD*, struct ___seh_buf*, struct _CONTEXT*, struct _EXCEPTION_RECORD*);


typedef struct ___seh_info {
  EXCEPTION_RECORD record;
  CONTEXT context;
  EXCEPTION_RECORD record2;
  EXCEPTION_POINTERS pointers;
} __seh_info;

typedef struct ___seh_buf {
  struct ___seh_buf* prev;
  _PEXCEPTION_HANDLER handler;
  unsigned int magic;
  __jmp_ctx context;
  unsigned int state;
  pthread_key_t tlsindex;
  __seh_info* excinfo;

} __seh_buf;

typedef struct ___seh_thread_stack {
  struct ___seh_buf* buf;
  struct ___seh_info* info;
  int refcount;
} __seh_thread_stack;


/* External prototypes */
DECLLANG int __stdcall __seh_register(__seh_buf* buf);
DECLLANG int __stdcall __seh_restore_context(__seh_buf* buf, int ret);
DECLLANG void __stdcall __seh_unregister();
DECLLANG __seh_buf* __stdcall __seh_get_registration();
DECLLANG void __stdcall __seh_set_registration(__seh_buf* buf);
DECLLANG __seh_buf* __stdcall __seh_pop_registration();

DECLLANG void __seh_init_buf(__seh_buf* buf);
DECLLANG void __seh_fini_buf(__seh_buf* buf);

/* Utility functions */
DECLLANG int GetExceptionCode();
DECLLANG LPEXCEPTION_POINTERS GetExceptionInformation();


#define __seh_handler_install(exclabel)       \
  __label__ exclabel ## _filter;              \
  __label__ exclabel ## _cleanup;             \
  __label__ exclabel ## _finally;             \
  __label__ exclabel ## _except;              \
  __seh_buf exclabel ## _rg;                  \
  int exclabel ## _result = 0;                \
  if(__seh_register(&(exclabel ## _rg)))      \
    goto exclabel ## _filter;                 \


#define __seh_handler_uninstall(exclabel)     \
    __seh_unregister();                       \



#define __seh_handler_filter(exclabel, expr)      \
exclabel ## _filter:;                             \
  if(EXCEPTION_EXECUTE_HANDLER == (expr))         \
    exclabel ## _result = 2;                      \
  else                                            \
    exclabel ## _result = 3;                      \
  goto exclabel ## _finally;                      \



#define __seh_handler_cleanup(exclabel)           \
exclabel ## _cleanup:                             \
  __seh_handler_uninstall(exclabel)               \



#define __seh_handler_begin_except(exclabel, expr)                             \
  goto exclabel ## _finally;                                                   \
  __seh_handler_filter(exclabel, expr)                                         \
exclabel ## _finally:;                                                         \
  if(exclabel ## _result == 3) {                                               \
    exclabel ## _rg.state = 1;                                                 \
    exclabel ## _rg.handler(&(exclabel ## _rg.excinfo->record),                \
                            &(exclabel ## _rg),                                \
                            &(exclabel ## _rg.excinfo->context),               \
                            &(exclabel ## _rg.excinfo->record2));              \
  }                                                                            \
  else if(exclabel ## _result == 2) goto exclabel ## _except;                  \
  goto exclabel ## _cleanup;                                                   \
                                                                               \
exclabel ## _except:                                                           \


#define __seh_handler_end_except(exclabel)    \
  __seh_handler_cleanup(exclabel)             \


#define __seh_handler_begin_finally(exclabel)                  \
  goto exclabel ## _finally;                                   \
  __seh_handler_filter(exclabel, EXCEPTION_CONTINUE_SEARCH)    \
exclabel ## _finally:;                                         \


#define __seh_handler_end_finally(exclabel)                                    \
  if(exclabel ## _result == 3) {                                               \
    exclabel ## _rg.state = 1;                                                 \
    exclabel ## _rg.handler(&(exclabel ## _rg.excinfo->record),                \
                            &(exclabel ## _rg),                                \
                            &(exclabel ## _rg.excinfo->context),               \
                            &(exclabel ## _rg.excinfo->record2));              \
  }                                                                            \
  else if(exclabel ## _result == 2) goto exclabel ## _except;                  \
  goto exclabel ## _cleanup;                                                   \
exclabel ## _except:;                                                          \
  __seh_handler_cleanup(exclabel)                                              \

#define __seh_handler_begin_try(exclabel)             \
  __seh_handler_install(exclabel);                    \


#define __seh_handler_end_try(exclabel)               \


#define __try                                         \
do {                                                  \
   __seh_handler_begin_try(__eh_frame)

#define __finally                                     \
   __seh_handler_end_try(__eh_frame)                  \
   __seh_handler_begin_finally(__eh_frame) 

#define __end_finally                                 \
   __seh_handler_end_finally(__eh_frame)              \
} while(0);                                           \

#define __except(filterexpr)                          \
   __seh_handler_end_try(__eh_frame)                  \
   __seh_handler_begin_except(__eh_frame, filterexpr) \

#define __end_except                                  \
   __seh_handler_end_except(__eh_frame)               \
} while(0);                                           \

#else

#define __end_finally
#define __end_except

#ifndef HAVE_COMPILER_SEH_SUPPORT

#define __try if(1)
#define __finally if(1)
#define __except(filterexpr) if(0)

#endif /* HAVE_COMPILER_SEH_SUPPORT */

#endif /* HAVE_SEH_WORKAROUND_SUPPORT */

#endif /* __SEH_H__ */

