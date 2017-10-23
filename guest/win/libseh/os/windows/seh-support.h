
/*******************************************************************************
 *                                                                             *
 * seh-support.h - Macros used to implement SEH-like constructs in GNU C/C++   *
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

#ifndef __LIBSEH_WINDOWS_SEHSUPPORT_H__
#define __LIBSEH_WINDOWS_SEHSUPPORT_H__

#include "../../common/config.h"

#ifdef __cplusplus
#define DECLLANG extern "C"
#else
#define DECLLANG
#endif

#define SEH_MAGIC_NUMBER 0xDEADBEEF

#if defined(LIBSEH_USE_COMPILER_SEH_IMPL) || defined(LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL)

#include <windows.h>
#include <excpt.h>

#endif

#ifdef LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL

#include <winnt.h>

#if defined(LIBSEH_ARCH_X86)
#include "arch/x86/seh-asm.h"
#endif

/* Code using libseh should never be compiled using -fomit-frame-pointer */
#if defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
#pragma GCC optimize ("no-omit-frame-pointer")
#endif
#endif

#define FLAG_IS_SET(bf, flag)   !!((bf) & (flag))
#define FLAG_SET(bf, flag)      (bf) |= (flag)
#define FLAG_CLR(bf, flag)      (bf) &= ~(flag)

#define FLAG(x)                 1 << (x)

#define FLAG_FINALLY_BLOCK      FLAG(0)
#define FLAG_CONST_FILTER_EXPR  FLAG(1)
#define FLAG_FINAL_BLOCK_CALL   FLAG(2)

#ifndef EXCEPTION_UNWINDING
#define EXCEPTION_UNWINDING     0x02
#endif

#ifndef EXCEPTION_EXIT_UNWIND
#define EXCEPTION_EXIT_UNWIND   0x04
#endif

/* In newer variants of the MinGW Windows headers, this is defined in winnt.h. */
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((DWORD)0xC000000DL)
#endif


typedef unsigned long __libseh_jmp_ctx[6];

struct ___libseh_buf;
struct ___libseh_fe_buf;

typedef int (*_PEXCEPTION_HANDLER)
            (struct _EXCEPTION_RECORD*, struct ___libseh_buf*, struct _CONTEXT*, struct _EXCEPTION_RECORD*);

typedef int (*_PFE_EXCEPTION_HANDLER)
            (struct _EXCEPTION_RECORD*, struct ___libseh_fe_buf*, struct _CONTEXT*, struct _EXCEPTION_RECORD*);

typedef LONG WINAPI (*_PUEH_FILTER)(struct _EXCEPTION_POINTERS* exc_info);


typedef struct ___libseh_info {
  EXCEPTION_RECORD record;
  CONTEXT context;
  EXCEPTION_RECORD record2;
  EXCEPTION_POINTERS pointers;
} __libseh_info;

typedef struct ___libseh_buf {
  struct ___libseh_buf* prev;
  _PEXCEPTION_HANDLER handler;
  unsigned int magic;
  __libseh_jmp_ctx context;
  __libseh_jmp_ctx ret_context;
  unsigned int flags;
  int const_filter_value;
  __libseh_info* excinfo;

} __libseh_buf;

typedef struct ___libseh_fe_buf {
  struct ___libseh_buf* prev;
  _PFE_EXCEPTION_HANDLER handler;
  struct ___libseh_buf* real_prev;
  _PUEH_FILTER prev_ueh_filter;
} __libseh_fe_buf;

/* External prototypes */
DECLLANG int __attribute__((returns_twice)) __stdcall __libseh_register(volatile __libseh_buf* buf);
DECLLANG void __stdcall __libseh_unregister(volatile __libseh_buf* buf);
DECLLANG void __stdcall __libseh_end_finally_blk(volatile __libseh_buf* buf);
DECLLANG __libseh_buf* __stdcall __libseh_get_registration();
DECLLANG void __stdcall __libseh_set_registration(volatile __libseh_buf* reg);
DECLLANG __libseh_buf* __stdcall __libseh_pop_registration();

DECLLANG void __libseh_init_buf(__libseh_buf* buf);
DECLLANG void __libseh_fini_buf(__libseh_buf* buf);

DECLLANG void __attribute__((noreturn)) 
__libseh_raise_fatal_exception(DWORD exc_code, DWORD exc_flags, DWORD num_arguments, const ULONG_PTR* arguments);

#define __LIBSEH_GET_EXCEPTION_CODE_LBL(exclabel)         (exclabel ## _rg.excinfo->record.ExceptionCode)
#define __LIBSEH_GET_EXCEPTION_INFORMATION_LBL(exclabel)  (&(exclabel ## _rg.excinfo->pointers))


#define __LIBSEH_BLK_BEGIN_TRY(exclabel)                      \
  __label__ exclabel ## _finally_lbl;                         \
  __label__ exclabel ## _register_lbl;                        \
  __label__ exclabel ## _try_lbl;                             \
  __label__ exclabel ## _end_try_lbl;                         \
  volatile __libseh_buf exclabel ## _rg;                      \
  if(0) goto exclabel ## _end_try_lbl;                        \
                                                              \
  goto exclabel ## _register_lbl;                             \
                                                              \
exclabel ## _try_lbl:                                         \
  __LIBSEH_COMPILER_FENCE();                                  \
  do 

#define __LIBSEH_BLK_END_TRY(exclabel)                        \
  while(0);                                                   \
exclabel ## _end_try_lbl:                                     \
  __LIBSEH_COMPILER_FENCE();                                  \
  FLAG_SET(exclabel ## _rg.flags, FLAG_FINAL_BLOCK_CALL);     \
  goto exclabel ## _finally_lbl

#define __LIBSEH_BLK_BEGIN_EXCEPT(exclabel, expr)             \
exclabel ## _register_lbl:                                    \
  exclabel ## _rg.flags = 0;                                  \
                                                              \
  if(__builtin_constant_p((expr)))                            \
  {                                                           \
    FLAG_SET(exclabel ## _rg.flags, FLAG_CONST_FILTER_EXPR);  \
    exclabel ## _rg.const_filter_value = (expr);              \
  }                                                           \
                                                              \
  {                                                           \
    __label__ exclabel ## _filter_lbl;                        \
    __label__ exclabel ## _except_lbl;                        \
                                                              \
    switch(__libseh_register(&(exclabel ## _rg)))             \
    {                                                         \
      case 0: goto exclabel ## _try_lbl;                      \
      case 1: goto exclabel ## _filter_lbl;                   \
      case 2: goto exclabel ## _except_lbl;                   \
    }                                                         \
                                                              \
    __libseh_raise_fatal_exception(                           \
      STATUS_INVALID_PARAMETER,                               \
      EXCEPTION_NONCONTINUABLE,                               \
      0,                                                      \
      NULL);                                                  \
                                                              \
    __LIBSEH_BLK_FILTER(exclabel, expr);                      \
exclabel ## _except_lbl:


#define __LIBSEH_BLK_END_EXCEPT(exclabel)                     \
  }                                                           \
exclabel ## _finally_lbl:                                     \
  __libseh_unregister(&(exclabel ## _rg));


#define __LIBSEH_BLK_BEGIN_FINALLY(exclabel)                  \
exclabel ## _register_lbl:                                    \
  exclabel ## _rg.flags = 0;                                  \
  FLAG_SET(exclabel ## _rg.flags, FLAG_FINALLY_BLOCK);        \
                                                              \
  switch(__libseh_register(&(exclabel ## _rg)))               \
  {                                                           \
    case 0: goto exclabel ## _try_lbl;                        \
    case 3: goto exclabel ## _finally_lbl;                    \
  }                                                           \
                                                              \
  __libseh_raise_fatal_exception(                             \
    STATUS_INVALID_PARAMETER,                                 \
    EXCEPTION_NONCONTINUABLE,                                 \
    0,                                                        \
    NULL);                                                    \
                                                              \
exclabel ## _finally_lbl:

#define __LIBSEH_BLK_END_FINALLY(exclabel)                    \
  __libseh_end_finally_blk(&(exclabel ## _rg)); 

#define __LIBSEH_BLK_LEAVE(exclabel)                          \
  goto exclabel ## _end_try_lbl;


#define __LIBSEH_TRY                                          \
do {                                                          \
   __LIBSEH_BLK_BEGIN_TRY(__libseh)

#define __LIBSEH_FINALLY                                      \
   __LIBSEH_BLK_END_TRY(__libseh);                            \
   __LIBSEH_BLK_BEGIN_FINALLY(__libseh) 

#define __LIBSEH_END_FINALLY                                  \
   __LIBSEH_BLK_END_FINALLY(__libseh);                        \
} while(0);

#define __LIBSEH_EXCEPT(filterexpr)                           \
   __LIBSEH_BLK_END_TRY(__libseh);                            \
   __LIBSEH_BLK_BEGIN_EXCEPT(__libseh, filterexpr)

#define __LIBSEH_END_EXCEPT                                   \
   __LIBSEH_BLK_END_EXCEPT(__libseh);                         \
} while(0);

#define __LIBSEH_LEAVE __LIBSEH_BLK_LEAVE(__libseh)

#define __LIBSEH_GET_EXCEPTION_CODE() __LIBSEH_GET_EXCEPTION_CODE_LBL(__libseh)
#define __LIBSEH_GET_EXCEPTION_INFORMATION() __LIBSEH_GET_EXCEPTION_INFORMATION_LBL(__libseh)

#endif /* LIBSEH_USE_LIBSEH_WIN32_SEH_IMPL */

#endif /* __LIBSEH_WINDOWS_SEHSUPPORT_H__ */

