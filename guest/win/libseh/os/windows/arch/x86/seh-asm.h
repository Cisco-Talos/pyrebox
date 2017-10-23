/*******************************************************************************
 *                                                                             *
 * seh-asm.h - Inline assembly portions of seh-support.h.                      *
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

#ifndef __LIBSEH_WINDOWS_ARCH_X86_SEHASM_H__
#define __LIBSEH_WINDOWS_ARCH_X86_SEHASM_H__

#include "../../../../common/config.h"

#define __LIBSEH_BLK_FILTER(exclabel, expr)       \
exclabel ## _filter_lbl:                          \
  __asm__ __volatile__ (                          \
    "popl %%ebp;\n"                               \
    "movl 0(%%ecx),  %%esi;\n"                    \
    "movl 4(%%ecx),  %%edi;\n"                    \
    "movl 8(%%ecx),  %%ebx;\n"                    \
    "movl 12(%%ecx), %%edx;\n"                    \
    "movl 20(%%ecx), %%esp;\n"                    \
    "movl 16(%%ecx), %%ebp;\n"                    \
    "jmp *%%edx;\n"                               \
    :                                             \
    : "a" ((expr)),                               \
      "c" (&(exclabel ## _rg.ret_context))        \
    );                                            \
    __LIBSEH_UNREACHABLE();

#define __LIBSEH_COMPILER_FENCE()                 \
    __asm__ __volatile__( "" : : : "memory")

#endif /* __LIBSEH_WINDOWS_ARCH_X86_SEHASM_H__ */

