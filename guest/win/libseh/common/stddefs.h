/*******************************************************************************
 *                                                                             *
 * stddefs.h - Standard global definitions                                     *
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

#ifndef __LIBSEH_STDDEFS_H__
#define __LIBSEH_STDDEFS_H__

#ifdef __cplusplus
extern "C" {
#endif


#define TO_STR(e) #e
#define TTO_STR(e) TO_STR(e)

void die(const char* msg, const char* file, int line, const char* function, const char* expr);

#define VERIFY(expr, msg)  if(!(expr)) die((msg), __FILE__, __LINE__, __FUNCTION__, TTO_STR(expr))

#define _TRACE0(msg) printf("%s", (msg)); fflush(stdout)
#define _TRACE1(msg, arg) printf(msg, arg); fflush(stdout)
#define _TRACE2(msg, arg, arg2) printf(msg, arg, arg2); fflush(stdout)
#define _TRACE3(msg, arg, arg2, arg3) printf(msg, arg, arg2, arg3); fflush(stdout)
#define _TRACE_FORWARD() _TRACE1(">>> %s: ", __FUNCTION__)

#ifdef DEBUG
#define TRACE0(msg) _TRACE_FORWARD(); _TRACE0(msg)
#define TRACE1(msg, arg) _TRACE_FORWARD(); _TRACE1(msg, arg)
#define TRACE2(msg, arg, arg2) _TRACE_FORWARD(); _TRACE2(msg, arg, arg2)
#define TRACE3(msg, arg, arg2, arg3) _TRACE_FORWARD(); _TRACE3(msg, arg, arg2, arg3)
#define TRACE_START() TRACE0( "*** Beginning Function ***\n" )
#define TRACE_END() TRACE0( "*** Ending Function ***\n" )
#else
#define TRACE0(msg)
#define TRACE1(msg, arg)
#define TRACE2(msg, arg, arg2)
#define TRACE3(msg, arg, arg2, arg3)
#define TRACE_START()
#define TRACE_END()
#endif


#if defined(DEBUG) || defined(VERBOSE)
#define INFO0(msg) _TRACE_FORWARD(); _TRACE0(msg)
#define INFO1(msg, arg) _TRACE_FORWARD(); _TRACE1(msg, arg)
#define INFO2(msg, arg, arg2) _TRACE_FORWARD(); _TRACE2(msg, arg, arg2)
#define INFO3(msg, arg, arg2, arg3) _TRACE_FORWARD(); _TRACE3(msg, arg, arg2, arg3)
#else
#define INFO0(msg)
#define INFO1(msg, arg)
#define INFO2(msg, arg, arg2)
#define INFO3(msg, arg, arg2, arg3)
#endif


#ifdef __cplusplus
}
#endif


#endif
