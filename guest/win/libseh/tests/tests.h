/*******************************************************************************
 *                                                                             *
 * tests.h - Very basic testing framework.                                     *
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

#ifndef __LIBSEH_TESTS_H__
#define __LIBSEH_TESTS_H__

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_TRACE0(msg) fprintf(stdout, msg)
#define TEST_TRACE1(msg, arg0) fprintf(stdout, msg, arg0)
#define TEST_TRACE2(msg, arg0, arg1) fprintf(stdout, msg, arg0, arg1)

#define REPORT_FAILURE(msg, line, func)  fprintf(stderr, "Test failed (line %d, test %s): %s\n", line, func, msg)
#define REPORT_FAILURE2(msg, line, func, arg0, arg1)  fprintf(stderr, "Test failed (line %d, test %s): " msg "\n", line, func, arg0, arg1)

#define IMPLEMENT_SIMPLE_RUNNER(testname)               \
    int testname(int token);                            \
    int main(int argc, char** argv)                     \
    {                                                   \
        int tok = rand();                               \
        int testresult = testname(tok);                 \
        if(testresult == ~tok) {                        \
            printf("Test " #testname " passed.\n");     \
            return 0;                                   \
        }                                               \
        else                                            \
        printf("Test " #testname " failed.\n");         \
        return 1;                                       \
    }                                                   \

#define BEGIN_SIMPLE_TEST(testname)      \
    IMPLEMENT_SIMPLE_RUNNER(testname)    \
    int testname(int token)              \
    {                                    \
       int rc = 0;                       \
       int testname ## _ons = 1;         \
       while(testname ## _ons--)         \
	 
	 
#define END_TEST()                       \
       return rc;                        \
    }


#define TEST_PASSED()                    \
       rc = ~token;                      \
       return rc;

#if defined(_MSC_VER) && _MSC_VER < 1300

#define TEST_FAILED(reason)                    \
       REPORT_FAILURE(reason, __LINE__, "");   \
       exit(1)

#define TEST_FAILED2(fmtstr, arg0, arg1)                   \
       REPORT_FAILURE2(fmtstr, __LINE__, "", arg0, arg1);  \
       exit(1)

#else

#define TEST_FAILED(reason)                              \
       REPORT_FAILURE(reason, __LINE__, __FUNCTION__);   \
       exit(1)

#define TEST_FAILED2(fmtstr, arg0, arg1)                             \
       REPORT_FAILURE2(fmtstr, __LINE__, __FUNCTION__, arg0, arg1);  \
       exit(1)

#endif

#define TEST_VERIFY(expr, failreason)           \
       if(!(expr)) { TEST_FAILED(failreason); } 
	 
#define TEST_VERIFY_INTEGER(expr, expected)                                                                     \
     { int expr_val = (expr), exp_val = (expected);                                                             \
       if((expr) != (expected))                                                                                 \
       { TEST_FAILED2("incorrect integer value %d for " #expr ".  Expected value is %d.", expr_val, exp_val); } \
       else { TEST_TRACE1("Correct integer value of %d for " #expr ".\n", expr_val); } }

#ifdef __cplusplus
}
#endif

#endif
