LIBSEH - a Windows SEH compatibility library for GCC.
(C) 2011 Tom Bramer ( tjb at postpro dot net )

Version 0.0.4

This is alpha grade code.  But then again, it might work very well.  It seems to work 
in my limited testing so far.

About LIBSEH:
LIBSEH is a compatibility layer that allows one to utilize the Structured 
Exception Handling facility found in Windows within GCC for Windows (MINGW32, CYGWIN).  
In other compilers, SEH is built into the compiler as a language extension.  In other 
words, this syntax is not standard C or C++, where standard in this case includes any 
ANSI standard.  Usually, support for this feature is implemented through __try, __except, 
and __finally compound statements.  Here is an example:


#include <windows.h>
#include <stdio.h>

int ExceptionFilter(unsigned int code, unsigned int excToFilter)
{
    if(code == excToFilter) return EXCEPTION_EXECUTE_HANDLER;
    else return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    int x = 0;
    int y = 4;
    __try 
    {
        y /= x;
    }
    __except(ExceptionFilter(GetExceptionCode(), EXCEPTION_INT_DIVIDE_BY_ZERO)) 
    {
        printf("Divide by zero exception.\n");
    }

    return 0;
}


This is only supported in Microsoft C/C++ and Digital Mars C/C++.  They are not 
standard language constructs.

LIBSEH allows programs intended for GCC to utilize this feature, with a high degree 
of source-level compatibility and minimal existing code changes.  

#include <windows.h>
#include <stdio.h>
#include <seh.h>       /* Include the seh.h header. */

int ExceptionFilter(unsigned int code, unsigned int excToFilter)
{
    if(code == excToFilter) return EXCEPTION_EXECUTE_HANDLER;
    else return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    int x = 0;
    int y = 4;
    __seh_try                                            /* Change __try to __seh_try */
    {
        y /= x;
    }
    __seh_except(ExceptionFilter(GetExceptionCode(),     /* Change __except to __seh_except */
       EXCEPTION_INT_DIVIDE_BY_ZERO))
    {
        printf("Divide by zero exception.\n");
    }
    __seh_end_except                                     /* Additional line required */

    return 0;
}


Not very much to it, really.  The seh.h header includes other headers, and when preprocessed 
under Microsoft C/C++ and Digital Mars C/C++ (untested), the __seh_end_except is defined as a 
no-op.  It does have meaning though for GCC, and the program will not compile without it 
(and since the above are preprocessor macros, strange compiler errors will result, so keep 
this in mind when something doesn't compile).

All of this allows the same source to be compiled on GCC and Microsoft C/C++ (and most likely,
Digital Mars C/C++).

The library also supports the __seh_try/__seh_finally combination:  

int main()
{
    int x = 0;
    int y = 4;
    __seh_try 
    {
        __seh_try {
            y /= x;
        }
        __seh_finally {
            printf("Leaving __seh_try/__seh_finally compound statement.\n");
        }
        __seh_end_finally          /****** NOTE THE __seh_end_finally, also required ******/
    }
    __seh_except(ExceptionFilter(GetExceptionCode(), EXCEPTION_INT_DIVIDE_BY_ZERO)) 
    {
        printf("Divide by zero exception.\n");
    }
    __seh_end_except

    return 0;
}

The __seh_finally block will be called if an exception is raised, and the exception is handled 
in a block farther up on the stack.  It's also called if no exception occurs.  


***********************************************************************************************
KNOWN DIFFERENCES BETWEEN LIBSEH AND BUILT IN IMPLEMENTATIONS OF SEH:

Yes, it's true.  LIBSEH does not have the exact same behavior as builtin SEH in Microsoft C/C++.
Here are some of the currently known differences (and I could be incorrect, as I haven't tested
all of these):

These differences only affect when LIBSEH is really being used, like when using GCC.

* __seh_finally in LIBSEH does not handle currently C++ exceptions.  If code leaves the __seh_try block 
  other than executing through the __seh_try block (finishing execution), by leaving with __seh_leave, 
  or because of a raised SEH exception, the __seh_finally block will not be executed.  This applies to 
  all other ways of exiting the __try block, such as return and goto.

* Certain compiler optimizations can cause problems with LibSEH.  In particular, the -fomit-frame-pointer flag
  should never be specified!  Also, having the compiler store a local variable in a register will cause problems
  if such a variable is modified within an __seh_try block.  If a variable is modified within a __seh_try block 
  and that new value needs to be retained after an exception has been raised, the variable needs to be declared
  as being volatile.  For example:

  volatile HANDLE hFile = NULL;
  __seh_try {
    hFile = CreateFile(...);
    /* Do something that raises an exception */
  }
  __seh_finally {
    /* Without the volatile modifier, hFile could still be NULL here,
       even if the exception is raised after the CreateFile call and even if
       that call does not return NULL. */
    if(hFile) {
      CloseHandle(hFile);
    }
  }
  __seh_end_finally

  It's probably best to avoid this situation by not putting code within such a block that would not be expected to
  raise an exception, if the code itself does not have issues.  

  

KEEP THESE IN MIND WHEN WRITING CODE THAT MAY BE BUILT WITH GCC AND A COMPILER WITH NATIVE SEH SUPPORT.

***********************************************************************************************      
BUILDING LibSEH:

For MinGW:

1.) Review the file Makefile.mingw32 to make sure your toolchain's development tool executables match the names 
in the Makefile (for CC, CXX, AS, and AR).  Most likely, no changes will need to be made.  

2.) With the environment set correctly to access your development tools as specified in the Makefile, run make 
(or mingw32-make) in the LibSEH root directory like so:
c:\path\to\libseh> make

3.) Optionally, build the tests in the tests directory:
c:\path\to\libseh\tests> make

For MSVC:

There are no steps for MSVC unless the C++ interface is being used.

To build the C++ interface:

1.) Review the file Makefile to make sure your toolchain's development tool executables match the names in the
Makefile.  The names will most likely match.

2.) With the environment set correctly to access your development tools as specified in the Makefile, run nmake
as follows:
c:\path\to\libseh> nmake

3.) Optionally, build the tests in the tests directory.  Note that not all of the tests are compatible with MSVC.
c:\path\to\libseh\tests> nmake


***********************************************************************************************      
USING LibSEH:

Your development system needs to be configured such that the LibSEH root directory is searched
for header files.  Optionally, you can specify the full relative or absolute path in your source
files, but this is not recommended.

MinGW programs should be linked against libseh.a that is created in the build subdirectory when
building the library.  MSVC programs using the C++ interface should be linked against the libseh.lib
file in the build subdirectory.

There are a couple of examples in the examples subdirectory that demonstrate usage.  Hopefully more
will come at a later time.

