How to generate sqlite database from deviare2
=============================================

Before generating a database, please be aware that there are
precompiled 32 and 64 bit databases available in this repository.
This generation process depends on an external project (Deviare2),
and is not supported by the PyREBox development team.

First, clone https://github.com/nektra/deviare2

Second, go to source code, open the visual studio solution. In order to make it 
compile with Visual Studio Community, you will need to replace the afxres.h 
dependency (MFC) on DbGenerator.rc, and other source files it you find any related
error during compialation.
::
    diff --git a/Source/Database/Generator/DbGenerator.rc b/Source/Database/Generator/DbGenerator.rc
    index ee77252..a8e4eab 100644
    --- a/Source/Database/Generator/DbGenerator.rc
    +++ b/Source/Database/Generator/DbGenerator.rc
    @@ -7,7 +7,7 @@
     //
     // Generated from the TEXTINCLUDE 2 resource.
     //
    -#include "afxres.h"
    +#include "windows.h"
     #include "..\..\version.ver"
     
     /////////////////////////////////////////////////////////////////////////////
    @@ -35,7 +35,7 @@ END
     
     2 TEXTINCLUDE 
     BEGIN
    -    "#include ""afxres.h""\r\n"
    +    "#include ""windows.h""\r\n"
         "#include ""..\\..\\version.ver""\r\n"
         "\0"
     END


Third, patch the DbGenerator.cpp to make it generate the sqlite database in a file instead of memory.
::
    diff --git a/Source/Database/Generator/DbGenerator.cpp b/Source/Database/Generator/DbGenerator.cpp
    old mode 100644
    new mode 100755
    index 7bfaa91..8199381
    --- a/Source/Database/Generator/DbGenerator.cpp
    +++ b/Source/Database/Generator/DbGenerator.cpp
    @@ -38,7 +38,7 @@
     #ifdef _DEBUG
       //#define DO_NOT_CREATE_SQLITE_FILE
     #else //_DEBUG
    -  #define DO_NOT_CREATE_SQLITE_FILE
    +  //#define DO_NOT_CREATE_SQLITE_FILE
     #endif //_DEBUG
     
     //-----------------------------------------------------------


Finally, compile the DbGenerator, DbMerge, and HeaderFix projects. For this, 
you may need to compile support libraries (SqLiteLib, Lz4Lib), and to retarget
the solution if you are using the Windows 10 SDK.

Generate the headers used to generate the database. Under Deviare2/Database/HeaderBuilder
::
build32.bat Full
build64.bat Full

This may produce some errors for missing header files. Edit Deviare2/Database/HeaderBuilder/Full/headers.h
to remove or comment the lines causing errors.

Build the database, on Deviare2/Database/DbBuilder/ run
::
build_db32.bat
build_db64.bat 

It will take some time, be patient. This might as well produce syntax errors, introduced during the header
generation. Fix them one by one, manually.



This database lacks information about which parameters are input and output 
parameters, but (at least part of) this information can be obtained from the 
MSDN documentation. Zynamics has a script (that we have modified) in order to 
extract this information from the MSDN into an xml file. Then, another script 
(populate_db.py) can be used to parse this xml and populate the database with 
the missing information, extracted from the xml.
