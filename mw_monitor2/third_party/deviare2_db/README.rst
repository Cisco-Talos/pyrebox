How to generate sqlite database from deviare2
=============================================

First, clone https://github.com/nektra/deviare2

Second, go to source code, open the visual studio solution. In order to make it 
compile with visual studio express, you will need to replace the afxres.h 
dependency (MFC) on DbGenerator.rc.
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


Finally, compile the DbGenerator project, and then under the directory 
Database/DbBuilder/ run build_db32, or build_db64. It will take some time, be patient.

This database lacks information about which parameters are input and output 
parameters, but (at least part of) this information can be obtained from the 
MSDN documentation. Zynamics has a script (that we have modified) in order to 
extract this information from the MSDN into an xml file. Then, another script 
(populate_db.py) can be used to parse this xml and populate the database with 
the missing information, extracted from the xml.
