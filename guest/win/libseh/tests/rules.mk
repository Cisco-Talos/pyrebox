TESTS = div_zero$(EXE_EXT) null_pointer$(EXE_EXT) null_pointer_cxx$(EXE_EXT) finally$(EXE_EXT) noexcept$(EXE_EXT) \
        complex_test$(EXE_EXT) leave$(EXE_EXT) leave_finally$(EXE_EXT) several_levels$(EXE_EXT)

LIBSEH_TESTS = $(TESTS) sehpp_tests$(EXE_EXT) seh_tests$(EXE_EXT) sehpp_tests_2$(EXE_EXT)

OBJS = div_zero$(OBJ_EXT) null_pointer$(OBJ_EXT) null_pointer_cxx$(OBJ_EXT) finally$(OBJ_EXT) noexcept$(OBJ_EXT) \
       complex_test$(OBJ_EXT) leave$(OBJ_EXT) leave_finally$(OBJ_EXT) several_levels$(OBJ_EXT)

LIBSEH_OBJS = $(OBJS) sehpp_tests$(OBJ_EXT) seh_tests$(OBJ_EXT) sehpp_tests_2$(OBJ_EXT) 

div_zero$(EXE_EXT): div_zero$(OBJ_EXT) 
null_pointer$(EXE_EXT): null_pointer$(OBJ_EXT) 
null_pointer_cxx$(EXE_EXT): null_pointer_cxx$(OBJ_EXT) 
finally$(EXE_EXT): finally$(OBJ_EXT) 
noexcept$(EXE_EXT): noexcept$(OBJ_EXT) 
complex_test$(EXE_EXT): complex_test$(OBJ_EXT)
sehpp_tests$(EXE_EXT): sehpp_tests$(OBJ_EXT)
seh_tests$(EXE_EXT): seh_tests$(OBJ_EXT)
sehpp_tests_2$(EXE_EXT): sehpp_tests_2$(OBJ_EXT)
leave$(EXE_EXT): leave$(OBJ_EXT)
leave_finally$(EXE_EXT): leave_finally$(OBJ_EXT)
several_levels$(EXE_EXT): several_levels$(OBJ_EXT)

