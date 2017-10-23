
#include "tests-common.inc"

BEGIN_SIMPLE_TEST(null_pointer_cxx)
{
  volatile int* x = 0;

  try 
  {
    libsehpp_initialize();
    int y = *x;
    TEST_FAILED("The access violation exception was not raised as expected");
  }
  catch(seh::access_violation) 
  {
    TEST_PASSED(); 
  }

  TEST_FAILED("The exception was not caught by the exception handler.");
}
END_TEST()
