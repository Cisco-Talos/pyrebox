
#include "tests-common.inc"

BEGIN_SIMPLE_TEST(null_pointer)
{
  int* x = 0;

  __libseh_try {
    volatile int y = *x;
    TEST_FAILED("The access violation exception was not raised as expected");
  }
  __libseh_except(exc_filter(__libseh_get_exception_code(), EXCEPTION_ACCESS_VIOLATION))
  {
    TEST_PASSED(); 
  }
  __libseh_end_except

  TEST_FAILED("The exception was not caught by the exception handler.");
}
END_TEST()
