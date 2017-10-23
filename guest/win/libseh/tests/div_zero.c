
#include "tests-common.inc"

BEGIN_SIMPLE_TEST(divzero)
{
  int x = 0;

  __libseh_try {
    volatile int y = 4 / x;
    TEST_FAILED("The exception was not caught by the exception handler.");
  }
  __libseh_except(exc_filter(__libseh_get_exception_code(), EXCEPTION_INT_DIVIDE_BY_ZERO))
  {
    TEST_PASSED(); 
  }
  __libseh_end_except

}
END_TEST()

