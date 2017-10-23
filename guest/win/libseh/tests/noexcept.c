
#include "tests-common.inc"

BEGIN_SIMPLE_TEST(noexcept)
{
  int x = 0;

  __libseh_try {
      x++;
  }
  __libseh_except(EXCEPTION_EXECUTE_HANDLER)
  {
      TEST_FAILED("Exception was caught, but no exception occurred.");
  }
  __libseh_end_except

  TEST_PASSED();
}
END_TEST()
