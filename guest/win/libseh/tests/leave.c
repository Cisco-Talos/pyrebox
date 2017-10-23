#include "tests-common.inc"

BEGIN_SIMPLE_TEST(leave_test)
{
  __libseh_try {
    __libseh_leave;
    TEST_FAILED("__libseh_leave did not exit the __libseh_try block!");
  }
  __libseh_except(EXCEPTION_EXECUTE_HANDLER) {
    TEST_FAILED("__libseh_except block should not have been called!");
  }
  __libseh_end_except

  TEST_PASSED();
}
END_TEST()

