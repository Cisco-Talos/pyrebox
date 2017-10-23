#include "tests-common.inc"

BEGIN_SIMPLE_TEST(leave_finally_test)
{
  volatile int ret = 0;
  __libseh_try {
    __libseh_leave;
    TEST_FAILED("__libseh_leave did not exit the __libseh_try block!");
  }
  __libseh_finally {
    ret = 1;
  }
  __libseh_end_finally

  TEST_VERIFY(ret == 1, "__libseh_finally block was not executed!");
  TEST_PASSED();
}
END_TEST()

