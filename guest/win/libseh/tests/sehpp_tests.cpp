
#include "tests-common.inc"

#define IMPLEMENT_SEHPP_SUBTEST(exception_class, exception_code)                \
bool exception_class ## _test()                                                 \
{                                                                               \
  try {                                                                         \
    RaiseException((exception_code), 0, 0, 0);                                  \
  }                                                                             \
  catch(seh::exception_class) {                                                 \
    return true;                                                                \
  }                                                                             \
                                                                                \
  return false;                                                                 \
}


IMPLEMENT_SEHPP_SUBTEST(access_violation, EXCEPTION_ACCESS_VIOLATION)
IMPLEMENT_SEHPP_SUBTEST(datatype_misalignment, EXCEPTION_DATATYPE_MISALIGNMENT)
IMPLEMENT_SEHPP_SUBTEST(array_bounds_exceeded, EXCEPTION_ARRAY_BOUNDS_EXCEEDED)
IMPLEMENT_SEHPP_SUBTEST(flt_denormal_operand, EXCEPTION_FLT_DENORMAL_OPERAND)
IMPLEMENT_SEHPP_SUBTEST(flt_divide_by_zero, EXCEPTION_FLT_DIVIDE_BY_ZERO)
IMPLEMENT_SEHPP_SUBTEST(flt_inexact_result, EXCEPTION_FLT_INEXACT_RESULT)
IMPLEMENT_SEHPP_SUBTEST(flt_invalid_operation, EXCEPTION_FLT_INVALID_OPERATION)
IMPLEMENT_SEHPP_SUBTEST(flt_overflow, EXCEPTION_FLT_OVERFLOW)
IMPLEMENT_SEHPP_SUBTEST(flt_stack_check, EXCEPTION_FLT_STACK_CHECK)
IMPLEMENT_SEHPP_SUBTEST(flt_underflow, EXCEPTION_FLT_UNDERFLOW)
IMPLEMENT_SEHPP_SUBTEST(int_divide_by_zero, EXCEPTION_INT_DIVIDE_BY_ZERO)
IMPLEMENT_SEHPP_SUBTEST(int_overflow, EXCEPTION_INT_OVERFLOW)
IMPLEMENT_SEHPP_SUBTEST(priv_instruction, EXCEPTION_PRIV_INSTRUCTION)
IMPLEMENT_SEHPP_SUBTEST(in_page_error, EXCEPTION_IN_PAGE_ERROR)
IMPLEMENT_SEHPP_SUBTEST(illegal_instruction, EXCEPTION_ILLEGAL_INSTRUCTION)
IMPLEMENT_SEHPP_SUBTEST(noncontinuable_exception, EXCEPTION_NONCONTINUABLE_EXCEPTION)
IMPLEMENT_SEHPP_SUBTEST(stack_overflow, EXCEPTION_STACK_OVERFLOW)
IMPLEMENT_SEHPP_SUBTEST(invalid_disposition, EXCEPTION_INVALID_DISPOSITION)
IMPLEMENT_SEHPP_SUBTEST(guard_page, EXCEPTION_GUARD_PAGE)
IMPLEMENT_SEHPP_SUBTEST(invalid_handle, EXCEPTION_INVALID_HANDLE)
IMPLEMENT_SEHPP_SUBTEST(ctrl_c_break, CONTROL_C_EXIT)

#undef IMPLEMENT_SEHPP_SUBTEST

#define DO_SEHPP_SUBTEST(exception_class)                                               \
  TEST_VERIFY(exception_class ## _test(), "Subtest " #exception_class "_test failed."); \
  TEST_TRACE0("Subtest " #exception_class "_test passed.\n")


BEGIN_SIMPLE_TEST(sehpp_tests)
{
  libsehpp_initialize();
  DO_SEHPP_SUBTEST(access_violation);
  DO_SEHPP_SUBTEST(datatype_misalignment);
  DO_SEHPP_SUBTEST(array_bounds_exceeded);
  DO_SEHPP_SUBTEST(flt_denormal_operand);
  DO_SEHPP_SUBTEST(flt_divide_by_zero);
  DO_SEHPP_SUBTEST(flt_inexact_result);
  DO_SEHPP_SUBTEST(flt_invalid_operation);
  DO_SEHPP_SUBTEST(flt_overflow);
  DO_SEHPP_SUBTEST(flt_stack_check);
  DO_SEHPP_SUBTEST(flt_underflow);
  DO_SEHPP_SUBTEST(int_divide_by_zero);
  DO_SEHPP_SUBTEST(int_overflow);
  DO_SEHPP_SUBTEST(priv_instruction);
  DO_SEHPP_SUBTEST(in_page_error);
  DO_SEHPP_SUBTEST(illegal_instruction);
  DO_SEHPP_SUBTEST(noncontinuable_exception);
  DO_SEHPP_SUBTEST(stack_overflow);
  DO_SEHPP_SUBTEST(invalid_disposition);
  DO_SEHPP_SUBTEST(guard_page);
  DO_SEHPP_SUBTEST(invalid_handle);
  DO_SEHPP_SUBTEST(ctrl_c_break);
  TEST_PASSED();
}
END_TEST()

#undef DO_SEHPP_SUBTEST

