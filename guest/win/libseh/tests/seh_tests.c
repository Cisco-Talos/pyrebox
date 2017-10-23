
#include "tests-common.inc"

DWORD 
subtest_filter(DWORD code, DWORD filtercode, PVOID reqaddr, LPEXCEPTION_POINTERS exc_info)
{
  DWORD ret_val = EXCEPTION_EXECUTE_HANDLER;

  if(code != filtercode)
  {
    TEST_TRACE2("code != filtercode!  code = 0x%08lx, filtercode = 0x%08lx\n", 
                code, filtercode);
    ret_val = EXCEPTION_CONTINUE_SEARCH;
  }

  if(exc_info)
  {
    if(exc_info->ExceptionRecord)
    {
      if(exc_info->ExceptionRecord->ExceptionAddress != reqaddr)
      {
        TEST_TRACE2("reqaddr != exc_info->ExceptionRecord->ExceptionAddress!  "
                    "reqaddr = 0x%p, exc_info->... = 0x%p\n", 
                    reqaddr, exc_info->ExceptionRecord->ExceptionAddress);
        ret_val = EXCEPTION_CONTINUE_SEARCH;
      }
      else if(!exc_info->ExceptionRecord->ExceptionAddress)
      {
        TEST_TRACE0("exc_info->ExceptionRecord->ExceptionAddress is NULL!");
        ret_val = EXCEPTION_CONTINUE_SEARCH;
      }
      else if(!reqaddr)
      {
        TEST_TRACE0("reqaddr is NULL!");
        ret_val = EXCEPTION_CONTINUE_SEARCH;
      }
    }
    else
    {
      TEST_TRACE0("exc_info->ExceptionRecord is NULL!");
      ret_val = EXCEPTION_CONTINUE_SEARCH;
    }
  }
  else
  {
    TEST_TRACE0("exc_info is NULL!");
    ret_val = EXCEPTION_CONTINUE_SEARCH;
  }

  return ret_val;
}


#define IMPLEMENT_SEH_SUBTEST(test_prefix, exception_code)              \
int test_prefix ## _test()                                              \
{                                                                       \
  volatile int ret = 0;                                                 \
  volatile PVOID addr = 0;                                              \
  typedef void NTAPI (*RREFunc)(PEXCEPTION_RECORD);                     \
  RREFunc rtl_raise_exception_fp =                                      \
    (RREFunc)GetProcAddress(GetModuleHandle("ntdll.dll"),               \
                            "RtlRaiseException");                       \
  EXCEPTION_RECORD exc_record;                                          \
  __libseh_try {                                                        \
    memset(&exc_record, 0, sizeof(exc_record));                         \
    __libseh_try {                                                      \
      exc_record.ExceptionCode = (exception_code);                      \
      __asm__ __volatile__("   movl   $1f, %[addr];\n"                  \
                           "   pushl  %[exc_record];\n"                 \
                           "   call   *%[func_ptr];\n"                  \
                           "   1:\n"                                    \
                           : [addr] "=g" (addr)                         \
                           : [exc_record] "g" (&exc_record),            \
                             [func_ptr] "a" (rtl_raise_exception_fp)    \
                           : "esp", "memory");                          \
    }                                                                   \
    __libseh_except(                                                    \
      subtest_filter(__libseh_get_exception_code(),                     \
                     (exception_code),                                  \
                     addr,                                              \
                     __libseh_get_exception_information())) {           \
      ret = 1;                                                          \
    }                                                                   \
    __libseh_end_except                                                 \
  }                                                                     \
  __libseh_except(EXCEPTION_EXECUTE_HANDLER)                            \
  {                                                                     \
  }                                                                     \
  __libseh_end_except                                                   \
                                                                        \
  return ret;                                                           \
}


IMPLEMENT_SEH_SUBTEST(access_violation, EXCEPTION_ACCESS_VIOLATION)
IMPLEMENT_SEH_SUBTEST(datatype_misalignment, EXCEPTION_DATATYPE_MISALIGNMENT)
IMPLEMENT_SEH_SUBTEST(array_bounds_exceeded, EXCEPTION_ARRAY_BOUNDS_EXCEEDED)
IMPLEMENT_SEH_SUBTEST(flt_denormal_operand, EXCEPTION_FLT_DENORMAL_OPERAND)
IMPLEMENT_SEH_SUBTEST(flt_divide_by_zero, EXCEPTION_FLT_DIVIDE_BY_ZERO)
IMPLEMENT_SEH_SUBTEST(flt_inexact_result, EXCEPTION_FLT_INEXACT_RESULT)
IMPLEMENT_SEH_SUBTEST(flt_invalid_operation, EXCEPTION_FLT_INVALID_OPERATION)
IMPLEMENT_SEH_SUBTEST(flt_overflow, EXCEPTION_FLT_OVERFLOW)
IMPLEMENT_SEH_SUBTEST(flt_stack_check, EXCEPTION_FLT_STACK_CHECK)
IMPLEMENT_SEH_SUBTEST(flt_underflow, EXCEPTION_FLT_UNDERFLOW)
IMPLEMENT_SEH_SUBTEST(int_divide_by_zero, EXCEPTION_INT_DIVIDE_BY_ZERO)
IMPLEMENT_SEH_SUBTEST(int_overflow, EXCEPTION_INT_OVERFLOW)
IMPLEMENT_SEH_SUBTEST(priv_instruction, EXCEPTION_PRIV_INSTRUCTION)
IMPLEMENT_SEH_SUBTEST(in_page_error, EXCEPTION_IN_PAGE_ERROR)
IMPLEMENT_SEH_SUBTEST(illegal_instruction, EXCEPTION_ILLEGAL_INSTRUCTION)
IMPLEMENT_SEH_SUBTEST(noncontinuable_exception, EXCEPTION_NONCONTINUABLE_EXCEPTION)
IMPLEMENT_SEH_SUBTEST(stack_overflow, EXCEPTION_STACK_OVERFLOW)
IMPLEMENT_SEH_SUBTEST(invalid_disposition, EXCEPTION_INVALID_DISPOSITION)
IMPLEMENT_SEH_SUBTEST(guard_page, EXCEPTION_GUARD_PAGE)
IMPLEMENT_SEH_SUBTEST(invalid_handle, EXCEPTION_INVALID_HANDLE)
IMPLEMENT_SEH_SUBTEST(ctrl_c_break, CONTROL_C_EXIT)

#undef IMPLEMENT_SEH_SUBTEST

#define DO_SEH_SUBTEST(test_prefix)                                                 \
  TEST_VERIFY(test_prefix ## _test(), "Subtest " #test_prefix "_test failed.");     \
  TEST_TRACE0("Subtest " #test_prefix "_test passed.\n")


BEGIN_SIMPLE_TEST(seh_tests)
{
  DO_SEH_SUBTEST(access_violation);
  DO_SEH_SUBTEST(datatype_misalignment);
  DO_SEH_SUBTEST(array_bounds_exceeded);
  DO_SEH_SUBTEST(flt_denormal_operand);
  DO_SEH_SUBTEST(flt_divide_by_zero);
  DO_SEH_SUBTEST(flt_inexact_result);
  DO_SEH_SUBTEST(flt_invalid_operation);
  DO_SEH_SUBTEST(flt_overflow);
  DO_SEH_SUBTEST(flt_stack_check);
  DO_SEH_SUBTEST(flt_underflow);
  DO_SEH_SUBTEST(int_divide_by_zero);
  DO_SEH_SUBTEST(int_overflow);
  DO_SEH_SUBTEST(priv_instruction);
  DO_SEH_SUBTEST(in_page_error);
  DO_SEH_SUBTEST(illegal_instruction);
  DO_SEH_SUBTEST(noncontinuable_exception);
  DO_SEH_SUBTEST(stack_overflow);
  DO_SEH_SUBTEST(invalid_disposition);
  DO_SEH_SUBTEST(guard_page);
  DO_SEH_SUBTEST(invalid_handle);
  DO_SEH_SUBTEST(ctrl_c_break);
  TEST_PASSED();
}
END_TEST()

#undef DO_SEH_SUBTEST

