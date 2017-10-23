
#include "tests-common.inc"

void 
subtest_checker(DWORD code, DWORD filtercode, volatile void* reqaddr, LPEXCEPTION_POINTERS exc_info)
{
  bool raise_exc = false;

  if(code != filtercode)
  {
    TEST_TRACE2("code != filtercode!  code = 0x%08lx, filtercode = 0x%08lx\n", 
                code, filtercode);
    raise_exc = true;
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
        raise_exc = true;
      }
      else if(!exc_info->ExceptionRecord->ExceptionAddress)
      {
        TEST_TRACE0("exc_info->ExceptionRecord->ExceptionAddress is NULL!");
        raise_exc = true;
      }
      else if(!reqaddr)
      {
        TEST_TRACE0("reqaddr is NULL!");
        raise_exc = true;
      }
    }
    else
    {
      TEST_TRACE0("exc_info->ExceptionRecord is NULL!");
      raise_exc = true;
    }
  }
  else
  {
    TEST_TRACE0("exc_info is NULL!");
    raise_exc = true;
  }

  if(raise_exc)
      RaiseException(0xCFFFFFFF, 0, 0, 0);

  return;

}


extern "C" void __stdcall 
CallRtlRaiseException(volatile void** exp_ret_addr_out, 
                      PEXCEPTION_RECORD exc_record);


__asm__ __volatile__
(
"                                              \n\
ntdllstr: .asciz \"ntdll.dll\"                 \n\
rtlrestr: .asciz \"RtlRaiseException\"         \n\
.func CallRtlRaiseException;                   \n\
.global _CallRtlRaiseException@8;              \n\
_CallRtlRaiseException@8:                      \n\
   pushl %ebp;                                 \n\
   movl %esp, %ebp;                            \n\
   pushl $ntdllstr;                            \n\
   call _GetModuleHandleA@4;                   \n\
   pushl $rtlrestr;                            \n\
   pushl %eax;                                 \n\
   call _GetProcAddress@8;                     \n\
   pushl %eax;                                 \n\
   movl 4(%ebp), %edx;                         \n\
   movl 8(%ebp), %eax;                         \n\
   movl %edx, (%eax);                          \n\
   popl %eax;                                  \n\
   movl 4(%ebp), %edx;                         \n\
   movl %edx, 8(%ebp);                         \n\
   popl %ebp;                                  \n\
   addl $4, %esp;                              \n\
   jmp *%eax;                                  \n\
");


#define IMPLEMENT_SEH_SUBTEST(test_prefix, exception_code)              \
int test_prefix ## _test()                                              \
{                                                                       \
  volatile int ret = 0;                                                 \
  volatile void* addr = 0;                                              \
  EXCEPTION_RECORD exc_record;                                          \
  try {                                                                 \
    memset(&exc_record, 0, sizeof(exc_record));                         \
    try {                                                               \
      exc_record.ExceptionCode = (exception_code);                      \
      CallRtlRaiseException(&addr, &exc_record);                        \
    }                                                                   \
    catch(seh::test_prefix& ex) {                                       \
      EXCEPTION_POINTERS exc_info;                                      \
      exc_info.ExceptionRecord = ex.record();                           \
      exc_info.ContextRecord = ex.context();                            \
      subtest_checker(ex.record()->ExceptionCode, (exception_code),     \
                      addr, &exc_info);                                 \
      ret = 1;                                                          \
    }                                                                   \
  }                                                                     \
  catch(seh::exception)                                                 \
  {                                                                     \
    ret = 0;                                                            \
  }                                                                     \
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


BEGIN_SIMPLE_TEST(sehpp_tests_2)
{
  libsehpp_initialize();
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


