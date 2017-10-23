#include "tests-common.inc"

int do_something(int a, int b)
{
    volatile int ret = 0;
    volatile int ret2 = 0;
    __libseh_try {
        __libseh_try {
            ret = a + (a / b);
            ret2 = 4;
            if(ret + ret2 > 20) RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, 0);
        }
        __libseh_finally {
            ret2 += -1;
        }
        __libseh_end_finally
    }
    __libseh_except(__libseh_get_exception_code() == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        ret += -10;
    }
    __libseh_end_except

    return ret + ret2;
}

int do_something_2(int a, int b, int c)
{
    volatile int ret = a + b * c;
    volatile int i, j;
    volatile int k;
    for(i = a; i < b; i++)
    {
        k = 0;
        __libseh_try {
            for(j = b; j < c; j++) {
                __libseh_try {
                    k += do_something(j, i);
                }
                __libseh_finally {
                    k += 9;
                }
                __libseh_end_finally
                if(k > b + c) __libseh_leave;
            }
        }
        __libseh_except(__libseh_get_exception_code() == EXCEPTION_ACCESS_VIOLATION) {
            k *= 4;
        }
        __libseh_end_except

        ret += k;
    }

    return ret;
}

BEGIN_SIMPLE_TEST(several_levels_test)
{
    TEST_VERIFY_INTEGER(do_something_2(0, 5, 10), 117);
    TEST_PASSED();
}
END_TEST()


