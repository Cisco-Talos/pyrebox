
#include "tests-common.inc"


typedef struct _node_t {
    struct _node_t* next;
    int value;
} node_t;


node_t* create_node(int n)
{
    node_t* ret = (node_t*)malloc(sizeof(node_t));
    // Bug...
    ret->next = (node_t*)0x2;
    ret->value = n;
    return ret;
}

int get_node_value(node_t* node)
{
    return node->value;
}
    

node_t* create_seq_list(int n1, int n2)
{
    node_t* ret = 0;
    int n = n2;
    for(; n >= n1; n--)
    {
        node_t* nret = create_node(n);
        nret->next = ret;
        ret = nret;
    }

    return ret;
}

int sum_list(node_t* list)
{
    volatile int ret = 0;
    while(list) {
        __libseh_try 
        {
            ret += get_node_value(list);
            list = list->next;
        }
        __libseh_except(__libseh_get_exception_code() == EXCEPTION_ACCESS_VIOLATION)
        {
            list = 0;
        }
        __libseh_end_except
    }

    return ret;
}

int sum_list_2(node_t* list)
{
    volatile int ret = 0;
    __libseh_try {
        while(list) {
            __libseh_try 
            {
                ret += get_node_value(list);
                list = list->next;
            }
            __libseh_finally
            {
                ret = -1;
            }
            __libseh_end_finally
        }
    }
    __libseh_except(__libseh_get_exception_code() == EXCEPTION_ACCESS_VIOLATION)
    {
    }
    __libseh_end_except

    return ret;
}

int fun3(volatile int *ret)
{
    *ret = 10;
    __libseh_try {
        RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
        TEST_FAILED("Exception not raised.");
    }
    __libseh_finally {
        *ret *= 10;
    }
    __libseh_end_finally
    
    return *ret;
}

BEGIN_SIMPLE_TEST(complex_test)
{
  volatile int x = 0;
  node_t* list = create_seq_list(1, 10);
  TEST_VERIFY_INTEGER(sum_list(list), 55);
  TEST_VERIFY_INTEGER(sum_list_2(list), -1);

  __libseh_try {
      fun3(&x);
      TEST_FAILED("Exception not raised.");
  }
  __libseh_except(__libseh_get_exception_code() == EXCEPTION_ACCESS_VIOLATION) 
  {
  }
  __libseh_end_except

  TEST_PASSED();
}
END_TEST()

