
/*******************************************************************************
 *                                                                             *
 * seh-suppoprt.c - Functions used to implement SEH support at runtime.        *
 *                                                                             *
 * LIBSEH - Structured Exception Handling compatibility library.               *
 * Copyright (c) 2008 Tom Bramer < tjb at postpro dot net >                    *
 *                                                                             *
 * Permission is hereby granted, free of charge, to any person                 *
 * obtaining a copy of this software and associated documentation              *
 * files (the "Software"), to deal in the Software without                     *
 * restriction, including without limitation the rights to use,                *
 * copy, modify, merge, publish, distribute, sublicense, and/or sell           *
 * copies of the Software, and to permit persons to whom the                   *
 * Software is furnished to do so, subject to the following                    *
 * conditions:                                                                 *
 *                                                                             *
 * The above copyright notice and this permission notice shall be              *
 * included in all copies or substantial portions of the Software.             *
 *                                                                             *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,             *
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES             *
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                    *
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT                 *
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,                *
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING                *
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR               *
 * OTHER DEALINGS IN THE SOFTWARE.                                             *
 *                                                                             *
 *******************************************************************************/

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "seh-support.h"
#include "../../common/tree.h"
#include "../../common/stddefs.h"
#include <stdint.h>

#ifdef HAVE_SEH_WORKAROUND_SUPPORT

tree_t seh_stacks;
pthread_mutex_t tree_mtx;

static void _init() __attribute__((constructor));
static void _fini() __attribute__((destructor));
static void _signal_init();

/**
 * Create an exception code.  This is used to map Unix signals and sub codes to
 * Windows exception codes.
 *
 * @param sig      The signal number.
 * @param subcode  The signal sub code.
 *
 * @return  The exception code.
 */
DECLLANG
DWORD __seh_make_exception(int sig, int subcode)
{
  switch(sig)
   {
    case SIGSEGV:
      return EXCEPTION_ACCESS_VIOLATION;
   }

  return MAKE_EXCEPTION(sig, subcode);
}


DECLLANG
int __seh_unhandled_exception_handler(PEXCEPTION_RECORD pRecord,
                                      __seh_buf* pReg,
                                      PCONTEXT pContext,
                                      PEXCEPTION_RECORD pRecord2)
{
  TRACE_START();
  fprintf(stderr, "Unhandled Exception: 0x%08lx\nAddress: 0x%08lx\n", 
	    (uint32_t)pRecord->ExceptionCode, 
            (uint32_t)pRecord->ExceptionAddress);
  fflush(stderr);
  exit(1);
  TRACE_END();
}
  

DECLLANG void __seh_signal_handler(int signal, siginfo_t* siginf, void* context)
{
  TRACE_START();
  __seh_buf* buf;
  __seh_info* info;
  EXCEPTION_RECORD rec;
  EXCEPTION_RECORD rec2;
  CONTEXT ctx;

  buf = __seh_get_registration();
  TRACE1("buf = 0x%08x\n", buf);

  INFO3("Exception occurred: signal: %d, code: %d, address: 0x%08x\n", 
	siginf->si_signo, siginf->si_code, siginf->si_addr);

  memset(&rec, 0, sizeof(EXCEPTION_RECORD));
  memset(&ctx, 0, sizeof(CONTEXT));
  memset(&rec2, 0, sizeof(EXCEPTION_RECORD));

  /* Build an EXCEPTION_RECORD */
  rec.ExceptionCode = __seh_make_exception(siginf->si_signo, siginf->si_code);
  rec.ExceptionAddress = siginf->si_addr;

  /* Build a CONTEXT record */
  /* Do nothing for now. */

  if(buf == NULL)
    {
      TRACE0("Executing default exception handler.\n");
      __seh_unhandled_exception_handler(&rec, buf, &ctx, &rec2);
    }
  else {
    TRACE0("Preparing to execute user defined exception handler block.\n");
    info = buf->excinfo;
    VERIFY(info != NULL, "Exception information pointer was not initialized!");
    memcpy(&info->record, &rec, sizeof(EXCEPTION_RECORD));
    memcpy(&info->record2, &rec2, sizeof(EXCEPTION_RECORD));
    memcpy(&info->context, &ctx, sizeof(CONTEXT));
    info->pointers.ContextRecord = &(info->context);
    info->pointers.ExceptionRecord = &(info->record);
    VERIFY(buf->handler != NULL, "Exception handler was not set!");
    _signal_init();
    TRACE0("Now executing user defined exception handler block.\n");
    buf->handler(&rec, buf, &ctx, &rec2);
    TRACE0("Exception handler emptied the handler stack...\n");

    fprintf(stderr, "Unhandled Exception: 0x%08lx\nSignal: %d, Code: %d\nAddress: 0x%08lx\n", 
	    rec.ExceptionCode, siginf->si_signo, siginf->si_code, (uint32_t)rec.ExceptionAddress);
    exit(1);
    }

  TRACE_END();
  /* Not Reached */
}


static void _init()
{
  TRACE_START();
  seh_stacks = tree_create();
  pthread_mutex_init(&tree_mtx, NULL);
  _signal_init();
  TRACE_END();
}

static void _signal_init()
{
  TRACE_START();
  struct sigaction sa;
  int trap_signals[] = { SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGTRAP };

  /* Set exception handlers. */
  for(int* p = trap_signals; p != trap_signals + (sizeof(trap_signals) / sizeof(trap_signals[0])); p++)
    {
      sigaction(*p, NULL, &sa);
      sa.sa_flags |= SA_SIGINFO | SA_NOMASK;
      sa.sa_sigaction = __seh_signal_handler;
      TRACE2("Signal mask for signal %d: %08x\n", *p, sa.sa_mask);
      sigemptyset(&sa.sa_mask);
      sigaction(*p, &sa, NULL);
    }
  TRACE_END();
}


static void _fini()
{
  TRACE_START();
  tree_destroy(&seh_stacks);
  pthread_mutex_destroy(&tree_mtx);
  TRACE_END();
}

DECLLANG
int __seh_exception_handler(PEXCEPTION_RECORD pRecord,
                            __seh_buf* pReg,
                            PCONTEXT pContext,
                            PEXCEPTION_RECORD pRecord2)
{
  TRACE_START();
  _PEXCEPTION_HANDLER me = pReg->handler;
  __seh_info* info = pReg->excinfo;
  int ret;

  if (pReg->state == 2)
    pReg = __seh_pop_registration();

  TRACE1("Value of pReg = 0x%08x\n", pReg);
  TRACE1("Top value of handler stack = 0x%08x\n", __seh_get_registration());
  TRACE1("Previous handler: 0x%08x\n", __seh_get_registration()->prev);
  TRACE1("Handler function: 0x%08x\n", __seh_get_registration()->handler);
  TRACE1("Magic number: 0x%08x\n", __seh_get_registration()->magic);


  VERIFY(info != NULL, "Exception information block was not initialized!");

  for(;;)
    {
    if (pReg->handler == me && pReg->magic == SEH_MAGIC_NUMBER)
      {
      TRACE0("This handler is handling the exception.\n");
      TRACE1("pReg->state = %d\n", pReg->state);
      pReg->excinfo = info;
      if (0 == pReg->state) {
	pReg->state = 2;
        __seh_restore_context(pReg, 1);
	}
      } 
    else
      {
      TRACE0("Executing other exception handler.\n");
      pReg->handler(pRecord, pReg, pContext, pRecord2);
      }
    
    if(pReg->prev == NULL) break;
    TRACE0("Poping top registration off stack.\n");
    pReg = __seh_pop_registration();

    }

  ret = __seh_unhandled_exception_handler(pRecord, pReg, pContext, pRecord2);
  TRACE_END();
  return ret; 
}



DECLLANG
int GetExceptionCode()
{
  TRACE_START();
  __seh_buf* pReg = __seh_get_registration();
  int ret;

  if(pReg == NULL || pReg->magic != SEH_MAGIC_NUMBER || pReg->excinfo == NULL)
    {
      return 0;
    }

  ret = pReg->excinfo->record.ExceptionCode;
  TRACE_END();
  return ret; 
}

DECLLANG
LPEXCEPTION_POINTERS GetExceptionInformation()
{
  TRACE_START();
  __seh_buf* pReg = __seh_get_registration();
  LPEXCEPTION_POINTERS ret;

  if(pReg == NULL || pReg->magic != SEH_MAGIC_NUMBER || pReg->excinfo == NULL)
    {
      return 0;
    }

  ret = &(pReg->excinfo->pointers);
  TRACE_END();
  return ret;
}

DECLLANG
void __seh_unregister()
{
  TRACE_START();
  /* Since __seh_pop_registration uses reference counting in this implementation, 
     it can be used to unregister the handler. */

  __seh_fini_buf(__seh_get_registration());
  __seh_pop_registration();
  TRACE_END();
}

DECLLANG __seh_buf* __stdcall __seh_get_registration()
{
  TRACE_START();
  __seh_thread_stack* stack = NULL;
  __seh_buf* buf;
  int ret;

  pthread_mutex_lock(&tree_mtx);
  ret = tree_search(&seh_stacks, (tree_key_t)pthread_self(), (tree_value_t*)&stack);
  pthread_mutex_unlock(&tree_mtx);

  TRACE1("tree_search returned: %d\n", ret);
  TRACE1("stack = 0x%08x\n", stack);

  if(stack == NULL)
    return NULL;

  buf = stack->buf;
  TRACE1("buf = 0x%08x\n", buf);
  TRACE_END();
  return buf;
}

DECLLANG void __stdcall __seh_set_registration(__seh_buf* buf)
{
  TRACE_START();
  __seh_thread_stack* stack;
  int res;
  TRACE1("buf = 0x%08x\n", buf);

  pthread_mutex_lock(&tree_mtx);
  res = tree_search(&seh_stacks, (tree_key_t)pthread_self(), (tree_value_t*)&stack);
  pthread_mutex_unlock(&tree_mtx);

  if(res == RESULT_FAIL)
    {
      stack = (__seh_thread_stack*)malloc(sizeof(__seh_thread_stack));
      stack->info = (__seh_info*)malloc(sizeof(__seh_info));
      stack->refcount = 0;
      pthread_mutex_lock(&tree_mtx);
      res = tree_insert(&seh_stacks, (tree_key_t)pthread_self(), (tree_value_t)stack);
      pthread_mutex_unlock(&tree_mtx);

      VERIFY(res == RESULT_OK, "Tree insertion failed!");
    }

  TRACE1("stack = 0x%08x\n", stack);
  
  stack->refcount++;

  TRACE1("stack->refcount = %d\n", stack->refcount);

  stack->buf = buf;
  stack->buf->excinfo = stack->info;
  TRACE_END();
}

DECLLANG __seh_buf* __seh_pop_registration()
{
  TRACE_START();
  __seh_thread_stack* stack = NULL;
  __seh_buf* buf = NULL;
  int res;

  pthread_mutex_lock(&tree_mtx);
  res = tree_search(&seh_stacks, (tree_key_t)pthread_self(), (tree_value_t*)&stack);
  pthread_mutex_unlock(&tree_mtx);

  VERIFY(res == RESULT_OK, "__seh_pop_registration() should only be called after at least one entry has been added");
  VERIFY(stack != NULL, "Tree search was OK, but returned null value anyway.");
  VERIFY(stack->buf != NULL, "SEH handler stack is empty.");

  stack->buf = stack->buf->prev;
  stack->refcount--;

  VERIFY(stack->refcount >= 0, "Invalid SEH stack reference count");

  buf = stack->buf;

  if(stack->refcount == 0)
    {
    TRACE0("Now calling free on shared memory for exception handling for this thread.\n");
    free(stack->info);
    free(stack);

    pthread_mutex_lock(&tree_mtx);
    res = tree_delete(&seh_stacks, (tree_key_t)pthread_self());
    pthread_mutex_unlock(&tree_mtx);

    VERIFY(res == RESULT_OK, "Unable to remove this threads SEH handler stack from stack tree.");
    }

  TRACE_END();
  return buf;
}

DECLLANG 
void __seh_init_buf(__seh_buf* buf)
{
  TRACE_START();
  TRACE1("buf = 0x%08x\n", buf);

  buf->magic = SEH_MAGIC_NUMBER;
  buf->state = 0;
  TRACE1("Before registration, top handler is: 0x%08x\n", __seh_get_registration());
  buf->handler = __seh_exception_handler;
  buf->prev = __seh_get_registration();
  __seh_set_registration(buf);
  TRACE1("After registration, top handler is: 0x%08x\n", __seh_get_registration());
  TRACE_END();
}

DECLLANG 
void __seh_fini_buf(__seh_buf* buf)
{
  TRACE_START();
  /* Resources are shared for the thread, and reference counting is used to free those
     within __seh_pop_registration. */
  buf->magic = 0x0;
  TRACE_END();
}

#endif
