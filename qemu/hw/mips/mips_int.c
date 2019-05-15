/*
 * QEMU MIPS interrupt support
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "hw/hw.h"
#include "hw/mips/cpudevs.h"
#include "cpu.h"
#include "sysemu/kvm.h"
#include "kvm_mips.h"

static void cpu_mips_irq_request(void *opaque, int irq, int level)
{
    MIPSCPU *cpu = opaque;
    CPUMIPSState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    bool locked = false;

    if (irq < 0 || irq > 7)
        return;

    /* Make sure locking works even if BQL is already held by the caller */
    if (!qemu_mutex_iothread_locked()) {
        locked = true;
        qemu_mutex_lock_iothread();
    }

    if (level) {
        env->CP0_Cause |= 1 << (irq + CP0Ca_IP);

        if (kvm_enabled() && irq == 2) {
            kvm_mips_set_interrupt(cpu, irq, level);
        }

    } else {
        env->CP0_Cause &= ~(1 << (irq + CP0Ca_IP));

        if (kvm_enabled() && irq == 2) {
            kvm_mips_set_interrupt(cpu, irq, level);
        }
    }

    if (env->CP0_Cause & CP0Ca_IP_mask) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }

    if (locked) {
        qemu_mutex_unlock_iothread();
    }
}

void cpu_mips_irq_init_cpu(MIPSCPU *cpu)
{
    CPUMIPSState *env = &cpu->env;
    qemu_irq *qi;
    int i;

    qi = qemu_allocate_irqs(cpu_mips_irq_request, mips_env_get_cpu(env), 8);
    for (i = 0; i < 8; i++) {
        env->irq[i] = qi[i];
    }
}

void cpu_mips_soft_irq(CPUMIPSState *env, int irq, int level)
{
    if (irq < 0 || irq > 2) {
        return;
    }

    qemu_set_irq(env->irq[irq], level);
}
