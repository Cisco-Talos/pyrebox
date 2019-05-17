/*
 * Copyright (c) 2018 Virtuozzo International GmbH
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 *
 */

#include "qemu/osdep.h"
#include "addrspace.h"

static struct pa_block *pa_space_find_block(struct pa_space *ps, uint64_t pa)
{
    size_t i;
    for (i = 0; i < ps->block_nr; i++) {
        if (ps->block[i].paddr <= pa &&
                pa <= ps->block[i].paddr + ps->block[i].size) {
            return ps->block + i;
        }
    }

    return NULL;
}

static uint8_t *pa_space_resolve(struct pa_space *ps, uint64_t pa)
{
    struct pa_block *block = pa_space_find_block(ps, pa);

    if (!block) {
        return NULL;
    }

    return block->addr + (pa - block->paddr);
}

int pa_space_create(struct pa_space *ps, QEMU_Elf *qemu_elf)
{
    Elf64_Half phdr_nr = elf_getphdrnum(qemu_elf->map);
    Elf64_Phdr *phdr = elf64_getphdr(qemu_elf->map);
    size_t block_i = 0;
    size_t i;

    ps->block_nr = 0;

    for (i = 0; i < phdr_nr; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            ps->block_nr++;
        }
    }

    ps->block = malloc(sizeof(*ps->block) * ps->block_nr);
    if (!ps->block) {
        return 1;
    }

    for (i = 0; i < phdr_nr; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            ps->block[block_i] = (struct pa_block) {
                .addr = (uint8_t *)qemu_elf->map + phdr[i].p_offset,
                .paddr = phdr[i].p_paddr,
                .size = phdr[i].p_filesz,
            };
            block_i++;
        }
    }

    return 0;
}

void pa_space_destroy(struct pa_space *ps)
{
    ps->block_nr = 0;
    free(ps->block);
}

void va_space_set_dtb(struct va_space *vs, uint64_t dtb)
{
    vs->dtb = dtb & 0x00ffffffffff000;
}

void va_space_create(struct va_space *vs, struct pa_space *ps, uint64_t dtb)
{
    vs->ps = ps;
    va_space_set_dtb(vs, dtb);
}

static uint64_t get_pml4e(struct va_space *vs, uint64_t va)
{
    uint64_t pa = (vs->dtb & 0xffffffffff000) | ((va & 0xff8000000000) >> 36);

    return *(uint64_t *)pa_space_resolve(vs->ps, pa);
}

static uint64_t get_pdpi(struct va_space *vs, uint64_t va, uint64_t pml4e)
{
    uint64_t pdpte_paddr = (pml4e & 0xffffffffff000) |
        ((va & 0x7FC0000000) >> 27);

    return *(uint64_t *)pa_space_resolve(vs->ps, pdpte_paddr);
}

static uint64_t pde_index(uint64_t va)
{
    return (va >> 21) & 0x1FF;
}

static uint64_t pdba_base(uint64_t pdpe)
{
    return pdpe & 0xFFFFFFFFFF000;
}

static uint64_t get_pgd(struct va_space *vs, uint64_t va, uint64_t pdpe)
{
    uint64_t pgd_entry = pdba_base(pdpe) + pde_index(va) * 8;

    return *(uint64_t *)pa_space_resolve(vs->ps, pgd_entry);
}

static uint64_t pte_index(uint64_t va)
{
    return (va >> 12) & 0x1FF;
}

static uint64_t ptba_base(uint64_t pde)
{
    return pde & 0xFFFFFFFFFF000;
}

static uint64_t get_pte(struct va_space *vs, uint64_t va, uint64_t pgd)
{
    uint64_t pgd_val = ptba_base(pgd) + pte_index(va) * 8;

    return *(uint64_t *)pa_space_resolve(vs->ps, pgd_val);
}

static uint64_t get_paddr(uint64_t va, uint64_t pte)
{
    return (pte & 0xFFFFFFFFFF000) | (va & 0xFFF);
}

static bool is_present(uint64_t entry)
{
    return entry & 0x1;
}

static bool page_size_flag(uint64_t entry)
{
    return entry & (1 << 7);
}

static uint64_t get_1GB_paddr(uint64_t va, uint64_t pdpte)
{
    return (pdpte & 0xfffffc0000000) | (va & 0x3fffffff);
}

static uint64_t get_2MB_paddr(uint64_t va, uint64_t pgd_entry)
{
    return (pgd_entry & 0xfffffffe00000) | (va & 0x00000001fffff);
}

static uint64_t va_space_va2pa(struct va_space *vs, uint64_t va)
{
    uint64_t pml4e, pdpe, pgd, pte;

    pml4e = get_pml4e(vs, va);
    if (!is_present(pml4e)) {
        return INVALID_PA;
    }

    pdpe = get_pdpi(vs, va, pml4e);
    if (!is_present(pdpe)) {
        return INVALID_PA;
    }

    if (page_size_flag(pdpe)) {
        return get_1GB_paddr(va, pdpe);
    }

    pgd = get_pgd(vs, va, pdpe);
    if (!is_present(pgd)) {
        return INVALID_PA;
    }

    if (page_size_flag(pgd)) {
        return get_2MB_paddr(va, pgd);
    }

    pte = get_pte(vs, va, pgd);
    if (!is_present(pte)) {
        return INVALID_PA;
    }

    return get_paddr(va, pte);
}

void *va_space_resolve(struct va_space *vs, uint64_t va)
{
    uint64_t pa = va_space_va2pa(vs, va);

    if (pa == INVALID_PA) {
        return NULL;
    }

    return pa_space_resolve(vs->ps, pa);
}

int va_space_rw(struct va_space *vs, uint64_t addr,
        void *buf, size_t size, int is_write)
{
    while (size) {
        uint64_t page = addr & PFN_MASK;
        size_t s = (page + PAGE_SIZE) - addr;
        void *ptr;

        s = (s > size) ? size : s;

        ptr = va_space_resolve(vs, addr);
        if (!ptr) {
            return 1;
        }

        if (is_write) {
            memcpy(ptr, buf, s);
        } else {
            memcpy(buf, ptr, s);
        }

        size -= s;
        buf = (uint8_t *)buf + s;
        addr += s;
    }

    return 0;
}
