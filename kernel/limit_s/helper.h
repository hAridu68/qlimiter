/* Misc helper macros. */
#define __section(x) __attribute__((section(x), used))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define ptr_to_u64(X) (__u64)(unsigned long) X

/* Object pinning settings */
#define PIN_NONE 0
#define PIN_OBJECT_NS 1
#define PIN_GLOBAL_NS 2
/* ELF map definition */
#ifdef USE_OLD_SECTION
struct bpf_elf_map
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};
#endif 

#define ___size(name, type) .name = sizeof(type)
#define ___uint(name, value) .name = value

#ifdef DEBUG
#define trace_printk(x, ...) ({                            \
    char __fmt[] = x;                                      \
    bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})
#else
#define trace_printk(x, ...)
#endif

// Use depricated section
#ifdef USE_OLD_SECTION
#define _s_map __section("maps")
#define _s_tc __section("classifier")
#else
#define _s_map SEC(".maps")
#define _s_tc SEC("tc")
#endif