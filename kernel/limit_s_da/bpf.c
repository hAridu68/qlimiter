#include "bpf.h"

#define FLOW_DROP 0xD4AC7

#define KEY_FLOW_STATE 0xF000FAFA
#define KEY_CLASSID 0xF000FACC
#define KEY_MARK_DUMP 0x0000AAAA

#ifdef USE_OLD_SECTION
_s_map struct bpf_elf_map f_map = {
    ___uint(type, BPF_MAP_TYPE_HASH),
    ___size(size_key, __u32),
    ___size(size_value, __u32),
    ___uint(max_elem, 6),
    ___uint(pinning, PIN_OBJECT_NS)};
#else
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 6);
    __uint(pinning, PIN_OBJECT_NS);
} f_map _s_map;
#endif

#ifdef USING_SAFE_FUNC
__Static __u32 RetValue(void *src)
{
    __u32 dist;
    if (bpf_probe_read_kernel(&dist, sizeof(__u32), src) < 0)
    {
        trace_printk("ret(ret<0, bpf_probe_read_kernel()): &safe=%d, val=%d\n", &dist, src);
    }
    return dist;
}
#define GetValue(a) RetValue(a)
#else
#define GetValue(a) *a
#endif

__Static int read(const __u32 key)
{
    __u32 *val = bpf_map_lookup_elem(&f_map, &key);
    if (val != NULL)
    {
        trace_printk("ret(!NULL, read()): val=%d, *val=%d\n", val, *val);
        return GetValue(val);
    }
    trace_printk("ret(NULL, read()): val=%d\n", val);
    return 0x0bad;
}

__Static int update(const __u32 key, const __u32 value)
{
    int ret = bpf_map_update_elem(&f_map, &key, &value, BPF_ANY);
    trace_printk("ret(%d,update()): _key=%d, _value=%d\n", ret, key, value);
    return ret;
}

__section("limitator/ingress") int cls_main2(struct __sk_buff *skb)
{
    skb->tc_classid = read(KEY_CLASSID);
    return read(KEY_FLOW_STATE);
}

__section("limitator") int cls_main(struct __sk_buff *skb)
{
    __u32 flow_state;

    if ((flow_state = read(KEY_FLOW_STATE)) == 0x0bad)
    {
        flow_state = TC_ACT_UNSPEC;
    }

    switch (skb->mark)
    {
    case FLOW_DROP:
        flow_state = TC_ACT_SHOT;
        break;

    default:
        skb->tc_classid = skb->mark;
        flow_state = TC_ACT_OK;
        break;
    }

    // update(KEY_MARK_DUMP, skb->mark);
    update(KEY_CLASSID, skb->tc_classid);
    update(KEY_FLOW_STATE, flow_state);

    trace_printk("ret(): skb->tc_classid=%d, skb->mark=%d, flow_state=%d", skb->tc_classid, skb->mark, flow_state);

    return flow_state;
}

char __license[] __section("license") = "GPL";
