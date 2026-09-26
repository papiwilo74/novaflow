// +build ignore
/*
 * NovaFlow NDR - Ultra High-Performance eBPF / XDP Network Probe
 *
 * Programa de kernel eBPF acoplado al driver de red (XDP - eXpress Data Path)
 * para inspección a velocidad de cable (Wire-Speed Kernel Bypass), extracción de 5-tuplas
 * y despacho asíncrono sin copia mediante BPF Ring Buffer.
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif

// Tipos básicos para compatibilidad con compilador clang BPF
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))

// Códigos de retorno XDP estándar
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

// Protocolos L4
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Estructura de contexto XDP provista por el kernel Linux
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

// Clave de 5-tupla para la tabla de flujos en kernel
struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

// Registro de flujo acumulado en mapa BPF
struct flow_value_t {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 packets;
    __u64 bytes;
    __u8  tcp_flags;
    __u8  pad[7];
};

// Evento emitido al userspace vía Ring Buffer
struct flow_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  tcp_flags;
    __u16 pad;
    __u64 packets;
    __u64 bytes;
    __u64 duration_ns;
};

// Definición de mapas BPF (BTF-defined maps)
enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_RINGBUF = 27,
};

struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} flow_table SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 65536,
    .key_size = sizeof(struct flow_key_t),
    .value_size = sizeof(struct flow_value_t),
};

struct {
    __u32 type;
    __u32 max_entries;
} events_rb SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24, // 16 MB ring buffer
};

struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} global_stats SEC(".maps") = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .max_entries = 4,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};

// Cabeceras de red L2/L3/L4 mínimas
struct eth_hdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
};

struct ip_hdr {
    __u8  ihl_version;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct tcp_hdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 res1_doff_flags;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

struct udp_hdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
};

// BPF helper stubs
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;

SEC("xdp")
int novaflow_xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Verificación de límites Ethernet (L2)
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Solo IPv4 (0x0800 en network byte order = 0x0008)
    if (eth->h_proto != 0x0008)
        return XDP_PASS;

    // 2. Verificación de límites IPv4 (L3)
    struct ip_hdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 ip_hl = (ip->ihl_version & 0x0F) * 4;
    if (ip_hl < sizeof(struct ip_hdr))
        return XDP_PASS;

    void *l4 = (void *)ip + ip_hl;
    if (l4 > data_end)
        return XDP_PASS;

    struct flow_key_t key = {0};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    __u8 flags = 0;
    __u64 pkt_len = (__u64)(data_end - data);

    // 3. Inspección L4 (TCP / UDP)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcp_hdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
        flags = (__u8)(tcp->res1_doff_flags & 0x3F);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udp_hdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else {
        return XDP_PASS;
    }

    // 4. Actualización de tabla de flujos en mapa BPF
    __u64 now = bpf_ktime_get_ns();
    struct flow_value_t *val = bpf_map_lookup_elem(&flow_table, &key);
    if (val) {
        val->packets += 1;
        val->bytes += pkt_len;
        val->last_seen_ns = now;
        val->tcp_flags |= flags;

        // Si el flujo cierra (FIN o RST) o supera umbral, emitir a userspace
        if (flags & 0x05) { // FIN (0x01) o RST (0x04)
            struct flow_event_t *ev = bpf_ringbuf_reserve(&events_rb, sizeof(*ev), 0);
            if (ev) {
                ev->src_ip = key.src_ip;
                ev->dst_ip = key.dst_ip;
                ev->src_port = key.src_port;
                ev->dst_port = key.dst_port;
                ev->protocol = key.protocol;
                ev->tcp_flags = val->tcp_flags;
                ev->packets = val->packets;
                ev->bytes = val->bytes;
                ev->duration_ns = now - val->first_seen_ns;
                bpf_ringbuf_submit(ev, 0);
            }
        }
    } else {
        struct flow_value_t new_val = {0};
        new_val.first_seen_ns = now;
        new_val.last_seen_ns = now;
        new_val.packets = 1;
        new_val.bytes = pkt_len;
        new_val.tcp_flags = flags;
        bpf_map_update_elem(&flow_table, &key, &new_val, 0);
    }

    return XDP_PASS;
}
