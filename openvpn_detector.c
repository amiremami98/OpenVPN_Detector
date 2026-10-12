#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AI Assistant");
MODULE_DESCRIPTION("Netfilter Kernel Module to Detect OpenVPN with DNS/VXLAN False-Positive Filtering");
MODULE_VERSION("2.2");

static struct nf_hook_ops nfho;

/**
 * @brief Helper function to check if a payload structurally looks like a standard DNS packet.
 */
static bool is_dns_packet(const u8 *payload, int len) {
    if (len < 12) return false;
    
    // Standard query (Questions = 1)
    if (payload[4] == 0x00 && payload[5] == 0x01) {
        if (payload[2] == 0x01 || payload[2] == 0x00 || payload[2] >= 0x80) return true;
    }
    
    // DNS response
    // if (payload[2] >= 0x80) return true;
    
    return false;
}

/**
 * @brief Helper function to check if a payload structurally looks like a VXLAN packet.
 * VXLAN first byte is 0x08, which perfectly mimics OpenVPN Opcode 1, KeyID 0.
 */
static bool is_vxlan_packet(const u8 *payload, int len) {
    if (len < 8) return false;
    
    // VXLAN Header Structure:
    // Byte 0: Flags (Usually 0x08)
    // Bytes 1-3: Reserved (Must be 0x000000)
    // Bytes 4-6: VNI (VXLAN Network Identifier)
    // Byte 7: Reserved (Must be 0x00)
    if (payload[0] == 0x08 && 
        payload[1] == 0x00 && payload[2] == 0x00 && payload[3] == 0x00 &&
        payload[7] == 0x00) {
        return true;
    }
    
    return false;
}

static unsigned int openvpn_detect_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    int payload_offset;
    int payload_len;
    const u8 *payload;
    u8 _payload_buffer[32];

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // ----- UDP Packet Inspection -----
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        
        payload_offset = iph->ihl * 4 + sizeof(struct udphdr);
        payload_len = skb->len - payload_offset;

        if (payload_len >= 14) {
            payload = skb_header_pointer(skb, payload_offset, 14, _payload_buffer);
            
            if (payload) {
                u8 opcode = payload[0] >> 3;
                u8 key_id = payload[0] & 0x07;

                // Check for valid OpenVPN Control Opcodes (1 to 8) and KeyID 0
                if ((opcode >= 1 && opcode <= 8) && key_id == 0) {
                    
                    // Exclude known protocols that mimic this exact byte signature
                    if (is_dns_packet(payload, payload_len)) {
                        printk(KERN_INFO "[DPI Module] DNS detected!\n");
                    }
                    if (is_vxlan_packet(payload, payload_len)) {
                        printk(KERN_INFO "[DPI Module] VXLAN detected!\n");
                    }
                    if (!is_dns_packet(payload, payload_len) &&
                        !is_vxlan_packet(payload, payload_len)) {
                        udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
                        printk(KERN_INFO "[OpenVPN Detector] UDP OpenVPN Handshake detected! Src: %pI4:%d -> Dst: %d (Opcode: %d)\n",
                               &iph->saddr, ntohs(udph->source), ntohs(udph->dest), opcode);
                        printk(KERN_INFO "Payload: %02X\n", payload[2]);
                    }
                }
            }
        }
    }
    // ----- TCP Packet Inspection -----
    else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
        payload_offset = iph->ihl * 4 + tcph->doff * 4;
        payload_len = skb->len - payload_offset;

        if (payload_len >= 16) {
            payload = skb_header_pointer(skb, payload_offset, 16, _payload_buffer);
            
            if (payload) {
                u16 ovpn_len = ntohs(*((u16 *)payload));
                u8 opcode = payload[2] >> 3;
                u8 key_id = payload[2] & 0x07;

                if (ovpn_len == (payload_len - 2)) {
                    if ((opcode >= 1 && opcode <= 8) && key_id == 0) {
                        printk(KERN_INFO "[OpenVPN Detector] TCP OpenVPN Handshake detected! Src: %pI4:%d -> Dst: %d (Opcode: %d)\n",
                               &iph->saddr, ntohs(tcph->source), ntohs(tcph->dest), opcode);
                    }
                }
            }
        }
    }

    return NF_ACCEPT;
}

static int __init openvpn_detector_init(void)
{
    nfho.hook = openvpn_detect_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[OpenVPN Detector] Module loaded. Monitoring all ports (DNS & VXLAN structurally excluded).\n");
    return 0;
}

static void __exit openvpn_detector_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[OpenVPN Detector] Module unloaded.\n");
}

module_init(openvpn_detector_init);
module_exit(openvpn_detector_exit);
