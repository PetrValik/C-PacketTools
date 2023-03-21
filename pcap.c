#include "pcap.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ip_header_helper_t
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

int init_context(struct pcap_context *context, const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        return PCAP_LOAD_ERROR;
    }
    context->handle = fp;
    context->checksum = malloc(22 * sizeof(uint8_t));
    if (context->checksum == NULL) {
        fclose(context->handle);
        return PCAP_LOAD_ERROR;
    }
    return PCAP_SUCCESS;
}

void destroy_context(struct pcap_context *context)
{
    fclose(context->handle);
    free(context->checksum);
}

int load_header(struct pcap_context *context, struct pcap_header_t *header)
{
    if (fread(header, sizeof(struct pcap_header_t), 1, context->handle) == 0) {
        return PCAP_LOAD_ERROR;
    }
    return PCAP_SUCCESS;
}

void destroy_packet(struct packet_t *packet)
{
    free(packet->packet_header);
    free(packet->eth_header);
    free(packet->ip_header);
}

void parse_ipv4_address(uint32_t srcaddr, uint8_t dstaddr[4])
{
    uint8_t *src_char = (uint8_t *) &srcaddr;
    for (int i = 0; i < 4; i++) {
        dstaddr[i] = src_char[i];
    }
}

static uint16_t change_byte_order_short(const uint16_t value)
{
    uint8_t byte_value[2] = { 0 };
    memcpy(byte_value, &value, sizeof(uint16_t));

    return ((uint16_t) byte_value[1]) | ((uint16_t) byte_value[0] << 8);
}

static void format_ip_header(struct ip_header_helper_t *ip_helper,
        struct packet_t *packet)
{
    packet->ip_header->version = ip_helper->ver_ihl >> 4;
    packet->ip_header->ihl = (ip_helper->ver_ihl & 0xF) * 4;
    packet->ip_header->tos = ip_helper->tos;
    packet->ip_header->total_length = change_byte_order_short(ip_helper->total_length);
    packet->ip_header->id = change_byte_order_short(ip_helper->id);
    packet->ip_header->flags_fo = ip_helper->flags_fo;
    packet->ip_header->ttl = ip_helper->ttl;
    packet->ip_header->protocol = ip_helper->protocol;
    packet->ip_header->checksum = change_byte_order_short(ip_helper->checksum);
    parse_ipv4_address(ip_helper->src_addr, packet->ip_header->src_addr);
    parse_ipv4_address(ip_helper->dst_addr, packet->ip_header->dst_addr);
}

int load_packet(struct pcap_context *context, struct packet_t *packet)
{
    packet->packet_header = malloc(sizeof(struct packet_header_t));
    packet->eth_header = malloc(sizeof(struct eth_header_t));
    packet->ip_header = malloc(sizeof(struct ip_header_t));
    if (packet->packet_header == NULL || packet->eth_header == NULL ||
            packet->ip_header == NULL) {
        destroy_packet(packet);
        return PCAP_LOAD_ERROR;
    }

    bool successfully_parsed = false;

    while (!successfully_parsed) {
        struct ip_header_helper_t ip_helper = { 0 };
        int packet_data_len, eth_data_len, ip_data_len;

        int offset = ftell(context->handle);
        packet_data_len = fread(packet->packet_header,
                sizeof(struct packet_header_t),
                1,
                context->handle);

        if (packet_data_len == 0) {
            // the "wanted" EOF can happen only here
            if (feof(context->handle)) {
                destroy_packet(packet);
                return PCAP_FILE_END;
            }
            destroy_packet(packet);
            return PCAP_LOAD_ERROR;
        }

        eth_data_len = fread(packet->eth_header,
                sizeof(struct eth_header_t),
                1,
                context->handle);

        if (eth_data_len == 0) {
            destroy_packet(packet);
            return PCAP_LOAD_ERROR;
        }

        packet->eth_header->ether_type = change_byte_order_short(packet->eth_header->ether_type);

        if (packet->eth_header->ether_type == IPV4_ETH_TYPE) {
            ip_data_len = fread(&ip_helper,
                    sizeof(struct ip_header_helper_t),
                    1,
                    context->handle);

            if (ip_data_len == 0) {
                destroy_packet(packet);
                return PCAP_LOAD_ERROR;
            }

            format_ip_header(&ip_helper, packet);

            successfully_parsed = true;
        }

        // skip to the next packet
        fseek(context->handle,
                offset + sizeof(struct packet_header_t) +
                        packet->packet_header->incl_len,
                SEEK_SET);
    }

    return PCAP_SUCCESS;
}

int copy_packet(struct packet_t *src, struct packet_t *dest)
{
    dest->packet_header = malloc(sizeof(struct packet_header_t));
    dest->eth_header = malloc(sizeof(struct eth_header_t));
    dest->ip_header = malloc(sizeof(struct ip_header_t));

    if (dest->packet_header == NULL || dest->eth_header == NULL ||
            dest->ip_header == NULL) {
        destroy_packet(dest);
        return PCAP_LOAD_ERROR;
    }

    memcpy(dest->packet_header, src->packet_header, sizeof(struct packet_header_t));
    memcpy(dest->eth_header, src->eth_header, sizeof(struct eth_header_t));
    memcpy(dest->ip_header, src->ip_header, sizeof(struct ip_header_t));
    return PCAP_SUCCESS;
}

void print_packet_info(struct packet_t *packet)
{
    struct packet_header_t packet_header = *(packet->packet_header);
    struct eth_header_t e = *(packet->eth_header);
    struct ip_header_t ip = *(packet->ip_header);

    printf("*************** PCAP PACKET ***************\n");
    printf("timestamp seconds: %u, %x\n", packet_header.ts_sec, packet_header.ts_sec);
    printf("timestamp lower units: %u, %x\n", packet_header.ts_usec, packet_header.ts_usec);
    printf("included length: %u, %x\n", packet_header.incl_len, packet_header.incl_len);
    printf("original length: %u, %x\n", packet_header.orig_len, packet_header.orig_len);

    printf("*************** ETHER *************\n");
    printf("destination host: ");
    for (int i = 0; i < 6; i++) {
        printf(i == 5 ? "%02hhx" : "%02hhx:", e.ether_dhost[i]);
    }
    printf("\nsource host: ");
    for (int i = 0; i < 6; i++) {
        printf(i == 5 ? "%02hhx" : "%02hhx:", e.ether_shost[i]);
    }
    printf("\nethernet type: %x\n", e.ether_type);

    if (e.ether_type != IPV4_ETH_TYPE) {
        return;
    }
    printf("*************** IP ***************\n");
    printf("IP version: %u, IP header length: %u\n", ip.version, ip.ihl);
    printf("IP TOS: %u, %x\n", ip.tos, ip.tos);
    printf("IP total length: %u, %x\n", ip.total_length, ip.total_length);
    printf("IP ID: %u, %x\n", ip.id, ip.id);
    printf("IP flags: %u, %x\n", ip.flags_fo, ip.flags_fo);
    printf("IP time to live: %u, %x\n", ip.ttl, ip.ttl);
    printf("IP protocol: %u, %x\n", ip.protocol, ip.protocol);
    printf("IP checksum: %u, %x\n", ip.checksum, ip.checksum);
    printf("IP source address: %u.%u.%u.%u\n", ip.src_addr[0], ip.src_addr[1], ip.src_addr[2], ip.src_addr[3]);
    printf("IP destination address: %u.%u.%u.%u\n", ip.dst_addr[0], ip.dst_addr[1], ip.dst_addr[2], ip.dst_addr[3]);
}
