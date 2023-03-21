#ifndef PCAP_H
#define PCAP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>


#define PCAP_SUCCESS 0
#define PCAP_FILE_END -1
#define PCAP_LOAD_ERROR -2

#define IPV4_ETH_TYPE 0x0800


struct pcap_header_t {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct packet_header_t {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct ip_header_t {
    uint8_t version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_addr[4];
    uint8_t dst_addr[4];
};

struct eth_header_t {
    unsigned char ether_dhost[6];
    unsigned char ether_shost[6];
    uint16_t ether_type;
};

struct packet_t {
    struct packet_header_t *packet_header;
    struct eth_header_t *eth_header;
    struct ip_header_t *ip_header;
};

struct pcap_context {
    FILE *handle;
    uint8_t *checksum;
};


/**
 * @brief Inits struct pcap_context to prepare loading of pcap file
 *
 * @param context
 * @param filename
 *
 * @return PCAP_SUCCESS in case of success, PCAP_LOAD_ERROR otherwise
 */
int init_context(struct pcap_context *context, const char *filename);

/**
 * @brief Destroys struct pcap_context and closes the pcap file associated with it
 *
 * @param context
 */
void destroy_context(struct pcap_context *context);


/**
 * @brief Loads pcap file header from pcap file. Must be called exactly once
 * before load_packet can be used
 *
 * @param context
 * @param header
 *
 * @return PCAP_SUCCESS in case of success, PCAP_LOAD_ERROR otherwise
 */
int load_header(struct pcap_context *context, struct pcap_header_t *header);


/**
 * @brief Loads next packet from pcap file
 *
 * @param context
 * @param packet
 *
 * @return PCAP_SUCCESS in case of success
 *         PCAP_FILE_END in case there are no more packets left to read
 *         PCAP_LOAD_ERROR otherwise
 */
int load_packet(struct pcap_context *context, struct packet_t *packet);

/**
 * @brief Copies data of packet src to packet dest
 *
 * @param src
 * @param dest
 *
 * @return PCAP_SUCCESS in case of success, PCAP_LOAD_ERROR otherwise
 */
int copy_packet(struct packet_t *src, struct packet_t *dest);

/**
 * @brief Destroys packet and releases all additional resources allocated
 * during load_packet/copy_packet call
 *
 * @param packet
 */
void destroy_packet(struct packet_t *packet);

/**
 * @brief Prints information about a single packet
 *
 * @param packet
 */
void print_packet_info(struct packet_t *packet);


#endif //PCAP_H
