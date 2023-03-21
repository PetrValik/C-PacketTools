#include "capture.h"
#include <stdlib.h>
#include <string.h>

int add_item(struct capture_t *capture, struct packet_t *packet, unsigned int index) {
    capture_t_item *new_item = malloc(sizeof(capture_t_item));
    if (new_item == NULL) {
        return EXIT_FAILURE;
    }
    if (capture->head == NULL) {
        capture->head = new_item;
        capture->tail = new_item;
        new_item->prev = NULL;
    } else {
        capture->tail->next = new_item;
        new_item->prev = capture->tail;
        capture->tail = new_item;
    }
    new_item->index = index;
    new_item->packet = packet;
    new_item->next = NULL;
    capture->len++;
    return EXIT_SUCCESS;
}

void initialize_capture(struct capture_t *capture) {
    capture->tail = NULL;
    capture->head = NULL;
    capture->len = 0;
    capture->item_size = sizeof(capture_t_item);
}

int load_capture(struct capture_t *capture, const char *filename)
{
    struct pcap_context *context = malloc(sizeof(struct pcap_context));
    if (context == NULL) {
        return EXIT_FAILURE;
    }
    if (init_context(context, filename) != 0) {
        free(context);
        return EXIT_FAILURE;
    }

    initialize_capture(capture);

    struct pcap_header_t *header = malloc(sizeof(struct pcap_header_t));
    if (header == NULL) {
        destroy_context(context);
        free(context);
        return EXIT_FAILURE;
    }

    if(load_header(context, header) != 0) {
        destroy_context(context);
        free(context);
        free(header);
        return EXIT_FAILURE;
    }
    capture->header = header;

    int loaded;
    struct packet_t *packet;
    do {
        packet = malloc(sizeof(struct packet_t));
        if (packet == NULL) {
            destroy_capture(capture);
            destroy_context(context);
            free(context);
            return EXIT_FAILURE;
        }
        loaded = load_packet(context, packet);
        if (loaded != 0 && loaded != -1) {
            free(packet);
            destroy_context(context);
            free(context);
            destroy_capture(capture);
            return EXIT_FAILURE;
        }
        if (loaded == -1) {
            free(packet);
            break;
        }
        add_item(capture, packet, capture->len);
    } while (1);
    destroy_context(context);
    free(context);
    return EXIT_SUCCESS;
}

void destroy_item(capture_t_item *item) {
    item->next = NULL;
    item->prev = NULL;
    destroy_packet(item->packet);
    free(item->packet);
    item->packet = NULL;
    item->index = 0;
    free(item);
}

void destroy_capture_struct(struct capture_t *capture) {
    capture->head = NULL;
    capture->tail = NULL;
    capture->item_size = 0;
    capture->len = 0;
    free(capture->header);
    capture->header = NULL;
}

void destroy_capture(struct capture_t *capture)
{
    struct capture_t_item *actual_item = capture->head;
    capture_t_item *next_item;
    while (actual_item != NULL) {
        next_item = actual_item->next;
        destroy_item(actual_item);
        actual_item = next_item;
    }
    destroy_capture_struct(capture);
}

const struct pcap_header_t *get_header(const struct capture_t *const capture)
{
    return capture->header;
}

struct packet_t *get_packet(
        const struct capture_t *const capture,
        size_t index)
{
    if (index > capture->len) {
        return NULL;
    }
    capture_t_item *actual = capture->head;
    while (actual != NULL) {
        if (actual->index == index) {
            return actual->packet;
        }
        actual = actual->next;
    }
    return NULL;
}

size_t packet_count(const struct capture_t *const capture)
{
    return capture->len;
}

size_t data_transfered(const struct capture_t *const capture)
{
    size_t counter = 0;
    capture_t_item *item = capture->head;
    while (item != NULL) {
        counter += item->packet->packet_header->orig_len;
        item = item->next;
    }
    return counter;
}

int filter_protocol(
        const struct capture_t *const original,
        struct capture_t *filtered,
        uint8_t protocol)
{
    capture_t_item *item = original->head;
    struct packet_t *new_packet;
    initialize_capture(filtered);
    struct pcap_header_t *new_header = malloc(sizeof(struct pcap_header_t));
    if (new_header == NULL) {
        return EXIT_FAILURE;
    }
    filtered->header = new_header;
    memcpy(new_header, original->header, sizeof(struct pcap_header_t));
    while (item != NULL) {
        if (protocol == item->packet->ip_header->protocol) {
            new_packet = malloc(sizeof(struct packet_t));
            if (new_packet == NULL) {
                destroy_capture(filtered);
                return EXIT_FAILURE;
            }
            copy_packet(item->packet, new_packet);
            add_item(filtered ,new_packet ,filtered->len);
        }
        item = item->next;
    }
    return EXIT_SUCCESS;
}

int filter_larger_than(
        const struct capture_t *const original,
        struct capture_t *filtered,
        uint32_t size)
{
    capture_t_item *item = original->head;
    struct packet_t *new_packet;
    initialize_capture(filtered);
    struct pcap_header_t *new_header = malloc(sizeof(struct pcap_header_t));
    if (new_header == NULL) {
        return EXIT_FAILURE;
    }
    filtered->header = new_header;
    memcpy(new_header, original->header, sizeof(struct pcap_header_t));
    while (item != NULL) {
        if (size <= item->packet->packet_header->orig_len) {
            new_packet = malloc(sizeof(struct packet_t));
            if (new_packet == NULL) {
                destroy_capture(filtered);
                return EXIT_FAILURE;
            }
            copy_packet(item->packet, new_packet);
            add_item(filtered ,new_packet ,filtered->len);
        }
        item = item->next;
    }
    return EXIT_SUCCESS;
}

int same_ips(struct packet_t *packet,
             const uint8_t source_ip[4],
             const uint8_t destination_ip[4])
{
    for (int i = 0; i < 4; i++) {
        if (packet->ip_header->src_addr[i] != source_ip[i] ||
            packet->ip_header->dst_addr[i] != destination_ip[i])
            return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int filter_from_to(
        const struct capture_t *const original,
        struct capture_t *filtered,
        uint8_t source_ip[4],
        uint8_t destination_ip[4])
{
    capture_t_item *item = original->head;
    struct packet_t *new_packet;
    initialize_capture(filtered);
    struct pcap_header_t *new_header = malloc(sizeof(struct pcap_header_t));
    if (new_header == NULL) {
        return EXIT_FAILURE;
    }
    filtered->header = new_header;
    memcpy(new_header, original->header, sizeof(struct pcap_header_t));
    while (item != NULL) {
        if (same_ips(item->packet, source_ip, destination_ip) == EXIT_SUCCESS) {
            new_packet = malloc(sizeof(struct packet_t));
            if (new_packet == NULL) {
                destroy_capture(filtered);
                return EXIT_FAILURE;
            }
            copy_packet(item->packet, new_packet);
            add_item(filtered ,new_packet ,filtered->len);
        }
        item = item->next;
    }
    return EXIT_SUCCESS;
}

int is_correct_mask(const uint8_t ip_adress[4],
                    const uint8_t network_prefix[4],
                    uint8_t mask_length) {
    for (int i = 0; i < mask_length; i++) {
        uint8_t network = network_prefix[ i / 8];
        uint8_t adress = ip_adress[ i / 8 ];
        uint8_t to_and = 1 << ((i / 8) + 7 - (i % 8)) ;
        if ((adress & to_and) != (network & to_and)) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int filter_from_mask(
        const struct capture_t *const original,
        struct capture_t *filtered,
        uint8_t network_prefix[4],
        uint8_t mask_length)
{
    capture_t_item *item = original->head;
    struct packet_t *new_packet;
    initialize_capture(filtered);
    struct pcap_header_t *new_header = malloc(sizeof(struct pcap_header_t));
    if (new_header == NULL) {
        return EXIT_FAILURE;
    }
    filtered->header = new_header;
    memcpy(new_header, original->header, sizeof(struct pcap_header_t));
    while (item != NULL) {
        if (is_correct_mask(item->packet->ip_header->src_addr, network_prefix, mask_length) == EXIT_SUCCESS) {
            new_packet = malloc(sizeof(struct packet_t));
            if (new_packet == NULL) {
                destroy_capture(filtered);
                return EXIT_FAILURE;
            }
            copy_packet(item->packet, new_packet);
            add_item(filtered ,new_packet ,filtered->len);}
        item = item->next;
    }
    return EXIT_SUCCESS;
}

int filter_to_mask(
        const struct capture_t *const original,
        struct capture_t *filtered,
        uint8_t network_prefix[4],
        uint8_t mask_length)
{
    capture_t_item *item = original->head;
    struct packet_t *new_packet;
    initialize_capture(filtered);
    struct pcap_header_t *new_header = malloc(sizeof(struct pcap_header_t));
    if (new_header == NULL) {
        return EXIT_FAILURE;
    }
    filtered->header = new_header;
    memcpy(new_header, original->header, sizeof(struct pcap_header_t));
    while (item != NULL) {
        if (is_correct_mask(item->packet->ip_header->dst_addr, network_prefix, mask_length) == EXIT_SUCCESS) {
            new_packet = malloc(sizeof(struct packet_t));
            if (new_packet == NULL) {
                destroy_capture(filtered);
                return EXIT_FAILURE;
            }
            copy_packet(item->packet, new_packet);
            add_item(filtered ,new_packet ,filtered->len);}
        item = item->next;
    }
    return EXIT_SUCCESS;

}

int adress_count(capture_t_item *item, struct packet_t *packet, int *already_uses) {
    int count = 0;
    while (item != NULL) {
        if (same_ips(item->packet, packet->ip_header->src_addr, packet->ip_header->dst_addr) == EXIT_SUCCESS) {
            count += 1;
            already_uses[item->index] = 1;
        }
        item = item->next;
    }
    return count;
}

void null_array(unsigned int len, int *already_uses) {
    for (unsigned int i = 0; i < len; i++) {
        already_uses[i] = 0;
    }
}

int print_flow_stats(const struct capture_t *const capture)
{
    int *already_uses = malloc(sizeof(int) * (capture->len + 1));
    null_array(capture->len, already_uses);
    capture_t_item *item = capture->head;
    int count = 0;
    while (item != NULL) {
        if (already_uses[item->index] == 0) {
            count = adress_count(item, item->packet, already_uses);
            printf("%d.%d.%d.%d -> ", item->packet->ip_header->src_addr[0], item->packet->ip_header->src_addr[1], item->packet->ip_header->src_addr[2], item->packet->ip_header->src_addr[3]);
            printf("%d.%d.%d.%d : ", item->packet->ip_header->dst_addr[0], item->packet->ip_header->dst_addr[1], item->packet->ip_header->dst_addr[2], item->packet->ip_header->dst_addr[3]);
            printf("%d\n",count);
        }
        item = item->next;
    }
    free(already_uses);
    return EXIT_SUCCESS;
}

size_t find_last_packet(const struct capture_t *const capture, struct packet_t *flow_start, size_t index)
{
    capture_t_item *item = capture->tail;
    while (item != NULL) {
        if (same_ips(flow_start, item->packet->ip_header->src_addr, item->packet->ip_header->dst_addr) == EXIT_SUCCESS) {
            return item->index;
        }
        item = item->prev;
    }
    return index;
}

void flow_time(struct packet_t *start, struct packet_t *end, uint32_t *sec, uint32_t *usec, uint32_t magic_number)
{
    uint32_t max = 1000000000;
    if (2712847316 == magic_number) {
        max = 1000000;
    }
    *sec = end->packet_header->ts_sec - start->packet_header->ts_sec;

    if ((end->packet_header->ts_sec - start->packet_header->ts_sec) > end->packet_header->ts_usec) {
        *usec = max - (start->packet_header->ts_usec - end->packet_header->ts_usec);
        *sec += 1;
    } else {
        *usec = end->packet_header->ts_usec - start->packet_header->ts_usec;
    }
}

void is_longer(const struct capture_t *capture, size_t *longest_start, size_t *longest_end, size_t start, size_t end, uint32_t magic_number)
{
    uint32_t longest_time_sec;
    uint32_t longest_time_usec;
    flow_time(get_packet(capture, *longest_start), get_packet(capture, *longest_end), &longest_time_sec, &longest_time_usec, magic_number);
    uint32_t time_sec;
    uint32_t time_usec;
    flow_time(get_packet(capture, start), get_packet(capture, end), &time_sec, &time_usec, magic_number);
    if (time_sec > longest_time_sec || (time_sec == longest_time_sec && longest_time_usec < time_usec)) {
        *longest_start = start;
        *longest_end = end;
    }
}

int print_longest_flow(const struct capture_t *const capture)
{
    if (capture->len == 0) {
        fprintf(stderr, "Failure - empty capture received\n");
        return EXIT_FAILURE;
    }
    size_t longest_flow_start = 0;
    size_t longest_flow_end = find_last_packet(capture, get_packet(capture, longest_flow_start), longest_flow_start);
    capture_t_item *item = capture->head;
    size_t flow_end;
    while (item != NULL) {
        flow_end = find_last_packet(capture, item->packet, item->index);
        is_longer(capture, &longest_flow_start, &longest_flow_end, item->index, flow_end, capture->header->magic_number);
        item = item->next;
    }
    printf("%d.%d.%d.%d -> ", get_packet(capture,longest_flow_start)->ip_header->src_addr[0], get_packet(capture,longest_flow_start)->ip_header->src_addr[1], get_packet(capture,longest_flow_start)->ip_header->src_addr[2], get_packet(capture,longest_flow_start)->ip_header->src_addr[3]);
    printf("%d.%d.%d.%d : ", get_packet(capture,longest_flow_start)->ip_header->dst_addr[0], get_packet(capture,longest_flow_start)->ip_header->dst_addr[1], get_packet(capture,longest_flow_start)->ip_header->dst_addr[2], get_packet(capture,longest_flow_start)->ip_header->dst_addr[3]);
    printf("%d:%d - %d:%d\n", get_packet(capture,longest_flow_start)->packet_header->ts_sec , get_packet(capture,longest_flow_start)->packet_header->ts_usec, get_packet(capture,longest_flow_end)->packet_header->ts_sec , get_packet(capture,longest_flow_end)->packet_header->ts_usec);
    return EXIT_SUCCESS;
}
