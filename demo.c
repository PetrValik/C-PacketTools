#include <stdio.h>
#include <stdlib.h>
#include "capture.h"

#define TEST_FILE "test.pcap"

void demo1()
{
    struct pcap_context context[1];
    if (init_context(context, TEST_FILE) != PCAP_SUCCESS) {
        return;
    }

    struct pcap_header_t *pcap_header = malloc(sizeof(struct pcap_header_t));
    if (pcap_header == NULL) {
        destroy_context(context);
        return;
    }

    if (load_header(context, pcap_header) != PCAP_SUCCESS) {
        free(pcap_header);
        destroy_context(context);
        return;
    }

    struct packet_t *packet1 = malloc(sizeof(struct packet_t));

    if (packet1 == NULL) {
        free(pcap_header);
        destroy_context(context);
        return;
    }

    if (load_packet(context, packet1) != PCAP_SUCCESS) {
        free(pcap_header);
        destroy_context(context);
        return;
    }

    struct packet_t *packet2 = malloc(sizeof(struct packet_t));

    if (packet2 == NULL) {
        free(packet1);
        free(pcap_header);
        destroy_context(context);
        return;
    }

    if (load_packet(context, packet2) != PCAP_SUCCESS) {
        free(packet1);
        free(pcap_header);
        destroy_context(context);
        return;
    }

    destroy_context(context);

    printf("packet 1:\n");
    print_packet_info(packet1);

    printf("\npacket 2:\n");
    print_packet_info(packet2);

    destroy_packet(packet1);
    destroy_packet(packet2);

    free(packet1);
    free(packet2);
    free(pcap_header);
}

void demoone() {
    struct capture_t capture[1];

    int retval = load_capture(capture, TEST_FILE);
    printf("retval %d\n", retval);

    struct capture_t filtered[1];
    printf("packets_len %zu\n", packet_count(capture));
    printf("packets %u\n", capture->tail->index);
    printf("Magic number: 0x%x\n", get_header(capture)->magic_number);
    retval = filter_from_to(
            capture,
            filtered,
            (uint8_t[4]){ 74U, 125U, 19U, 17U },
            (uint8_t[4]){ 172U, 16U, 11U, 12U });
    printf("retval %d\n", retval);

    printf("packets_len %zu\n", packet_count(filtered));
    printf("packets %u\n", filtered->tail->index);
    printf("Magic number: 0x%x\n", get_header(filtered)->magic_number);

    // Check lengths of both packets
    printf("packet1 %d\n", get_packet(filtered, 0)->packet_header->orig_len == 66U);
    printf("packet2 %d\n", get_packet(filtered, 1)->packet_header->orig_len == 66U);
}

void demo2()
{
    struct capture_t capture[1];
    int ret = load_capture(capture, TEST_FILE);
    printf("retval %d\n", ret);
    printf("load ok\n");
    printf("packet_count %zu\n",packet_count(capture));
    for (size_t current_packet = 0; current_packet < packet_count(capture); current_packet++) {
        printf("packet-ok");
        struct packet_t *packet = get_packet(capture, current_packet);
        printf("packet_get-ok");
        print_packet_info(packet);
    }

    printf("Magic number: 0x%x\n", get_header(capture)->magic_number);
    printf("Total number of bytes transferred in this capture: %zu.\n", data_transfered(capture));
    printf("pocet paketu %zu\n",packet_count(capture));
    destroy_capture(capture);

    struct capture_t capture_one[1];
    int retval = load_capture(capture_one, TEST_FILE);
    printf("navrat retval %d\n",retval);

    printf("pocet paketu test %zu\n",packet_count(capture_one));

    printf("delka paketu1 %d\n",get_packet(capture_one, 0)->packet_header->orig_len == 93U);

    printf("delka paketu2 %d\n",get_packet(capture_one, 9)->packet_header->orig_len == 1514U);

    destroy_capture(capture_one);
}

void demo3() {
    struct capture_t capture[1];

    int retval = load_capture(capture, TEST_FILE);
    printf("navrat retval %d\n",retval);

    capture_t_item *item = capture->head;
    while (item != NULL) {
        printf("%d.%d.%d.%d -> ", item->packet->ip_header->src_addr[0], item->packet->ip_header->src_addr[1], item->packet->ip_header->src_addr[2], item->packet->ip_header->src_addr[3]);
        printf("%d.%d.%d.%d : ", item->packet->ip_header->dst_addr[0], item->packet->ip_header->dst_addr[1], item->packet->ip_header->dst_addr[2], item->packet->ip_header->dst_addr[3]);
        printf("index %d\n\n",item->index);
        item = item->next;
    }

    print_flow_stats(capture);


    printf("\n\n\n172.16.11.12 -> 74.125.19.17 : 3\n"
            "74.125.19.17 -> 172.16.11.12 : 2\n"
            "216.34.181.45 -> 172.16.11.12 : 3\n"
            "172.16.11.12 -> 216.34.181.45 : 2\n"
    );
    destroy_capture(capture);
}

void demo4() {
    struct capture_t capture[1];
    int from_one, from_two, from_three, from_four, from_mask;
    int to_one, to_two, to_three, to_four, to_mask;
    uint8_t source_ip[4] = {0, 0, 0, 0};
    uint8_t destination_ip[4] = {0, 0, 0, 0};
    load_capture( capture, TEST_FILE);
    struct capture_t filtered_one[1];
    filter_from_mask(capture, filtered_one, source_ip, 0);
    struct capture_t filtered_two[1];
    filter_to_mask(filtered_one, filtered_two, destination_ip, 0);
    print_longest_flow(filtered_two);
    destroy_capture(capture);
    destroy_capture(filtered_one);
    destroy_capture(filtered_two);
    }

int main()
{
    //demo1();

    // TODO: Uncomment this after you implement part 1 of the assignment
    //demoone();
    //demo2();
    //demo3();
    //demo4();
}
