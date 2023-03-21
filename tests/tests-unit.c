#include "cut.h"

#include "../capture.h"
#include "../pcap.h"

#define TEST_FILE "test.pcap"

TEST(load_capture_basic)
{
    struct capture_t capture[1];

    int retval = load_capture(capture, TEST_FILE);
    ASSERT(retval == 0);

    CHECK(packet_count(capture) == 10U);

    // Check the length of the first packet
    CHECK(get_packet(capture, 0)->packet_header->orig_len == 93U);

    // Check the length of the last packet
    CHECK(get_packet(capture, 9)->packet_header->orig_len == 1514U);

    destroy_capture(capture);
}

TEST(filter_from_to_basic)
{
    struct capture_t capture[1];

    int retval = load_capture(capture, TEST_FILE);
    ASSERT(retval == 0);

    struct capture_t filtered[1];

    retval = filter_from_to(
            capture,
            filtered,
            (uint8_t[4]){ 74U, 125U, 19U, 17U },
            (uint8_t[4]){ 172U, 16U, 11U, 12U });
    ASSERT(retval == 0);

    CHECK(packet_count(filtered) == 2U);

    // Check lengths of both packets
    CHECK(get_packet(filtered, 0)->packet_header->orig_len == 66U);
    CHECK(get_packet(filtered, 1)->packet_header->orig_len == 66U);

    destroy_capture(capture);
    destroy_capture(filtered);
}

TEST(print_flow_stats)
{
    struct capture_t capture[1];

    int retval = load_capture(capture, TEST_FILE);
    ASSERT(retval == 0);

    print_flow_stats(capture);

    CHECK_FILE(
            stdout,
            "172.16.11.12 -> 74.125.19.17 : 3\n"
            "74.125.19.17 -> 172.16.11.12 : 2\n"
            "216.34.181.45 -> 172.16.11.12 : 3\n"
            "172.16.11.12 -> 216.34.181.45 : 2\n");

    destroy_capture(capture);
}
