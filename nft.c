#include <stdlib.h>
#include "string.h"
#include "capture.h"

int is_correct_load_mask(int mask)
{
    if (mask > 32) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr, "Failure - invalid number of arguments\n");
        return EXIT_FAILURE;
    }
    struct capture_t capture[1];
    int from_one, from_two, from_three, from_four, from_mask;
    int to_one, to_two, to_three, to_four, to_mask;
    if (sscanf( argv[2], "%d.%d.%d.%d/%d", &from_one, &from_two, &from_three, &from_four, &from_mask) != 5) {
        fprintf(stderr, "Failure - wrong address with mask\n");
        return EXIT_FAILURE;
    }
    uint8_t source_ip[4] = {from_one, from_two, from_three, from_four};
    if (is_correct_load_mask(from_mask)) {
        fprintf(stderr, "Failure - bad address or mask\n");
        return EXIT_FAILURE;
    }
    if (sscanf( argv[3], "%d.%d.%d.%d/%d", &to_one, &to_two, &to_three, &to_four, &to_mask) != 5) {
        fprintf(stderr, "Failure - wrong address with mask\n");
        return EXIT_FAILURE;
    }
    uint8_t destination_ip[4] = {to_one, to_two, to_three, to_four};
    if (is_correct_load_mask(from_mask)) {
        fprintf(stderr, "Failure - bad address or mask\n");
        return EXIT_FAILURE;
    }
    if (load_capture( capture, argv[1])) {
        return EXIT_FAILURE;
    }

    struct capture_t filtered_one[1];
    if(filter_from_mask(capture, filtered_one, source_ip, from_mask) == EXIT_FAILURE) {
        destroy_capture(capture);
        return EXIT_FAILURE;
    }
    struct capture_t filtered_two[1];
    if(filter_to_mask(filtered_one, filtered_two, destination_ip, to_mask) == EXIT_FAILURE) {
        destroy_capture(capture);
        destroy_capture(filtered_one);
        return EXIT_FAILURE;
    }
    if (strcmp( argv[4], "flowstats") == EXIT_SUCCESS) {
        if (print_flow_stats(filtered_two) != 0) {
            destroy_capture(capture);
            destroy_capture(filtered_one);
            destroy_capture(filtered_two);
            return EXIT_FAILURE;
        }
    } else if (strcmp( argv[4], "longestflow") == EXIT_SUCCESS) {
        if (print_longest_flow(filtered_two) != 0) {
            destroy_capture(capture);
            destroy_capture(filtered_one);
            destroy_capture(filtered_two);
            return EXIT_FAILURE;
        }
    } else {
        destroy_capture(capture);
        destroy_capture(filtered_one);
        destroy_capture(filtered_two);
        return EXIT_FAILURE;
    }
    destroy_capture(capture);
    destroy_capture(filtered_one);
    destroy_capture(filtered_two);
    return EXIT_SUCCESS;
}
