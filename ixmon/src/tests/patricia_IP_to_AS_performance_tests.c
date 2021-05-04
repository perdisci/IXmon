#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <dirent.h>

#include "../libpatricia/patricia.h"

/*
  How to compile:
    gcc ../libpatricia/patricia.c -c -o patricia.o
    gcc patricia_IP_to_AS_performance_tests.c patricia.o -o patricia_IP_to_AS_performance_test
*/

int main() {
    patricia_tree_t* lookup_tree;
    lookup_tree = New_Patricia(32);
    
    make_and_lookup_uint32(lookup_tree, "46.36.216.0/21", 432432);
    make_and_lookup_uint32(lookup_tree, "159.253.16.0/23", 123);
    make_and_lookup_uint32(lookup_tree, "5.128.0.0/14", 1221321);
    make_and_lookup_uint32(lookup_tree, "8.12.0.0/16", 321);

    prefix_t prefix_for_search;
    prefix_for_search.family = AF_INET;
    prefix_for_search.bitlen = 32;
    patricia_node_t* node = NULL;

    int i_iter = 100;
    // Million operations
    int j_iter = 1000000;

    printf("Start tests\n");
    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);

    int i, j;
    struct in_addr ip_addr;
    struct in_addr prefix_subnet;
    char *subnet;
    
    for (j = 0; j < j_iter; j++) {
        for (i = 0; i < i_iter; i++) {
            // Random Pseudo IP
            prefix_for_search.add.sin.s_addr = i*j;
            patricia_node_t* node = patricia_search_best2(lookup_tree, &prefix_for_search, 1);

            if (node != NULL) {
                  // printf("Found IP\n");
                  ip_addr.s_addr = prefix_for_search.add.sin.s_addr;
                  //prefix_subnet = node->prefix->sin.s_addr;
                  char *subnet = prefix_toa(node->prefix);
                  u_short bitlen = node->prefix->bitlen;
                  uint32_t asn = node->uint32_data;
                  // printf("IP:%s | Prefix:%s | Mask-len:%hu | OriginAS:%d \n", inet_ntoa(ip_addr), subnet, bitlen, asn);
            }
        }
    }

    struct timespec finish_time;
    clock_gettime(CLOCK_REALTIME, &finish_time);

    unsigned long used_seconds = finish_time.tv_sec - start_time.tv_sec;
    unsigned long total_ops = i_iter * j_iter;
    float megaops_per_second = (float)total_ops / (float)used_seconds / 1000000;

    printf("Total time is %lu seconds total ops: %lu\nMillion of ops per second: %.1f\n",
           used_seconds, total_ops, megaops_per_second);

    Destroy_Patricia(lookup_tree, (void_fn_t)0);
}
