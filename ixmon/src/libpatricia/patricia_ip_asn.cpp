/* 
 * Author: Roberto Perdisci (perdisci@cs.uga.edu)
 */ 

// #define _TEST_PATRICIA_IP_TO_ASN_
/* NOTE(Roberto): 
 * if _TEST_PATRICIA_IP_TO_ASN_ is defined, this can be tested as 
 * $ ln -s ../pyasn_util_download.py
 * $ gcc -c patricia.c
 * $ g++ --std=c++11 -o asn_tree patricia_ip_asn.cpp patricia.o
 * $ ./asn_tree
 */

#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <sstream>
#include <arpa/inet.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "patricia_ip_asn.h"

using namespace std;


#define RIB_FILE_NAME "/tmp/bgp_rib.bin"
#define BGP_OUT_FILE_NAME "/tmp/bgp_rib.txt"

#define RIB_FILE_REMOVE_COMMAND_PREFIX "rm "
#define RIB_DOWNLOAD_COMMAND "./pyasn_util_download.py --latest --outfile "
#define RIB_PARSING_COMMAND_PRFIX "bgpreader -d singlefile -w 0,-2 -o upd-file,"

/* Leverage exteranal tools to download and parse BGP RIB file.
 * Build a patricia tree to store (ip_prefix==>ASN) mappings.
 * - uses pyasn external python script to download latest BGP RIB file
 *   - https://github.com/hadiasghari/pyasn
 * - uses bgpreader to parse RIB file
 *   - https://bgpstream.caida.org/docs/tools/bgpreader
 */

string download_latest_bgp_rib_file() {

    // download BGP RIB file
    string rib_download_cmd;
    rib_download_cmd += RIB_DOWNLOAD_COMMAND;
    rib_download_cmd += RIB_FILE_NAME;

    cout << "rib_download_cmd = " << rib_download_cmd << endl;
    int s = system(rib_download_cmd.c_str());

    return RIB_FILE_NAME;
}

string parse_bgp_rib_file() {
    // parse RIB file
    string rib_parsing_cmd;
    rib_parsing_cmd += RIB_PARSING_COMMAND_PRFIX;
    rib_parsing_cmd += RIB_FILE_NAME;
    rib_parsing_cmd += " > ";
    rib_parsing_cmd += BGP_OUT_FILE_NAME;
    int s = system(rib_parsing_cmd.c_str());
    
    return BGP_OUT_FILE_NAME;
}

void remove_parsed_files() { 
    remove(RIB_FILE_NAME);
    remove(BGP_OUT_FILE_NAME);
}


patricia_tree_t* build_patricia_ans_tree_from_bgp_rib() {
    
    cout << "Downloading latest BGP RIB file..." << endl;
    string rib_file = download_latest_bgp_rib_file();

    cout << "Parsing BGP RIB file..." << endl;
    string bgp_out_file = parse_bgp_rib_file();

    // build patricia tree
    // we currently only handle IPv4
    cout << "Building IP-to-ASN patricia tree..." << endl;
    patricia_tree_t *ip4_as_tree;
    ip4_as_tree = New_Patricia(32);

    ifstream f(bgp_out_file);
    string line; 
    string prefix;
    string origin_asn_str;
    while (getline(f, line)) {
        try {

            /* BGP RIB format: 
             * see https://bgpstream.caida.org/docs/tools/bgpreader#elem
             *
             * <dump-type>|<elem-type>|<record-ts>|<project>|<collector>|
             * <peer-ASn>|<peer-IP>|<prefix>|<next-hop-IP>|<AS-path>|
             * <origin-AS>|<communities>|<old-state>|<new-state>
             */

            vector<string> toks;
            boost::trim_right(line);
            boost::split(toks, line, boost::is_any_of("|"));

            prefix = toks[7];
            origin_asn_str = toks[10];

            /* normalize origin_asn_str
             * example cases to be translated into integer:
             * {11831}
             * {65500,65501}
             */
            if(boost::starts_with(origin_asn_str,"{"))
                origin_asn_str.erase(0,1);
            if(boost::ends_with(origin_asn_str,"}"))
                origin_asn_str.erase(origin_asn_str.size()-1,1);
            if(origin_asn_str.find(",")!=string::npos) {
                vector<string> v;
                boost::split(v, origin_asn_str, boost::is_any_of(","));
                origin_asn_str = v[0]; // arbitrarily take the first ANS in the list
            }
            
            uint32_t origin_asn = stoul(origin_asn_str); 
            make_and_insert_uint32(ip4_as_tree, prefix.c_str(), origin_asn);
        }
        catch (std::exception& e) {
            cerr << "Error while parsing BGP RIB line: " << line << endl;
            cerr << "prefix = " << prefix << endl;
            cerr << "origin_asn_str = " << origin_asn_str << endl;
            cerr << e.what() << endl;
        }
    }

    remove_parsed_files();
    cout << "Done building IP-to-ASN patricia tree." << endl;
    
    return ip4_as_tree;
}


/* NOTE(Roberto): main() used only used for testing purposes */
#ifdef _TEST_PATRICIA_IP_TO_ASN_
int main() {

    patricia_tree_t* ip4_asn_tree = build_patricia_ans_tree_from_bgp_rib();
    patricia_node_t* p_node = NULL;

    prefix_t test_prefix;
    test_prefix.family = AF_INET;
    test_prefix.bitlen = 32;
    
    string ip = "128.192.1.1";
    
    if(!inet_pton(AF_INET, ip.c_str(), &test_prefix.add)) {
        perror ("Error convering IP address:");
        return 0;
    }

    cout << "Searching patricia tree for IP:" << ip << endl;
    p_node = patricia_search_best2(ip4_asn_tree, &test_prefix, 1);


    uint32_t asn = 0;
    if(p_node) 
        asn = p_node->uint32_data;
    cout << "IP " << ip << " belongs to ASN " << asn << endl;

    return 1;
}
#endif
