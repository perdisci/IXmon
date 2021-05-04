/* 
 * IXmon is a tool for extracting aggregated traffic statistics from raw 
 * traffic flows, such as NetFlow traffic.
 * 
 * The code is based on the FastNetMon project. However, only the code needed
 * to parse flow information has been reused. All of FastNetMon's logic for
 * DoS attack detection has essentially been removed.
 * Future code cleaning will further removed unnecessary/unused FastNetMon
 * code from this project.
 *
 * FastNetMon Author: pavel.odintsov@gmail.com
 * https://github.com/pavel-odintsov/fastnetmon
 * License: GPLv2
 * (commit b9339d53115fd405644d03f59b7b5048e2342bb9)
 *
 * IXmon Author: Roberto Perdisci (perdisci@cs.uga.edu)
 *
 */

#ifndef FASTNETMON_TYPES_H
#define FASTNETMON_TYPES_H

#include <utility> // std::pair
#include <stdint.h> // uint32_t
#include <sys/time.h> // struct timeval
#include <netinet/in.h> // struct in6_addr

#include <string>
#include <map>
#include <vector>


// NOTE(Roberto): added includes
#include <unordered_map>
#include <functional>
#include <boost/functional/hash.hpp>
//

#include "packet_storage.h"

#define SUBNET_MASK_24 0xFFFFFF00

enum direction { INCOMING = 0, OUTGOING, INTERNAL, OTHER };



/* NOTE(Roberto): definition of ASN-to-INTERFACE matrix counters */

// NetFlow Interface unique ID
// notice that none of the fields by itslef can guarantee uniqueness
struct nf_if_idx {
    // TODO(Roberto): generalize to input traces other than NetFlows

    uint32_t src_id = 0; // Netflow's source ID
    uint32_t if_id = 0; // SNMP interface ID
    std::string nf_client_ip_addr; // IPv4/v6 address of machine that exports flows

    bool operator==(const nf_if_idx &r) const {
        return this->src_id == r.src_id && this->if_id == r.if_id &&
               this->nf_client_ip_addr == r.nf_client_ip_addr;
    }

    std::size_t hash() const {
        std::size_t h = 0;
        boost::hash_combine(h,std::hash<uint32_t>{}(src_id));
        boost::hash_combine(h,std::hash<uint32_t>{}(if_id));
        boost::hash_combine(h,std::hash<std::string>{}(nf_client_ip_addr));
        return h;
    }

    std::string str() const {
        std::string s;
        s += "\"nfif_id\": ";
            s += "{ \"source_id\": ";
                s += std::to_string(src_id) + ", ";
                s += "\"interface_id\": ";
                s += std::to_string(if_id) + ", ";
                s += "\"client_ip\": ";
                s += "\"" + nf_client_ip_addr + "\"";
            s += " }";
        return s;
    }
};
///////////////////////////////////////////////



///////////////////////////////////////////////
// AS to NetFlow Interface mapping
struct as_nfif_pair {

    uint32_t srcAS = 0; // AS number
    uint32_t srcIP24 = 0; // IP/24 subnet
    uint32_t dstAS = 0; // AS number
    uint32_t dstIP24 = 0; // IP/24 subnet
    nf_if_idx if_idx;  // unique interface index

    bool operator==(const as_nfif_pair &r) const {
        return this->srcAS == r.srcAS && 
               this->srcIP24 == r.srcIP24 && 
               this->dstAS == r.dstAS && 
               this->dstIP24 == r.dstIP24 && 
               this->if_idx == r.if_idx;
    }

    std::size_t hash() const {
        std::size_t h = 0;
        boost::hash_combine(h,std::hash<uint32_t>{}(srcAS));
        boost::hash_combine(h,std::hash<uint32_t>{}(srcIP24));
        boost::hash_combine(h,std::hash<uint32_t>{}(dstAS));
        boost::hash_combine(h,std::hash<uint32_t>{}(dstIP24));
        boost::hash_combine(h,if_idx.hash());
        return h;
    }

    std::string str() const {
        std::string s;
        s += "\"as_nfif_pair\": ";
            s += "{ \"srcAS\": ";
            s += std::to_string(srcAS);
            s += " , ";
            s += " \"srcIP24\": ";
            s += std::to_string(srcIP24);
            s += " , ";
            s += " \"dstAS\": ";
            s += std::to_string(dstAS);
            s += " , ";
            s += " \"dstIP24\": ";
            s += std::to_string(dstIP24);
            s += " , ";
            s += if_idx.str();
        s += " }";
        return s;
    }
};

namespace std {
    template<> struct hash<as_nfif_pair> {
        std::size_t operator()(as_nfif_pair const& p) const {
            return p.hash();
        }
    };

    template<> struct equal_to<as_nfif_pair> {
        bool operator()(const as_nfif_pair &l, const as_nfif_pair &r) const{
            return l == r;
        }
    };
}
///////////////////////////////////////////////




///////////////////////////////////////////////
struct as_as_pair {
    uint32_t srcAS = 0; // source AS number
    uint32_t srcIP24 = 0; // source IP/24 subnet
    uint32_t dstAS = 0; // destination AS number
    uint32_t dstIP24 = 0; // destination IP/24 subnet
    // NetFlow client address that reported the srcAS-to-dstAS traffic info
    std::string nf_client_addr;

    bool operator==(const as_as_pair &r) const {
        return this->srcAS == r.srcAS &&
	           this->srcIP24 == r.srcIP24 &&
	           this->dstAS == r.dstAS &&
	           this->dstIP24 == r.dstIP24 &&
	           this->nf_client_addr == r.nf_client_addr;
    }

    std::size_t hash() const {
        std::size_t h = 0;
        boost::hash_combine(h,std::hash<uint32_t>{}(srcAS));
        boost::hash_combine(h,std::hash<uint32_t>{}(srcIP24));
        boost::hash_combine(h,std::hash<uint32_t>{}(dstAS));
        boost::hash_combine(h,std::hash<uint32_t>{}(dstIP24));
	    boost::hash_combine(h,std::hash<std::string>{}(nf_client_addr));
        return h;
    }

    std::string str() const {
        std::string s;
        s += "\"as_as_pair\": ";
            s += "{ \"srcAS\": ";
            s += std::to_string(srcAS);
            s += ",";
            s += " \"srcIP24\": ";
            s += std::to_string(srcIP24);
            s += ",";
            s += " \"dstAS\": ";
            s += std::to_string(dstAS);
            s += ",";
            s += " \"dstIP24\": ";
            s += std::to_string(dstIP24);
            s += ",";
            s += " \"nf_client_addr\": \"";
            s += nf_client_addr;
            s += "\" }";
        return s;
    }
};


// specialization of std::hash and std::equal_to for as_as_pair
namespace std {
    template<> struct hash<as_as_pair> {
        std::size_t operator()(as_as_pair const& p) const {
            return p.hash();
        }
    };

    template<> struct equal_to<as_as_pair> {
        bool operator()(const as_as_pair &l, const as_as_pair &r) const {
            return l == r;
        }
    };
}
///////////////////////////////////////////////



// this will represent the values for each AS-to-PortID matrix cell
struct ix_traffic_counters {

    // total counters
    // uint64_t num_flows = 0;
    uint64_t num_packets = 0;
    uint64_t num_bytes = 0;

    // tcp counters
    // uint64_t tcp_flows = 0;
    uint64_t tcp_packets = 0;
    uint64_t tcp_syn_packets = 0;
    uint64_t tcp_bytes = 0;

    // uint64_t udp_flows = 0;
    uint64_t udp_packets = 0;
    uint64_t udp_bytes = 0;

    // uint64_t icmp_flows = 0;
    uint64_t icmp_packets = 0;
    uint64_t icmp_bytes = 0;

    // TCP port counters : port, (packets, syn_packets, bytes)
    std::unordered_map<uint16_t,std::tuple<uint64_t, uint64_t, uint64_t>> 
            tcp_sport_stats;
    std::unordered_map<uint16_t,std::tuple<uint64_t, uint64_t, uint64_t>> 
            tcp_dport_stats;

    // UDP port counters : port, (packets, bytes)
    std::unordered_map<uint16_t,std::tuple<uint64_t, uint64_t>> udp_sport_stats;
    std::unordered_map<uint16_t,std::tuple<uint64_t, uint64_t>> udp_dport_stats;

    std::string str() const {

        std::ostringstream s;
        s << "\"counters\": "
            << "[ "
            << num_packets << ", " << num_bytes << ", "
            << tcp_packets << ", " << tcp_syn_packets << ", "
            << tcp_bytes << ", "
            << udp_packets << ", " << udp_bytes << ", "
            << icmp_packets << ", " << icmp_bytes
            << " ], "
          << "\"tcp_sport_counters\": "
            << "[ ";
            for(const auto& p : tcp_sport_stats)
                s << "{\"" << p.first << "\": [" << std::get<0>(p.second) << ", "
                                             << std::get<1>(p.second) << ", "
                                             << std::get<2>(p.second) << "]},";
            s << " {} ], "
          << "\"tcp_dport_counters\": "
            << "[ ";
            for(const auto& p : tcp_dport_stats)
                s << "{\"" << p.first << "\": [" << std::get<0>(p.second) << ", "
                                             << std::get<1>(p.second) << ", "
                                             << std::get<2>(p.second) << "]},";
            s << " {} ], "
          << "\"udp_sport_counters\": "
            << "[ ";
            for(const auto& p : udp_sport_stats)
                s << "{\"" << p.first << "\": [" << std::get<0>(p.second) << ", "
                                             << std::get<1>(p.second) << "]},";
            s << " {} ], "
          << "\"udp_dport_counters\": "
            << "[ ";
            for(const auto& p : udp_dport_stats)
                s << "{\"" << p.first << "\": [" << std::get<0>(p.second) << ", "
                                             << std::get<1>(p.second) << "]},";
            s << " {} ]  "
          << "";
        return s.str();
    }
};


/* NOTE(Roberto): this serves as a sparse matrix representation
 * for the AS-to-PortID and AS-to-AS traffic stats */
using as_nfif_matrix_counters =
                std::unordered_map<as_nfif_pair, ix_traffic_counters>;
using as_as_matrix_counters =
                std::unordered_map<as_as_pair, ix_traffic_counters>;
/*************/


/* NOTE(Roberto): Added to store AS information into simple_packet */
class as_info {
    public:
    as_info() : src_as(0), dst_as(0) {}

    // NFv9 specs are defined in rfc3954
    // SRC_AS and DST_AS could be 2 or 4 bytes long (2 is the default)
    uint32_t src_as, dst_as;
};


class if_info {
    public:
    if_info() : in_idx(0), out_idx(0) {}

    // NFv9 specs are defined in rfc3954
    // OUTPUT_SNMP and INPUT_SNMP indicate the index of the output and input interfaces
    uint32_t in_idx, out_idx;
};
/*******/

// simplified packet struct for lightweight save into memory
class simple_packet {
    public:
    simple_packet()
    : sample_ratio(1), src_ip(0), dst_ip(0), source_port(0), destination_port(0), protocol(0),
      length(0), flags(0), number_of_packets(1), ip_fragmented(false), ip_protocol_version(4), ttl(0),
        packet_payload_pointer(NULL), packet_payload_length(0), packet_direction(OTHER) {

        ts.tv_usec = 0;
        ts.tv_sec = 0;
    }
    uint32_t sample_ratio;

    /* IPv4 */
    uint32_t src_ip;
    uint32_t dst_ip;
    /* IPv6 */
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;

    uint8_t ip_protocol_version; /* IPv4 or IPv6 */
    uint8_t ttl;
    uint16_t source_port;
    uint16_t destination_port;
    unsigned int protocol;
    uint64_t length;
    uint64_t number_of_packets; /* for netflow */
    uint8_t flags; /* tcp flags */
    bool ip_fragmented; /* If IP packet fragmented */
    struct timeval ts;
    void* packet_payload_pointer;
    int packet_payload_length;
    // We store packet direction here because direction calculation is very difficult task for cpu
    direction packet_direction;

    /* NOTE(Roberto) */
    as_info asinf; // src and dst AS numbers
    if_info ifinf; // information about input and output interfaces involved in routing the flow/packet
    uint32_t nf_source_id; // Scource_ID of NetFlow agent
    std::string nf_source_client_addr; // IP address of NetFlow agent
    /*******/
};

class logging_configuration_t {
    public:
        logging_configuration_t() :
            filesystem_logging(true), local_syslog_logging(false), remote_syslog_logging(false), remote_syslog_port(0) {}
        bool filesystem_logging;
        std::string filesystem_logging_path;

        bool local_syslog_logging;

        bool remote_syslog_logging;
        std::string remote_syslog_server;
        unsigned int remote_syslog_port;
};

typedef std::pair<uint32_t, uint32_t> subnet_t;
typedef std::vector<subnet_t> subnet_vector_t;

typedef std::map<subnet_t, std::string> subnet_to_host_group_map_t;
typedef std::map<std::string, subnet_vector_t> host_group_map_t;

typedef void (*process_packet_pointer)(simple_packet&);

// Enum with available sort by field
enum sort_type { PACKETS, BYTES, FLOWS };

// Attack types
enum attack_type_t {
    ATTACK_UNKNOWN = 1,
    ATTACK_SYN_FLOOD = 2,
    ATTACK_ICMP_FLOOD = 3,
    ATTACK_UDP_FLOOD = 4,
    ATTACK_IP_FRAGMENTATION_FLOOD = 5,
};

// Amplification types
enum amplification_attack_type_t {
    AMPLIFICATION_ATTACK_UNKNOWN = 1,
    AMPLIFICATION_ATTACK_DNS     = 2,
    AMPLIFICATION_ATTACK_NTP     = 3,
    AMPLIFICATION_ATTACK_SSDP    = 4,
    AMPLIFICATION_ATTACK_SNMP    = 5,
    AMPLIFICATION_ATTACK_CHARGEN = 6,
};

typedef struct {
    uint64_t bytes;
    uint64_t packets;
    uint64_t flows;
} total_counter_element;


// main data structure for storing traffic and speed data for all our IPs
class map_element {
    public:
    map_element()
    : in_bytes(0), out_bytes(0), in_packets(0), out_packets(0), tcp_in_packets(0), tcp_out_packets(0),
      tcp_in_bytes(0), tcp_out_bytes(0), tcp_syn_in_packets(0), tcp_syn_out_packets(0),
      tcp_syn_in_bytes(0), tcp_syn_out_bytes(0), udp_in_packets(0), udp_out_packets(0),
      udp_in_bytes(0), udp_out_bytes(0), in_flows(0), out_flows(0), fragmented_in_packets(0),
      fragmented_out_packets(0), fragmented_in_bytes(0), fragmented_out_bytes(0),
      icmp_in_packets(0), icmp_out_packets(0), icmp_in_bytes(0), icmp_out_bytes(0) {
    }
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint64_t in_packets;
    uint64_t out_packets;

    // Fragmented traffic is so recently used for attacks
    uint64_t fragmented_in_packets;
    uint64_t fragmented_out_packets;
    uint64_t fragmented_in_bytes;
    uint64_t fragmented_out_bytes;

    // Additional data for correct attack protocol detection
    uint64_t tcp_in_packets;
    uint64_t tcp_out_packets;
    uint64_t tcp_in_bytes;
    uint64_t tcp_out_bytes;

    // Additional details about one of most popular atatck type
    uint64_t tcp_syn_in_packets;
    uint64_t tcp_syn_out_packets;
    uint64_t tcp_syn_in_bytes;
    uint64_t tcp_syn_out_bytes;

    uint64_t udp_in_packets;
    uint64_t udp_out_packets;
    uint64_t udp_in_bytes;
    uint64_t udp_out_bytes;

    uint64_t icmp_in_packets;
    uint64_t icmp_out_packets;
    uint64_t icmp_in_bytes;
    uint64_t icmp_out_bytes;

    uint64_t in_flows;
    uint64_t out_flows;
};

// structure with attack details
class attack_details : public map_element {
    public:
    attack_details()
    : attack_protocol(0), attack_power(0), max_attack_power(0), average_in_bytes(0),
      average_out_bytes(0), average_in_packets(0), average_out_packets(0), average_in_flows(0),
      average_out_flows(0), ban_time(0), attack_direction(OTHER), unban_enabled(true) {

        customer_network.first = 0;
        customer_network.second = 0;
    }
    direction attack_direction;
    // first attackpower detected
    uint64_t attack_power;
    // max attack power
    uint64_t max_attack_power;
    unsigned int attack_protocol;

    // Average counters
    uint64_t average_in_bytes;
    uint64_t average_out_bytes;
    uint64_t average_in_packets;
    uint64_t average_out_packets;
    uint64_t average_in_flows;
    uint64_t average_out_flows;

    // time when we but this user
    time_t ban_timestamp;
    bool unban_enabled;
    int ban_time; // seconds of the ban

    subnet_t customer_network;

    packet_storage_t pcap_attack_dump;
};


typedef attack_details banlist_item;

// struct for save per direction and per protocol details for flow
typedef struct {
    uint64_t bytes;
    uint64_t packets;
    // will be used for Garbage Collection
    time_t last_update_time;
} conntrack_key_struct;

typedef uint64_t packed_session;
// Main mega structure for storing conntracks
// We should use class instead struct for correct std::map allocation
typedef std::map<packed_session, conntrack_key_struct> contrack_map_type;

class conntrack_main_struct {
    public:
    contrack_map_type in_tcp;
    contrack_map_type in_udp;
    contrack_map_type in_icmp;
    contrack_map_type in_other;

    contrack_map_type out_tcp;
    contrack_map_type out_udp;
    contrack_map_type out_icmp;
    contrack_map_type out_other;
};

typedef std::map<uint32_t, map_element> map_for_counters;
typedef std::vector<map_element> vector_of_counters;

typedef std::map<subnet_t, vector_of_counters> map_of_vector_counters;

// Flow tracking structures
typedef std::vector<conntrack_main_struct> vector_of_flow_counters;
typedef std::map<subnet_t, vector_of_flow_counters> map_of_vector_counters_for_flow;

typedef map_element subnet_counter_t;
typedef std::pair<subnet_t, subnet_counter_t> pair_of_map_for_subnet_counters_elements_t;
typedef std::map<subnet_t, subnet_counter_t> map_for_subnet_counters;



class packed_conntrack_hash {
    public:
    packed_conntrack_hash() : opposite_ip(0), src_port(0), dst_port(0) {
    }
    // src or dst IP
    uint32_t opposite_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

// This class consists of all configuration of global or per subnet ban thresholds
class ban_settings_t {
    public:
        ban_settings_t() : enable_ban(false),
            enable_ban_for_pps(false), enable_ban_for_bandwidth(false), enable_ban_for_flows_per_second(false),
            enable_ban_for_tcp_pps(false), enable_ban_for_tcp_bandwidth(false),
            enable_ban_for_udp_pps(false), enable_ban_for_udp_bandwidth(false),
            enable_ban_for_icmp_pps(false), enable_ban_for_icmp_bandwidth(false),
            ban_threshold_tcp_mbps(0), ban_threshold_tcp_pps(0),
            ban_threshold_udp_mbps(0), ban_threshold_udp_pps(0),
            ban_threshold_icmp_mbps(0), ban_threshold_icmp_pps(0),
            ban_threshold_mbps(0), ban_threshold_flows(0), ban_threshold_pps(0) {

        }
        bool enable_ban;

        bool enable_ban_for_pps;
        bool enable_ban_for_bandwidth;
        bool enable_ban_for_flows_per_second;

        bool enable_ban_for_tcp_pps;
        bool enable_ban_for_tcp_bandwidth;

        bool enable_ban_for_udp_pps;
        bool enable_ban_for_udp_bandwidth;

        bool enable_ban_for_icmp_pps;
        bool enable_ban_for_icmp_bandwidth;

        unsigned int ban_threshold_tcp_mbps;
        unsigned int ban_threshold_tcp_pps;

        unsigned int ban_threshold_udp_mbps;
        unsigned int ban_threshold_udp_pps;

        unsigned int ban_threshold_icmp_mbps;
        unsigned int ban_threshold_icmp_pps;

        unsigned int ban_threshold_mbps;
        unsigned int ban_threshold_flows;
        unsigned int ban_threshold_pps;
};


typedef std::map<std::string, ban_settings_t> host_group_ban_settings_map_t;

// data structure for storing data in Vector
typedef std::pair<uint32_t, map_element> pair_of_map_elements;

#endif
