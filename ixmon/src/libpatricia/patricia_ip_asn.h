
#ifndef __PATRICIA_IP_ASN_TREE__
#define __PATRICIA_IP_ASN_TREE__

#include <string>
#include "patricia.h"

std::string download_latest_bgp_rib_file();
std::string parse_bgp_rib_file();
patricia_tree_t* build_patricia_ans_tree_from_bgp_rib();

#endif
