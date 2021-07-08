#pragma once

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "ENCRYPTO_utils/crypto/crypto.h"
#include <ENCRYPTO_utils/parse_options.h>

#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/Channel.h"

#include "abycore/aby/abyparty.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"

#include <cassert>
#include <vector>

class multicom {
public:
    multicom(uint32_t id);
    // std::unique_ptr<CSocket> connect(uint32_t otherid);
    void testconnection(uint32_t otherid);
    void testconnection(std::string addr, uint16_t port, e_role role);
    uint32_t getpcnt() {return pcnt;}
    uint32_t getpid() {return pid;}
private:
    uint32_t pcnt, pid;
    // IOService ios;
    std::vector<std::string> paddress;
    std::vector<uint16_t> pport;
    // vector<Session> psession;
    // vector<Channel> pchannel;
    // std::vector<std::unique_ptr<CSocket>> psocket;
};