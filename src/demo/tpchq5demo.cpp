//
// \file psi_analytics_example.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//

#include <cassert>
#include <iostream>
#include <unistd.h>

#include <boost/program_options.hpp>

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "ENCRYPTO_utils/crypto/crypto.h"
#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"
#include "OEP/OEP.h"
#include "join/join.h"
#include "utils/MurmurHash3.h"
#include "Purify/PurificationCircuit.h"
#include "join/twoserverjoin.h"

using namespace std;
using namespace ENCRYPTO;

auto read_test_options(int32_t argcp, char **argvp) {
    namespace po = boost::program_options;
    ENCRYPTO::PsiAnalyticsContext context;
    po::options_description allowed("Allowed options");
    std::string type;
    // clang-format off
    allowed.add_options()("help,h", "produce this message")
    ("role,r",         po::value<decltype(context.role)>(&context.role)->required(),                                  "Role of the node")
    ("bit-length,b",   po::value<decltype(context.bitlen)>(&context.bitlen)->default_value(61u),                      "Bit-length of the elements")
    ("epsilon,e",      po::value<decltype(context.epsilon)>(&context.epsilon)->default_value(1.27f),                   "Epsilon, a table size multiplier")
    ("address,a",      po::value<decltype(context.address)>(&context.address)->default_value("127.0.0.1"),            "IP address of the server")
    ("port,p",         po::value<decltype(context.port)>(&context.port)->default_value(7777),                         "Port of the server")
    ("threshold,c",    po::value<decltype(context.threshold)>(&context.threshold)->default_value(0u),                 "Show PSI size if it is > threshold")
    ("nmegabins,m",    po::value<decltype(context.nmegabins)>(&context.nmegabins)->default_value(1u),                 "Number of mega bins")
    ("functions,f",    po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(3u),                         "Number of hash functions in hash tables")
    ("threads,t",      po::value<decltype(context.nthreads)>(&context.nthreads)->default_value(1),                    "Number of threads");  // clang-format on

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argcp, argvp, allowed), vm);
        po::notify(vm);
    } catch (const boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<
                boost::program_options::required_option> > &e) {
        if (!vm.count("help")) {
        std::cout << e.what() << std::endl;
        std::cout << allowed << std::endl;
        exit(EXIT_FAILURE);
        }
    }

    if (vm.count("help")) {
        std::cout << allowed << "\n";
        exit(EXIT_SUCCESS);
    }
    return context;
}

void ServerClientSync(ENCRYPTO::PsiAnalyticsContext context) {
    std::unique_ptr<CSocket> sock = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    uint8_t value = 0;
    if (context.role == SERVER) {
        sock -> Send(&value, sizeof(value));
    } else {
        sock -> Receive(&value, sizeof(value));
    }
    sock->Close();
    return;
}

void CheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, ENCRYPTO::PsiAnalyticsContext &context) {
    std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    if (context.role == SERVER) {
        std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 1));
        sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
        sockres->Close();
        for (auto i=0, j=0; i<outputs.size(); ++i) {
            bool tag = receive[j++];
            cout << (eqtags[i] ^ tag) << " : ";
            for (auto k=0; k<outputs[i].size(); ++k) {
            cout << ((uint32_t)(outputs[i][k] + receive[j])) << '|';
            j++;
            }
            cout << endl;
        }
    } else {
        std::vector<uint32_t> send;
        for (auto i=0; i<outputs.size(); ++i) {
            send.push_back(eqtags[i]);
            for (auto j=0; j<outputs[i].size(); ++j) {
                send.push_back(outputs[i][j]);
            }
        }
        sockres->Send(send.data(), send.size() * sizeof(uint32_t));
        sockres->Close();
    }
}

void ArrayClear(vector<vector<uint32_t>> &array) {
    for (auto i=0; i<array.size(); ++i) {
        for (auto j=0; j<array[i].size(); ++j) {
            array[i][j] = 0;
        }
    }
}

std::vector<std::vector<uint32_t>> loadtpchdata(string filename, vector<uint32_t> filterindex, int bound = -1) {
    std::vector<std::vector<uint32_t>> weights;
    string path = "../../data/tpch/data100M/" + filename;
    cout << path << " , ";
    if( access( path.c_str(), F_OK ) != -1 ) {
        cout << "find ";
    } else {
        cout << "not exists" << endl;
    }

    ifstream fin(path.c_str(), ios::in);
    string str;
    while (getline(fin, str)) {
        std::vector<uint32_t> values;
        uint32_t val = 0;
        for (auto i=0; i<str.size(); ++i) {
            if (str[i] == '|') {
                values.push_back(val);
                val = 0;
            } else if (str[i] == '.') {
              continue;
            } else {
                val = val * 10 + (str[i] - '0');
            }
        }
        values.push_back(val);

        vector<uint32_t> tempvals;
        for (auto i=0; i<filterindex.size(); ++i) {
          tempvals.push_back(values[filterindex[i]]);
        }
        weights.push_back(tempvals);
        if (weights.size() == bound) break;
    }
    cout << weights.size() << " tuples" << endl;
    fin.close();
    return weights;
}

void TPCHQ5(PsiAnalyticsContext config) {
    vector<vector<uint32_t>> lineitem, orders, customer, nation, region, supplier;
    vector<vector<uint32_t>> NR, OC, SNR, OCNR, LSNR, LSOCNR;

    customer = loadtpchdata("customer.tbl", {0, 3});
    lineitem = loadtpchdata("lineitem.tbl", {0, 2});
    orders = loadtpchdata("orders.tbl", {0, 1});
    nation = loadtpchdata("nation.tbl", {0, 2});
    region = loadtpchdata("region.tbl", {0});
    supplier = loadtpchdata("supplier.tbl", {0, 3});

    // local computation
    plaintext_join({1}, orders, {0}, customer, OC);
    plaintext_join({1}, nation, {0}, region, NR);

    if (config.role == SERVER) {
        ArrayClear(supplier);
        ArrayClear(OC);
    } else {
        ArrayClear(lineitem);
        ArrayClear(NR);
    }

    PsiAnalyticsContext invcfg = config;
    invcfg.role = (config.role == SERVER) ? CLIENT : SERVER;

    vector<bool> eqtags;

    // S join NR
    // plaintext_join({1}, supplier, {0}, NR, SNR, invcfg);
    if (config.role == SERVER) {
        SharedJoinClient({0}, NR, supplier, SNR, eqtags, config);
    } else {
        SharedJoinServer({1}, supplier, NR, SNR, eqtags, config);
    }
    cout << " communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << " time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
    // OC join NR
    // plaintext_join({3}, OC, {0}, NR, OCNR, invcfg);
    if (config.role == SERVER) {
        SharedJoinClient({0}, NR, OC, OCNR, eqtags, config);
    } else {
        SharedJoinServer({3}, OC, NR, OCNR, eqtags, config);
    }
    cout << " communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << " time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
    // L join SNR
    // plaintext_join({1}, lineitem, {0}, SNR, LSNR, config);
    if (config.role == CLIENT) {
        SharedJoinClient({0}, SNR, lineitem, LSNR, eqtags, config);
    } else {
        SharedJoinServer({3}, lineitem, SNR, LSNR, eqtags, config);
    }
    cout << " communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << " time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
    // LSNR join OCNR
    // plaintext_join({0}, LSNR, {0}, OCNR, LSOCNR, config);
    if (config.role == CLIENT) {
        SharedJoinClient({0}, OCNR, LSNR, LSOCNR, eqtags, config);
    } else {
        SharedJoinServer({0}, LSNR, OCNR, LSOCNR, eqtags, config);
    }
    UpdateEQTag(LSOCNR, 4, 11, eqtags, config);
    cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
}

void PlaintextTPCHQ5(PsiAnalyticsContext config) {
    vector<vector<uint32_t>> lineitem, orders, customer, nation, region, supplier;
    vector<vector<uint32_t>> NR, OC, SNR, OCNR, LSNR, LSOCNR;

    customer = loadtpchdata("customer.tbl", {0, 3});
    lineitem = loadtpchdata("lineitem.tbl", {0, 2});
    orders = loadtpchdata("orders.tbl", {0, 1});
    nation = loadtpchdata("nation.tbl", {0, 2});
    region = loadtpchdata("region.tbl", {0});
    supplier = loadtpchdata("supplier.tbl", {0, 3});

    // local computation
    plaintext_join({1}, orders, {0}, customer, OC);
    plaintext_join({1}, nation, {0}, region, NR);

    if (config.role == SERVER) {
        ArrayClear(supplier);
        ArrayClear(OC);
    } else {
        ArrayClear(lineitem);
        ArrayClear(NR);
    }

    PsiAnalyticsContext invcfg = config;
    invcfg.role = (config.role == SERVER) ? CLIENT : SERVER;

    uint64_t GCcost, OGCcost, transgc, transogc;
    GCcost = OGCcost = transgc = transogc = 0;

    // S join NR
    plaintext_join({1}, supplier, {0}, NR, SNR, invcfg);
    GCcost += supplier.size() * NR.size();
    OGCcost += supplier.size() * NR.size();
    transgc += supplier.size() * NR.size() * NR[0].size();
    transogc += supplier.size() * NR.size() * NR[0].size();
    // OC join NR
    plaintext_join({3}, OC, {0}, NR, OCNR, invcfg);
    GCcost += OC.size() * NR.size();
    OGCcost += OC.size() * NR.size();
    transgc += OC.size() * NR.size() * NR[0].size();
    transogc += OC.size() * NR.size() * NR[0].size();
    // L join SNR
    plaintext_join({1}, lineitem, {0}, SNR, LSNR, config);
    GCcost += lineitem.size() * supplier.size() * NR.size();
    OGCcost += lineitem.size() * supplier.size();
    transgc += lineitem.size() * supplier.size() * NR.size() * SNR[0].size();
    transogc += lineitem.size() * supplier.size() * NR[0].size();
    // LSNR join OCNR
    plaintext_join({0}, LSNR, {0}, OCNR, LSOCNR, config);
    GCcost += lineitem.size() * OC.size() * NR.size();
    OGCcost += lineitem.size() * OC.size();
    transgc += lineitem.size() * OC.size() * NR.size() * OCNR[0].size();
    transogc += lineitem.size() * OC.size() * OCNR[0].size();
    
    // for (auto i=0; i<LSOCNR.size(); ++i) {
    //     for (auto j=0; j<LSOCNR[i].size(); ++j) {
    //         cout << LSOCNR[i][j] << ' ';
    //     }
    //     cout << endl;
    // }

    config.comm_cost += invcfg.comm_cost;
    config.total_time += invcfg.total_time;
    cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
    cout << endl << "GC cost " << endl;
    cout << "total comm cost " << transgc / 10000.0 * 0.35141 << " MB" << endl;
    cout << "total time cost " << GCcost /10000.0 * 23.4034 << " s" << endl;
    cout << endl << "GC with compaction cost " << endl;
    cout << "total comm cost " << transogc / 10000.0 * 0.35141 << " MB" << endl;
    cout << "total time cost " << OGCcost /10000.0 * 23.4034 << " s" << endl;
}

int main(int argc, char **argv) {
    auto config = read_test_options(argc, argv);
    PlaintextTPCHQ5(config);
    TPCHQ5(config);
    return EXIT_SUCCESS;
}
