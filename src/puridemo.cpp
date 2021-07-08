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

using namespace std;
using namespace ENCRYPTO;

void ServerClientSync(ENCRYPTO::PsiAnalyticsContext context) {
  cout << "check server client linkage" << endl;
  std::unique_ptr<CSocket> sock = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
  uint8_t value = 0;
  if (context.role == SERVER) {
    sock -> Send(&value, sizeof(value));
  } else {
    sock -> Receive(&value, sizeof(value));
  }
  sock->Close();
  cout << "check server client linkage ended" << endl;
  return;
}

void CheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, ENCRYPTO::PsiAnalyticsContext &context) {
    cout << "Before purification circuit" << endl;
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

void CheckPhase(vector<vector<uint32_t>> outputs, ENCRYPTO::PsiAnalyticsContext &context) {
    cout << "After purification circuit" << endl;
    std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    if (context.role == SERVER) {
      std::vector<uint32_t> receive(outputs.size() * (outputs[0].size()));
      sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
      sockres->Close();
      for (auto i=0, j=0; i<outputs.size(); ++i) {
        for (auto k=0; k<outputs[i].size(); ++k) {
          cout << ((uint32_t)(outputs[i][k] + receive[j])) << '|';
          j++;
        }
        cout << endl;
      }
    } else {
      std::vector<uint32_t> send;
      for (auto i=0; i<outputs.size(); ++i) {
        for (auto j=0; j<outputs[i].size(); ++j) {
          send.push_back(outputs[i][j]);
        }
      }
      sockres->Send(send.data(), send.size() * sizeof(uint32_t));
      sockres->Close();
    }
}

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

void PuriDemo(ENCRYPTO::PsiAnalyticsContext config) {
    ServerClientSync(config);
    uint32_t neles = 100, D = 4, nreal = 0;
    vector<vector<uint32_t>> vals (neles);
    vector<bool> tags (neles);
    srand(time(0));
    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<D; ++j) {
          vals[i].push_back(i*10 + j);
        }
        if (config.role == SERVER) {
          tags[i] = rand() & 1;
        } else {
          tags[i] = 0;
        }
    }
    
    CheckPhase(vals, tags, config);

    PurificationCircuit(vals, tags, config);
    // PurificationCircuitMultiWires(vals, tags, config);

    CheckPhase(vals, config);

    cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
}


int main(int argc, char **argv) {
  auto config = read_test_options(argc, argv);
  config.comm_cost = 0;
  config.total_time = 0;
  PuriDemo(config);
  return EXIT_SUCCESS;
}
