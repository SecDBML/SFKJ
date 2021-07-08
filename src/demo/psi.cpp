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

#include <boost/program_options.hpp>

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "ENCRYPTO_utils/crypto/crypto.h"
#include <ENCRYPTO_utils/parse_options.h>
#include "abycore/aby/abyparty.h"

#include "common/psi_analytics.h"
#include "common/psi_analytics_context.h"
#include "OEP/OEP.h"
#include "Purify/PurificationCircuit.h"
// #include "aggregation/aggregation.h"
#include "join/join.h"
#include "join/twoserverjoin.h"
#include "sort/sort.h"

using namespace std;

void CheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, ENCRYPTO::PsiAnalyticsContext &context) {
  cout << "check final result" << endl;
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
  cout << "check final result" << endl;
    std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    if (context.role == SERVER) {
      std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 0));
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
  ("port,p",         po::value<decltype(context.port)>(&context.port)->default_value(8080),                         "Port of the server")
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

void testPSI(ENCRYPTO::PsiAnalyticsContext &config) {
  uint64_t elenumber = 0;
  std::vector<uint64_t> inputs;
  std::vector<std::vector<uint32_t>> weights;
  if (config.role == SERVER) {
    // elenumber = 5;
    // inputs = {1,3,7,11,14};
    // weights = {{1,11,111},{2,22,222},{3,33,333},{4,44,444},{5,55,555}};//,{6,66,666},{7,77,777},{8,88,888},{9,99,999},{10, 100, 1000}};
    elenumber = 7;
    inputs = {1,2,3,4,5,6,7};
  } else {
    elenumber = 3;
    inputs = {1,3,5};
    weights = {{1,10}, {3,30}, {5,50}};
    // inputs = {1,3,7,11,14};
  }

  //auto inputs = ENCRYPTO::GeneratePseudoRandomElements(elenumber, 16);

  cout << "input: " << elenumber << endl;
  for (auto i = 0; i < inputs.size(); ++i) {
      cout << inputs[i] << ' ';
  }
  cout << endl << flush;

  std::vector<bool> outputs;
  std::vector<uint64_t> output1s;
  std::vector<int32_t> orders;

  ENCRYPTO::PSI(inputs, config, output1s);
  ENCRYPTO::PSIpayload(inputs, weights, config, orders, outputs);

  std::cout << "PSI circuit successfully executed" << std::endl;
  PrintTimings(config);
}

void testObliviousPermutation(ENCRYPTO::PsiAnalyticsContext &config) {
  // ENCRYPTO::obliviousPermutation(config);
  uint32_t nele = 1600, weightcnt = 1;
  vector<vector<uint32_t>> weights(nele), values(nele);
  vector<uint32_t> indices(nele);
  for (uint32_t i=0; i<nele; ++i) {
    weights[i].resize(weightcnt);
    values[i].resize(weightcnt);
    for (uint32_t wid=0; wid<weightcnt; ++wid) {
      weights[i][wid] = (i+1) * 100 + wid;
    }
    indices[i] = nele - 1 - i;
  }
  for (uint32_t i=0; i<nele; ++i) {
    for (uint32_t wid=0; wid<weightcnt; ++wid) {
      cout << weights[i][wid] << ' ';
    }
    cout << endl;
  }
  ENCRYPTO::obliviousPermutation(weights, indices, values, config, S_ARITH);
  for (uint32_t i=0; i<nele; ++i) {
    for (uint32_t wid=0; wid<weightcnt; ++wid) {
      cout << values[i][wid] << ' ';
    }
    cout << endl;
  }
}

void testOEP(ENCRYPTO::PsiAnalyticsContext &config) {
  // ENCRYPTO::obliviousPermutation(config);
  uint32_t nele = 4, weightcnt = 4, mele = 8;
  vector<vector<uint32_t>> weights(nele), outputs(nele);
  vector<uint32_t> indices1 {3,2,1,0,3,2,2,1};
  vector<uint32_t> indices2 {1,0,2};
  vector<uint32_t> indices3 {1,1,1,1};
  for (uint32_t i=0; i<nele; ++i) {
    weights[i].resize(weightcnt);
    outputs[i].resize(weightcnt);
    for (uint32_t wid=0; wid<weightcnt; ++wid) {
      weights[i][wid] = (i+1) * 100 + wid;
      // weights[i][wid] = rand() % 2;
    }
  }
  for (uint32_t i=0; i<nele; ++i) {
    for (uint32_t wid=0; wid<weightcnt; ++wid) {
      cout << weights[i][wid] << ' ';
    }
    cout << endl;
  }
  if (config.role == SERVER) {
    ENCRYPTO::OEPServer(indices1, outputs, config, S_ARITH);
  } else {
    ENCRYPTO::OEPClient(weights, outputs, config, S_ARITH);
  }

  CheckPhase(outputs, config);
}

void testObExtOT(ENCRYPTO::PsiAnalyticsContext config) {
    uint32_t neles = 4;
    std::vector<uint32_t> m0 = {10, 20, 30, 40};
    std::vector<uint32_t> m1 = {100, 200, 300, 400};
    std::vector<bool> tag = {0,0,0,0};
    if (config.role == SERVER) {
      tag[0] = 1;
      tag[2] = 1;
    } else {
      tag[0] = 1;
      tag[1] = 1;
    }
    std::vector<uint32_t> mr(neles);

    oblivExtTranfer(m0, m1, tag, mr, config);
    for (uint32_t i=0; i<neles; ++i) {
      cout << mr[i] << endl;
    }
}

void testSharedPSI(ENCRYPTO::PsiAnalyticsContext config) {
  uint64_t elenumber = 0;
  std::vector<uint64_t> inputs;
  std::vector<std::vector<uint32_t>> weights;
  if (config.role == CLIENT) {
    elenumber = 7;
    inputs = {1,2,3,4,5,6,7};
    weights = {{1,11,111},{2,22,222},{3,33,333},{4,44,444},{5,55,555},{6,66,666},{7,77,777}};
  } else {
    elenumber = 5;
    inputs = {1,3,7,11,14};
    weights = {{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}};
  }

  //auto inputs = ENCRYPTO::GeneratePseudoRandomElements(elenumber, 16);

  cout << "input: " << elenumber << endl;
  for (auto i = 0; i < inputs.size(); ++i) {
      cout << inputs[i] << ' ';
  }
  cout << endl << flush;

  std::vector<bool> outputs;
  std::vector<int32_t> orders;
  // ENCRYPTO::PSI(inputs, config, outputs);
  ENCRYPTO::PSIsharedpayload(inputs, weights, config, orders, outputs);

  std::cout << "PSI circuit successfully executed" << std::endl;
  PrintTimings(config);
}

void testjoin(ENCRYPTO::PsiAnalyticsContext config) {

  std::vector<uint32_t> Aid = {2};
  std::vector<uint32_t> Bid = {0};
  std::vector<std::vector<uint32_t>> Atuples, Btuples;
  std::vector<std::vector<uint32_t>> outputs;

  Atuples = {{1, 11, 2}, {2, 22, 2}, {3, 33, 1}, {4, 44, 7}, {5, 55, 9}, {6, 66, 3}, {7, 77, 1}, {8, 88, 1}};  
  Btuples = {{1,10}, {2,20}, {3,30}, {4, 40}, {5, 50}};

  // plaintext_join(Aid, Atuples, Bid, Btuples, outputs, config);

  vector<bool> et;

  config.comm_cost = 0;
  config.total_time = 0;

  if (config.role == SERVER) {
    JoinServer({0}, Atuples, outputs, et, config);
  } else {
    JoinClient({0}, Btuples, Atuples, outputs, et, config);
  }

  cout << "communication cost until now = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "time cost until now = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  for (auto i=0; i<outputs.size(); ++i) {
    for (auto j=0; j<outputs[i].size(); ++j) {
      cout << outputs[i][j] << ' ';
    }
    cout << endl;
  }
  CheckPhase(outputs, config);
}

// void testsharedjoin(ENCRYPTO::PsiAnalyticsContext config) {

//   std::vector<uint32_t> inputid = {0};
//   std::vector<uint32_t> inputid2 = {2};
//   std::vector<std::vector<uint32_t>> weights, weights2;
//   std::vector<std::vector<uint32_t>> outputs;
//   std::vector<bool> equaltags;
//   // if (config.role == SERVER) {
//   //   weights = {{1, 11, 2}, {2, 22, 2}, {3, 33, 1}, {4, 44, 7}, {5, 55, 9}, {6, 66, 3}, {7, 77, 1}, {8, 88, 1}};
//   //   weights2 = {{0, 100}, {0, 200}, {0, 300}, {0, 400}, {0, 500}};
//   //   SharedJoinServer(inputid2, weights, weights2, outputs, equaltags, config);
//   // } else {
//   //   weights = {{1,10}, {2,20}, {3,30}, {4, 40}, {5, 50}};
//   //   SharedJoinClient(inputid, weights, outputs, equaltags, config);
//   // }

//   if (config.role == SERVER) {
//     weights = {{1,11,111},{2,22,222},{3,33,333},{4,44,444},{5,55,555},{6,66,666},{7,77,777}};
//     weights2 = {{0, 1000}, {0, 2000}, {0, 3000}};
//     SharedJoinServer(inputid, weights, weights2, outputs, equaltags, config);
//   } else {
//     weights = {{1,10}, {2,20}, {3,30}};
//     SharedJoinClient(inputid, weights, outputs, equaltags, config);
//   }

//   for (auto i=0; i<outputs.size(); ++i) {
//     for (auto j=0; j<outputs[i].size(); ++j) {
//       cout << outputs[i][j] << ' ';
//     }
//     cout << endl;
//   }
//   CheckPhase(outputs, equaltags, config);
// }

void testtsjoin(ENCRYPTO::PsiAnalyticsContext config) {
  vector<vector<uint32_t>> Atuples, Btuples, outputs;
  vector<bool> eqtags;
  Atuples = {{1, 10}, {2, 20}, {2, 21},{3, 30}, {4, 40}, {6, 60}, {6, 61}};
  Btuples = {{7, 100}, {2, 200}, {3, 300}, {5, 500}};
  TSJoin({0}, Atuples, {0}, Btuples, outputs, eqtags, config);
}

void testsharedjoinwithtags(ENCRYPTO::PsiAnalyticsContext config) {

  std::vector<uint32_t> inputid = {0};
  std::vector<uint32_t> inputid2 = {2};
  std::vector<std::vector<uint32_t>> Aweights, Bweights;
  std::vector<std::vector<uint32_t>> outputs;
  std::vector<bool> BTags, equaltags;
  // if (config.role == SERVER) {
  //   weights = {{1, 11, 2}, {2, 22, 2}, {3, 33, 1}, {4, 44, 7}, {5, 55, 9}, {6, 66, 3}, {7, 77, 1}, {8, 88, 1}};
  //   weights2 = {{0, 100}, {0, 200}, {0, 300}, {0, 400}, {0, 500}};
  //   SharedJoinServer(inputid2, weights, weights2, outputs, equaltags, config);
  // } else {
  //   weights = {{1,10}, {2,20}, {3,30}, {4, 40}, {5, 50}};
  //   SharedJoinClient(inputid, weights, outputs, equaltags, config);
  // }

  if (config.role == SERVER) {
    Aweights = {{1,11,111},{2,22,222},{3,33,333},{4,44,444},{5,55,555},{6,66,666},{7,77,777}};
    Bweights = {{0, 1000}, {0, 2000}, {0, 3000}, {0, 4000}};
    BTags = {0, 0, 1, 1};
    SharedJoinWithTagServer(inputid, Aweights, Bweights, BTags, outputs, equaltags, config);
  } else {
    Aweights = {{0,0,0}, {0,0,0}, {0,0,0}, {0,0,0}, {0,0,0}, {0,0,0}, {0,0,0}};
    Bweights = {{1,10}, {2,20}, {3,30}, {4, 40}};
    BTags = {0, 1, 0, 1};
    SharedJoinWithTagClient(inputid, Bweights, Aweights, BTags, outputs, equaltags, config);
  }

  for (auto i=0; i<outputs.size(); ++i) {
    for (auto j=0; j<outputs[i].size(); ++j) {
      cout << outputs[i][j] << ' ';
    }
    cout << endl;
  }
  CheckPhase(outputs, equaltags, config);
}

void testmergetag(ENCRYPTO::PsiAnalyticsContext config) {
  vector<bool> tag1, tag2, newtag;
  tag1 = {1, 0, 1, 0, 1};
  tag2 = {0, 1, 0, 1, 0};
  MergeTags(tag1, tag2, newtag, config);
  for (auto i=0; i<newtag.size(); ++i) {
    cout << tag1[i] << ' ' << tag2[i] << ' ' << newtag[i] << endl;
  }
  return;
}

void testoblreveal(ENCRYPTO::PsiAnalyticsContext config) {
  vector<bool> tag1, tag2;
  tag1 = {1, 0, 0, 0, 1};
  tag2 = {0, 0, 0, 0, 1};
  vector<vector<uint32_t>> weights = {{1, 11, 111}, {2, 22, 222}, {3, 33, 333}, {4, 44, 444}, {5, 55, 555}};
  vector<vector<uint32_t>> outputs;
  if (config.role == SERVER) {
    ObliviousReveal(weights, tag1, outputs, config);
  } else {
    ObliviousReveal(weights, tag2, outputs, config);
  }

  CheckPhase(outputs, tag1, config);

  return;
}

void testInnerProduct(ENCRYPTO::PsiAnalyticsContext config) {
  vector<bool> tag, output;
  if (config.role == SERVER) {
    tag = {1,0,0,1,0,1};
  } else {
    tag = {1,0,1,0,1,1};
  }
  BooleanInnerProduct(tag, output, config);
  for (auto i=0; i<tag.size(); ++i) {
    cout << i << ' ' << tag[i] << ' ' << output[i] << endl;
  }
}

// void testaggregation(ENCRYPTO::PsiAnalyticsContext config) {
//   vector<vector<uint32_t>> weights = {{1, 11, 111}, {3, 33, 333}, {7, 77, 123}, {1, 11, 222}, {5, 55, 555}, {3, 33, 123}};
//   if (config.role == CLIENT) {
//     weights = {{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}};
//   }
//   vector<vector<uint32_t>> outputs;
//   vector<bool> tags(6, false);

//   CheckPhase(weights, config);

//   if (config.role == SERVER) {
//     Aggregation({0, 1}, weights, outputs, tags, config);
//   } else {
//     Aggregation({0, 1}, weights, outputs, tags, config);
//   }

//   cout << "finished" << endl;

//   CheckPhase(outputs, config);

//   return;
// }

void testPurify(ENCRYPTO::PsiAnalyticsContext config) {
  uint32_t neles = 20, nreal = 0;
  vector<vector<uint32_t>> vals (neles);
  vector<bool> tags (neles);
  srand(time(0));
  for (auto i=0; i<neles; ++i) {
    vals[i].resize(5);
    for (auto j=0; j<5; ++j) {
      vals[i][j] = i * 100;
      if (config.role == CLIENT) {
        vals[i][j] = j;
      }
    }
    if (config.role == SERVER) {
      tags[i] = rand() % 2;
    } else {
      tags[i] = 0;
    }
    cout << tags[i] << ' ';
  }
  cout << endl;;

  // HalfCopyCircuit(vals, tags, config);
  // CompactionCircuit(vals, tags, config);
  // DuplicationCircuit(nreal, vals, tags, config);
  PurificationCircuit(vals, tags, config);
  // CheckPhase(vals, config);
}

void testsort(ENCRYPTO::PsiAnalyticsContext config) {
  uint32_t neles = 32, nreal = 0;
  vector<vector<uint32_t>> vals (neles);
  vector<bool> tags (neles);
  srand(time(0));
  for (auto i=0; i<neles; ++i) {
    vals[i].resize(5);
    for (auto j=0; j<5; ++j) {
      vals[i][j] = (rand() % 100) * 100;
      cout << vals[i][j] + j << ' ';
      if (config.role == CLIENT) {
        vals[i][j] = j;
      }
    }
    cout << endl;
  }

  // bitonicsort(vals, config);
  sortoep(vals, config, false);
  CheckPhase(vals, config);
}

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

int main(int argc, char **argv) {
  auto config = read_test_options(argc, argv);
  config.total_time = 0;
  config.comm_cost = 0;

  ServerClientSync(config);

  // testObliviousPermutation(config);
  

  // cout << "test psi " << endl;
  // testPSI(config);
  // cout << "test psi done " << endl;


  // cout << "test oep " << endl;
  // testOEP(config);
  // cout << "test oep done " << endl;
  // testObExtOT(config);
  // testSharedPSI(config);

  // testjoin(config);

  cout << "test join " << endl;
  testjoin(config);
  cout << "test join done " << endl;

  // testmergetag(config);
  // testoblreveal(config);

  // testInnerProduct(config);
  // testsharedjoinwithtags(config);

  // testaggregation(config);

  // testPurify(config);

  // test(config);

  // testsort(config);

  // testtsjoin(config);

  return EXIT_SUCCESS;
}
