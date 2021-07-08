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
#include <cstdio>
#include <cstdlib>

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
  cout << "check final result one tag" << endl;
  // for (auto i=0; i<outputs.size(); ++i) {
  //   for (auto j=0; j<outputs[i].size(); ++j){
  //     cout << outputs[i][j] << ' ';
  //   }
  //   cout << " | " << eqtags[i] << endl;
  // }
  // cout << endl;
    std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    std::vector<std::vector<uint32_t>> out (outputs.size());
    if (context.role == SERVER) {
      std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 1));
      sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
      sockres->Close();
      for (auto i=0, j=0; i<outputs.size(); ++i) {
        bool tag = receive[j++];
        cout << (eqtags[i] ^ tag) << " : ";
        // out[i].push_back((eqtags[i] ^ tag));
        for (auto k=0; k<outputs[i].size(); ++k) {
          cout << ((uint32_t)(outputs[i][k] + receive[j])) << '|';
          out[i].push_back((uint32_t)(outputs[i][k] + receive[j]));
          j++;
        }
        cout << endl;
      }

      std::freopen("movielens_linear.dat", "w", stdout);
      vector<uint32_t> outattr = {2,4,5,6};
      for (auto i=0; i<out.size(); ++i) {
        for (auto j=0; j<outattr.size(); ++j) {
          cout << out[i][outattr[j]] << ',';
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

void CheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, vector<bool> anotags, ENCRYPTO::PsiAnalyticsContext &context) {
  cout << "check final result two tags" << endl;
    std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    if (context.role == SERVER) {
      std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 2));
      sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
      sockres->Close();
      for (auto i=0, j=0; i<outputs.size(); ++i) {
        bool tag = receive[j++];
        bool tag2 = receive[j++];
        cout << ((eqtags[i] ^ tag) & (anotags[i] ^ tag2)) << " : ";
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
        send.push_back(anotags[i]);
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

std::vector<std::vector<uint32_t>> loaddata(string filename, int bound = -1) {
    std::vector<std::vector<uint32_t>> weights;
    string path = "../../data/movielens/ml-1m/" + filename;
    cout << path << " ";

    if( access( path.c_str(), F_OK ) != -1 ) {
        cout << "find";
        // file exists
    } else {
        cout << "not exists" << endl;
        // file doesn't exist
    }

    ifstream fin(path.c_str(), ios::in);
    string str;
    while (getline(fin, str)) {
        std::vector<uint32_t> values;
        uint32_t val = 0;
        for (auto i=0; i<str.size(); ++i) {
            if (str[i] == ':') {
                ++i;
                values.push_back(val);
                val = 0;
            } else {
                if (str[i] == 'M') {
                  val = 1;
                } else if (str[i] == 'F') {
                  val = 0;
                } else {
                  val = val * 10 + (str[i] - '0');
                }
            }
        }
        values.push_back(val);
        if (filename == "movies.dat" && values[0] >= 50) continue;
        if (filename == "ratings.dat" && values[1] >= 50) continue;
        weights.push_back(values);
        if (weights.size() == bound) break;
    }
    fin.close();
    cout << ", find " << weights.size() << " tuples" << endl;
    return weights;
}

void testsharedjoin(ENCRYPTO::PsiAnalyticsContext &config) {

  std::vector<uint32_t> inputid = {0};
  std::vector<uint32_t> inputid2 = {2};
  std::vector<std::vector<uint32_t>> weights, weights2;
  std::vector<std::vector<uint32_t>> outputs;
  std::vector<bool> equaltags;
  // if (config.role == SERVER) {
  //   weights = {{1, 11, 2}, {2, 22, 2}, {3, 33, 1}, {4, 44, 7}, {5, 55, 9}, {6, 66, 3}, {7, 77, 1}, {8, 88, 1}};
  //   weights2 = {{0, 100}, {0, 200}, {0, 300}, {0, 400}, {0, 500}};
  //   SharedJoinServer(inputid2, weights, weights2, outputs, equaltags, config);
  // } else {
  //   weights = {{1,10}, {2,20}, {3,30}, {4, 40}, {5, 50}};
  //   SharedJoinClient(inputid, weights, outputs, equaltags, config);
  // }

  if (config.role == SERVER) {
    weights = {{1,11,111},{2,22,222},{3,33,333},{4,44,444},{5,55,555},{6,66,666},{7,77,777}};
    weights2 = {{0, 1000}, {0, 2000}, {0, 3000}};
    SharedJoinServer(inputid, weights, weights2, outputs, equaltags, config);
  } else {
    weights = {{1,10}, {2,20}, {3,30}};
    weights2 = {{0,0,0}, {0,0,0}, {0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}};
    SharedJoinClient(inputid, weights, weights2, outputs, equaltags, config);
  }

  for (auto i=0; i<outputs.size(); ++i) {
    for (auto j=0; j<outputs[i].size(); ++j) {
      cout << outputs[i][j] << ' ';
    }
    cout << endl;
  }
  CheckPhase(outputs, equaltags, config);
}

void MovielensLinearDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> data, users, movies, ratings;
  data = loaddata("users.dat");
  FilterColumns({0,1,2,3}, data, users);
  data = loaddata("movies.dat");
  FilterColumns({0}, data, movies);
  data = loaddata("ratings.dat");
  FilterColumns({0,1,2}, data, ratings);

  if (config.role == SERVER) {
    for (auto i=0; i<movies.size(); ++i) {
      for (auto j=0; j<movies[i].size(); ++j) {
        movies[i][j] = 0;
      }
    }
    for (auto i=0; i<users.size(); ++i) {
      for (auto j=0; j<users[i].size(); ++j) {
        users[i][j] =0;
      }
    }
  } else {
    for (auto i=0; i<ratings.size(); ++i) {
      for (auto j=0; j<ratings[i].size(); ++j) {
        ratings[i][j] = 0;
      }
    }
  }

  vector<vector<uint32_t>> RU, RUM, result, outputs;
  vector<bool> et1, et2, et;

  // Stage 1: R join U
  if (config.role == SERVER) {
      JoinServer({0}, ratings, RU, et1, config);
  } else {
      JoinClient({0}, users, ratings, RU, et1, config);
  }
  // CheckPhase(RU, et1, config);

  cout << "RU join finished" << endl;
  cout << "communication cost until now = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "time cost until now = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  // cout << "My RU result" << endl;
  // for (auto i=0; i<RU.size(); ++i) {
  //   for (auto j=0; j<RU[i].size(); ++j) {
  //     cout << RU[i][j] << ' ';
  //   }
  //   cout << endl;
  // }

  // Stage 2: RU join M
  if (config.role == SERVER) {
      JoinServer({1}, RU, RUM, et2, config);
  } else {
      JoinClient({0}, movies, RU, RUM, et2, config);
  }

  MergeTags(et1, et2, et, config);

  result = RUM;


  cout << "RU join M finished" << endl;
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;


  // PurificationCircuit(result, et, config);
  CheckPhase(result, et, config);
  // ObliviousReveal(result, et, outputs, config);
  // CheckPhase(outputs, et, config);

  // cout << "My RUM result" << endl;
  // for (auto i=0; i<RUM.size(); ++i) {
  //   for (auto j=0; j<RUM[i].size(); ++j) {
  //     cout << RUM[i][j] << ' ';
  //   }
  //   cout << endl;
  // }
}

void IRISDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> fact, dim;
  
  fact.resize(500);
  for (auto i=0; i<500; ++i) {
    fact[i].resize(5);
    for (auto j=0; j<5; ++j) {
      fact[i][j] = rand();
    }
  }

  dim.resize(20);
  for (auto i=0; i<20; ++i) {
    dim[i].resize(2);
    for (auto j=0; j<2; ++j) {
      dim[i][j] = rand();
    }
  }

  vector<vector<uint32_t>> r1, r2, r3, r4;
  vector<bool> et;

  if (config.role == SERVER) {
      JoinServer({0}, fact, r1, et, config);
  } else {
      JoinClient({0}, dim, fact, r1, et, config);
  }
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
  
  if (config.role == SERVER) {
      JoinServer({1}, r1, r2, et, config);
  } else {
      JoinClient({0}, dim, r1, r2, et, config);
  }
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  if (config.role == SERVER) {
      JoinServer({2}, r2, r3, et, config);
  } else {
      JoinClient({0}, dim, r2, r3, et, config);
  }
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  if (config.role == SERVER) {
      JoinServer({3}, r3, r4, et, config);
  } else {
      JoinClient({0}, dim, r3, r4, et, config);
  }

  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
}

void OULADDemo(PsiAnalyticsContext &config) {
  cout << "start " << endl;
  vector<vector<uint32_t>> fact, dim1, dim2;
  
  fact.resize(20000);
  for (auto i=0; i<20000; ++i) {
    fact[i].resize(2);
    for (auto j=0; j<2; ++j) {
      fact[i][j] = rand();
    }
  }

  dim1.resize(4951);
  for (auto i=0; i<4951; ++i) {
    dim1[i].resize(2);
    for (auto j=0; j<2; ++j) {
      dim1[i][j] = rand();
    }
  }

  dim2.resize(20000);
  for (auto i=0; i<20000; ++i) {
    dim2[i].resize(2);
    for (auto j=0; j<2; ++j) {
      dim2[i][j] = rand();
    }
  }

  vector<vector<uint32_t>> r1, r2;
  vector<bool> et;

  if (config.role == SERVER) {
      JoinServer({0}, fact, r1, et, config);
  } else {
      JoinClient({0}, dim1, fact, r1, et, config);
  }
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
  
  cout << endl << endl << endl;

  if (config.role == SERVER) {
      JoinServer({1}, fact, r2, et, config);
  } else {
      JoinClient({0}, dim2, fact, r2, et, config);
  }
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
}

void MNISTDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> fact, dim;
  
  fact.resize(1000);
  for (auto i=0; i<1000; ++i) {
    fact[i].resize(2);
    for (auto j=0; j<2; ++j) {
      fact[i][j] = rand();
    }
  }

  dim.resize(1000);
  for (auto i=0; i<1000; ++i) {
    dim[i].resize(2);
    for (auto j=0; j<2; ++j) {
      dim[i][j] = rand();
    }
  }

  vector<vector<uint32_t>> result(fact.size());
  vector<bool> et(fact.size());

  cout << "going to JOIN " << endl;

  if (config.role == SERVER) {
    JoinServer({0}, fact, result, et, config);
  } else if (config.role == CLIENT) {
    JoinClient({0}, dim, fact, result, et, config);
  }

  cout << "end join" << endl;

  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
  return;
}

int main(int argc, char **argv) {
    auto config = read_test_options(argc, argv);

    config.comm_cost = 0;
    config.total_time = 0;

    OULADDemo(config);
    // MNISTDemo(config);
    // IRISDemo(config);
    // MovielensLinearDemo(config);

    cout << config.comm_cost << endl;

    return EXIT_SUCCESS;
}
