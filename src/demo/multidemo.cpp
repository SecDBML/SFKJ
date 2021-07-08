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
#include "utils/multicom.h"

using namespace std;
using namespace ENCRYPTO;

void CheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, ENCRYPTO::PsiAnalyticsContext context) {
  cout << "check final result one tag" << endl;
  for (auto i=0; i<outputs.size(); ++i) {
    for (auto j=0; j<outputs[i].size(); ++j){
      cout << outputs[i][j] << ' ';
    }
    cout << " | " << eqtags[i] << endl;
  }
  cout << endl;
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

void MultCheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, ENCRYPTO::PsiAnalyticsContext context) {
  cout << "check final result one tag" << endl;

  if (context.role == 0 || context.role == 1) {
      std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection("127.0.0.1", 9876, static_cast<e_role>(context.role));
      if (context.role == 0) {
        std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 1));
        sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
        sockres->Close();
        for (auto i=0, j=0; i<outputs.size(); ++i) {
          bool tag = receive[j++];
          eqtags[i] = eqtags[i] ^ tag;
          for (auto k=0; k<outputs[i].size(); ++k) {
            outputs[i][k] += receive[j++];
          }
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

  if (context.role == 0 || context.role == 2) {
    if (context.role == 2) {
      context.role = 1;
    }
    std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection("127.0.0.1", 9877, static_cast<e_role>(context.role));
      if (context.role == 0) {
        std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 1));
        sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
        sockres->Close();
        for (auto i=0, j=0; i<outputs.size(); ++i) {
          bool tag = receive[j++];
          eqtags[i] = eqtags[i] ^ tag;
          for (auto k=0; k<outputs[i].size(); ++k) {
            outputs[i][k] += receive[j++];
          }
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
      if (context.role == 1) {
        context.role = 2;
      }
  }

  if (context.role == 0) {
      for (auto i=0; i<outputs.size(); ++i) {
          cout << i << " : " << eqtags[i] << " | ";
          for (auto j=0; j<outputs[i].size(); ++j) {
            cout << outputs[i][j] << ',';
          }
          cout << endl;
      }
  }
}


void CheckPhase(vector<vector<uint32_t>> outputs, vector<bool> eqtags, vector<bool> anotags, ENCRYPTO::PsiAnalyticsContext context) {
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

std::vector<std::vector<uint32_t>> loaddata(string filename, int bound = 999999) {
    std::vector<std::vector<uint32_t>> weights;
    string path = "../../data/movielens/ml-1m/" + filename;
    cout << path << endl;

    if( access( path.c_str(), F_OK ) != -1 ) {
        cout << "find" << endl;
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
                val = val * 10 + (str[i] - '0');
            }
        }
        values.push_back(val);
        if (filename == "users.dat" || filename == "movies.dat") {
          if (values[0] > bound) continue;
        } else {
          if (values[0] > bound || values[1] > bound) continue;
        }
        weights.push_back(values);
        if (weights.size() > 10) break;
    }
    fin.close();
    cout << weights.size() << endl;
    return weights;
}

void testsharedjoin(ENCRYPTO::PsiAnalyticsContext config) {

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

void MovieLensDemo(PsiAnalyticsContext config) {
  cout << config.role << endl;

  multicom mcom(config.role);

  cout << "set up communication finished" << endl;

  vector<vector<uint32_t>> users, movies, ratings;
  users = loaddata("users.dat");
  movies = loaddata("movies.dat");
  ratings = loaddata("ratings.dat");
  if (config.role == 0) {
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
  } else if (config.role == 1) {
    for (auto i=0; i<ratings.size(); ++i) {
      for (auto j=0; j<ratings[i].size(); ++j) {
        ratings[i][j] = 0;
      }
    }
    for (auto i=0; i<users.size(); ++i) {
      for (auto j=0; j<users[i].size(); ++j) {
        users[i][j] =0;
      }
    }
  } else if (config.role == 2) {
    for (auto i=0; i<ratings.size(); ++i) {
      for (auto j=0; j<ratings[i].size(); ++j) {
        ratings[i][j] = 0;
      }
    }
    for (auto i=0; i<movies.size(); ++i) {
      for (auto j=0; j<movies[i].size(); ++j) {
        movies[i][j] = 0;
      }
    }
  }
  cout << "load data finished" << endl;
  // P0 holds ratings
  // P1 holds movies
  // P2 holds users

  // JOIN PHASE
  vector<vector<uint32_t>> RU, RUM, result, outputs;
  vector<bool> et1, et2, et;

  et1.resize(ratings.size());
  et2.resize(ratings.size());

      // notice to change config information when implement TRUE multiparty communication
      // here we only works on one laptop

  // R join U
  if (config.role == 0 || config.role == 2) {
    mcom.testconnection(2 - config.role);
    // string addr; uint32_t port;
    config.address = "127.0.0.1";
    config.port = 7777;
    if (config.role == 0) {
      JoinServer({0}, ratings, RU, et1, config);
    } else {
      JoinClient({0}, users, ratings, RU, et1, config);
    }
    CheckPhase(RU, et1, config);
  }
  cout << "RU join finished" << endl;

  // RU join M
  if (config.role == 0 || config.role == 1) {
    mcom.testconnection(1 - config.role);
    config.address = "127.0.0.1";
    config.port = 8888;
    if (config.role == 0) {
      JoinServer({1}, RU, RUM, et2, config);
    } else {
      RU.resize(ratings.size());
      for (auto i=0; i<RU.size(); ++i) {
        RU[i].resize(ratings[0].size() + users[0].size());
      }
      JoinClient({0}, movies, RU, RUM, et2, config);
    }
    CheckPhase(RUM, et2, config);
  }
  if (config.role == 0 || config.role == 2) {
    // maybe need extra OEP in special case
    // but here we only consider a simplier form: adding dummy attributes
    if (config.role == 2) {
      RUM.resize(RU.size());
      for (auto i=0; i<RUM.size(); ++i) {
        RUM[i] = RU[i];
        RUM[i].resize(RU[0].size() + movies[0].size());
      }
    }
  }
  cout << "RUM join finished" << endl;

  et.resize(RUM.size());
  MergeTags(et1, et2, et, mcom, config);

  cout << "update tags finished" << endl;

  cout << "Final Result: " << endl;
  for (auto i=0; i<RUM.size(); ++i) {
    cout << i << " : " << et[i] << " | ";
    for (auto j=0; j<RUM[i].size(); ++j) {
      printf("%12u ", RUM[i][j]);
    }
    cout << endl;
  }
}

std::vector<std::vector<uint32_t>> loadtpchdata(string filename, vector<uint32_t> filterindex) {
    std::vector<std::vector<uint32_t>> weights;
    string path = "../../data/tpch/" + filename;
    cout << path << endl;

    if( access( path.c_str(), F_OK ) != -1 ) {
        cout << "find" << endl;
        // file exists
    } else {
        cout << "not exists" << endl;
        // file doesn't exist
    }

    ifstream fin(path.c_str(), ios::in);
    string str;
    // ignore first three lines
    getline(fin, str);
    getline(fin, str);
    getline(fin, str);
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
        if (weights.size() > 1000) break;
    }
    fin.close();
    cout << weights.size() << endl;
    for (auto i=0; i<weights[0].size(); ++i) {
      cout << weights[0][i] << ' ';
    }
    cout << endl;
    return weights;
}

void TPCHDemo(PsiAnalyticsContext config) {
  cout << config.role << endl;
  multicom mcom(config.role);
  cout << "set up communication finished" << endl;

  vector<vector<uint32_t>> customer, lineitem, orders;

  customer = loadtpchdata("customer.tbl", {0, 1, 3});
  lineitem = loadtpchdata("lineitem.tbl", {0, 1, 2});
  orders = loadtpchdata("orders.tbl", {0, 1, 3});

  // customer = {{1, 10, 100}};
  // orders = {{11, 1, 1234}, {22, 2, 2345}};
  // lineitem = {{11, 111, 1111}, {22, 222, 2222}, {33, 333, 3333}};

  // customer = {{1, 10, 100}};
  // orders = {{11, 1, 1234}};
  // lineitem = {{11, 111, 1111}};

  if (config.role == 0) {
    for (auto i=0; i<customer.size(); ++i) {
      for (auto j=0; j<customer[i].size(); ++j) {
        customer[i][j] = 0;
      }
    }
    for (auto i=0; i<orders.size(); ++i) {
      for (auto j=0; j<orders[i].size(); ++j) {
        orders[i][j] = 0;
      }
    }
  } else if (config.role == 1) {
    for (auto i=0; i<customer.size(); ++i) {
      for (auto j=0; j<customer[i].size(); ++j) {
        customer[i][j] = 0;
      }
    }
    for (auto i=0; i<lineitem.size(); ++i) {
      for (auto j=0; j<lineitem[i].size(); ++j) {
        lineitem[i][j] = 0;
      }
    }
  } else {
    for (auto i=0; i<orders.size(); ++i) {
      for (auto j=0; j<orders[i].size(); ++j) {
        orders[i][j] = 0;
      }
    }
    for (auto i=0; i<lineitem.size(); ++i) {
      for (auto j=0; j<lineitem[i].size(); ++j) {
        lineitem[i][j] = 0;
      }
    }
  }

  // P0 holds lineitem
  // P1 holds orders
  // P2 holds customer

  vector<vector<uint32_t>> OC, LOC;
  vector<bool> eq1, eq2, eq3, resulteq;
  vector<uint32_t> oepindices;

  // orders join customer
  if (config.role == 1 || config.role == 2) {
    mcom.testconnection(3 - config.role);
    config.address = "127.0.0.1";
    config.port = 7777;
    if (config.role == 1) {
      JoinServer({1}, orders, OC, eq1, config);
    } else {
      JoinClient({0}, customer, orders, OC, eq1, config);
    }
  } else {
    eq1.resize(orders.size(), 0);
    OC.resize(orders.size());
    for (auto i=0; i<OC.size(); ++i) {
      OC[i].resize(orders[0].size() + customer[0].size());
    }
  }
  cout << "orders join customer finished" << endl;

    // cout << "OC Result: " << endl;
    // for (auto i=0; i<OC.size(); ++i) {
    //   cout << i << " : " << eq1[i] << " | ";
    //   for (auto j=0; j<OC[i].size(); ++j) {
    //     printf("%u,", OC[i][j]);
    //   }
    //   cout << endl;
    // }

  // lineitem join OC
  if (config.role == 0 || config.role == 1) {
    mcom.testconnection(1 - config.role);
    config.address = "127.0.0.1";
    config.port = 8888;
    if (config.role == 0) {
      SharedJoinWithTagServer({0}, lineitem, OC, eq1, LOC, eq2, oepindices, config);
    } else {
      SharedJoinWithTagClient({0}, OC, lineitem, eq1, LOC, eq2, oepindices, config);
    }
    cout << "           oep indices details : " ;
    for (auto i=0; i<oepindices.size(); ++i) {
      cout << oepindices[i] << ' ';
    }
    cout << endl;
  } else {
    eq1.resize(lineitem.size());
    eq2.resize(lineitem.size());
    LOC.resize(lineitem.size());
    for (auto i=0; i<LOC.size(); ++i) {
      LOC[i].resize(lineitem[0].size() + OC[0].size());
    }
  }

  // cout << "eq1 : ";
  // for (auto i=0; i<eq1.size(); ++i) {
  //   cout << eq1[i] << ' ';
  // }
  // cout << endl;

  eq3.resize(lineitem.size(), false);

  vector<vector<uint32_t>> inputweights, outputweights;
  if (config.role == 1 || config.role == 2) {
    cout << "oep p1 and p2" << endl;
    mcom.testconnection(3 - config.role);
    config.address = "127.0.0.1";
    config.port = 9090;
    if (config.role == 1) {
      config.role = 0;
      OEPServer(oepindices, outputweights, config, S_ARITH);
      config.role = 1;
    } else {
      config.role = 1;
      uint32_t outputsize = (uint32_t)(lineitem.size() * 2.27);
      inputweights.resize(outputsize);
      for (auto i=0; i<inputweights.size(); ++i) {
        if (i < OC.size()) {
          inputweights[i] = OC[i];
          inputweights[i].erase(inputweights[i].begin(), inputweights[i].begin() + 3);
          inputweights[i].push_back(eq1[i]);
        } else {
          inputweights[i].resize(4);
        }
      }
      OEPClient(inputweights, outputweights, config, S_ARITH);
      config.role = 2;
    }
  }
  if (config.role == 0 || config.role == 1) {
    // OEP Phase
    cout << "oep p0 and p1" << endl;
    mcom.testconnection(1 - config.role);
    config.address = "127.0.0.1";
    config.port = 9099;
    vector<vector<uint32_t>> tempweights;
    if (config.role == 0) {
      OEPServer(oepindices, tempweights, config, S_ARITH);
    } else {
      OEPClient(outputweights, tempweights, config, S_ARITH);
    }
    // reconstruct result
    for (auto i=0; i<LOC.size(); ++i) {
      for (auto j=0; j<tempweights[i].size() - 1; ++j) {
        LOC[i][j+6] += tempweights[i][j];
      }
      eq3[i] = eq3[i] ^ (static_cast<bool>(tempweights[i][tempweights[i].size() - 1] % 2));
    }
  }
  if (config.role == 0 || config.role == 2) {
    // OEP Phase
    cout << "oep p0 and p2" << endl;
    mcom.testconnection(2 - config.role);
    cout << "connection succeed" << endl;
    config.address = "127.0.0.1";
    config.port = 9009;
    vector<vector<uint32_t>> tempweights;
    if (config.role == 0) {
      OEPServer(oepindices, tempweights, config, S_ARITH);
    } else {
      config.role = 1;
      OEPClient(outputweights, tempweights, config, S_ARITH);
      config.role = 2;
    }
    // reconstruct result
    for (auto i=0; i<LOC.size(); ++i) {
      for (auto j=0; j<tempweights[i].size() - 1; ++j) {
        LOC[i][j+6] += tempweights[i][j];
      }
      eq3[i] = eq3[i] ^ (static_cast<bool>(tempweights[i][tempweights[i].size() - 1] % 2));
    }
  }
  cout << "lineitem join OC finished" << endl;

  //  cout << "eq3 : ";
  //   for (auto i=0; i<eq3.size(); ++i) {
  //     cout << eq3[i] << ' ';
  //   }
  //   cout << endl;
  

  if (config.role == 0 || config.role == 1) {
    for (auto i=0; i<eq3.size(); ++i) {
      eq3[i] = eq3[i] ^ eq1[i];
    }
  }

  // cout << "finial eq : ";
  // for (auto i=0; i<eq3.size(); ++i) {
  //   cout << eq3[i] << ' ' ;
  // }
  // cout << endl;

  MergeTags(eq2, eq3, resulteq, mcom, config);

    cout << "Final Result: " << endl;
    for (auto i=0; i<LOC.size(); ++i) {
      cout << i << " : " << eq3[i] << ' ' << eq2[i] << "  " << resulteq[i] << " | ";
      for (auto j=0; j<LOC[i].size(); ++j) {
        printf("%u,", LOC[i][j]);
      }
      cout << endl;
    }

  MultCheckPhase(LOC, resulteq, config);

}

int main(int argc, char **argv) {
  auto config = read_test_options(argc, argv);

  // MovieLensDemo(config);
  TPCHDemo(config);

  return EXIT_SUCCESS;
}
