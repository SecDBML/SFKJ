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
  cout << "check final result one tag" << endl;
  // for (auto i=0; i<outputs.size(); ++i) {
  //   for (auto j=0; j<outputs[i].size(); ++j){
  //     cout << outputs[i][j] << ' ';
  //   }
  //   cout << " | " << eqtags[i] << endl;
  // }
  // cout << endl;
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

std::vector<std::vector<uint32_t>> loaddata(string filename, int bound = 2000) {
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
                val = val * 10 + (str[i] - '0');
            }
        }
        values.push_back(val);
        // if (filename == "users.dat" || filename == "movies.dat") {
        //   if (values[0] > bound) continue;
        // } else {
        //   if (values[0] > bound || values[1] > bound) continue;
        // }
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

void PlaintextMovieLensDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> users, movies, ratings;
  users = loaddata("users.dat");
  movies = loaddata("movies.dat");
  ratings = loaddata("ratings.dat");

  vector<vector<uint32_t>> RU, RUM, result, outputs;

  plaintext_join({0}, ratings, {0}, users, RU, config);

  cout << "RU join finished" << endl;
  cout << "communication cost until now = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "time cost until now = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  plaintext_join({1}, RU, {0}, movies, RUM, config);

  cout << "RU join M finished" << endl;
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  // for (auto i=0; i<RUM.size(); ++i) {
  //   for (auto j=0; j<RUM[i].size(); ++j) {
  //     cout << RUM[i][j] << ' ';
  //   }
  //   cout << endl;
  // }

  uint64_t SU, SM, SR, SRU, SRUM, number_of_OT;
  SU = users.size();
  SM = movies.size();
  SR = ratings.size();
  SRU = SU * SR;
  SRUM = SRU * SM;
  number_of_OT = SRU + SRUM;
  cout << endl << "GC cost " << endl;
  cout << "total time cost " << number_of_OT * 3 / 10000.0 * 0.35141 << " MB" << endl;
  cout << "total time cost " << number_of_OT /10000.0 * 23.4034 << " s" << endl;
  cout << endl << "GC with compaction cost " << endl;
  cout << "total time cost " << (SU * SR + SU * SM) * 3 / 10000.0 * 0.35141 << " MB" << endl;
  cout << "total time cost " << (SU * SR + SU * SM) /10000.0 * 23.4034 << " s" << endl;
}

void MovieLensDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> users, movies, ratings;
  users = loaddata("users.dat");
  movies = loaddata("movies.dat");
  ratings = loaddata("ratings.dat");
  // for (auto i=0; i<users.size(); ++i) {
  //   for (auto j=0; j<users[i].size(); ++j) {
  //     cout << users[i][j] << ' ';
  //   }
  //   cout << endl;
  // }
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

  vector<int32_t> filterids = {0,1,2,3,5,6,7,8,10,11};
  FilterColumns(filterids, RUM, result);


  cout << "RU join M finished" << endl;
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;


  // PurificationCircuit(result, et, config);
  // CheckPhase(result, et, config);
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

void MovielensLinearDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> users, movies, ratings;
  users = loaddata("users.dat");
  movies = loaddata("movies.dat");
  ratings = loaddata("ratings.dat");
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

  vector<int32_t> filterids = {0,1,2,3,5,6,7,8,10,11};
  FilterColumns(filterids, RUM, result);


  cout << "RU join M finished" << endl;
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;


  // PurificationCircuit(result, et, config);
  // CheckPhase(result, et, config);
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

std::vector<std::vector<uint32_t>> loadtpchdata(string filename, vector<uint32_t> filterindex) {
    std::vector<std::vector<uint32_t>> weights;
    string path = "../../data/tpch/data100M/" + filename;
    cout << path << " , ";

    if( access( path.c_str(), F_OK ) != -1 ) {
        cout << "find ";
        // file exists
    } else {
        cout << "not exists" << endl;
        // file doesn't exist
    }

    ifstream fin(path.c_str(), ios::in);
    string str;
    // ignore first three lines
    // getline(fin, str);
    // getline(fin, str);
    // getline(fin, str);
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
        if (weights.size() > 100) break;
    }
    cout << weights.size() << " tuples" << endl;
    fin.close();
    return weights;
}

void PlaintextTPCHDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> customer, lineitem, orders;
  customer = loadtpchdata("customer.tbl", {0, 1, 3});
  lineitem = loadtpchdata("lineitem.tbl", {0, 1, 2});
  orders = loadtpchdata("orders.tbl", {0, 1, 3});

  cout << "loading data finished ..." << endl;
  ServerClientSync(config);

  // SERVER holds customer & lineitem
  // CLIENT holds order

  vector<vector<uint32_t>> OC, LOC, outputs;
  
  plaintext_join({1}, orders, {0}, customer, OC, config);
  cout << "orders join customer finished" << endl;;
  cout << "communication cost until now = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "time cost until now = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  plaintext_join({0}, lineitem, {0}, OC, LOC, config);
  cout << "lineitem join OC finished" << endl;
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  uint64_t cussize, linsize, ordersize;
  uint64_t midsize, finalsize, optsize;
  cussize = customer.size();
  linsize = lineitem.size();
  ordersize = orders.size();
  midsize = cussize * ordersize;
  finalsize = midsize * linsize;
  optsize = linsize * ordersize;

  cout << endl << "GC cost " << endl;
  cout << "total communication cost " << (midsize * 3 + finalsize * 6) / 10000.0 * 0.35141 << " MB" << endl;
  cout << "total time cost " << (midsize * 3 + finalsize * 6) /10000.0 * 23.4034 << " s" << endl;
  cout << endl << "GC with compaction cost " << endl;
  cout << "total communication cost " << (midsize * 3 + optsize * 6) / 10000.0 * 0.35141 << " MB" << endl;
  cout << "total time cost " << (midsize * 3 + optsize * 6) /10000.0 * 23.4034 << " s" << endl;

  // for (auto i=0; i<LOC.size(); ++i) {
  //   for (auto j=0; j<LOC[i].size(); ++j) {
  //     cout << LOC[i][j] << ' ';
  //   }
  //   cout << endl;
  // }
}

void TPCHDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> customer, lineitem, orders;
  customer = loadtpchdata("customer.tbl", {0, 1, 3});
  lineitem = loadtpchdata("lineitem.tbl", {0, 1, 2});
  orders = loadtpchdata("orders.tbl", {0, 1, 3});

  if (config.role == SERVER) {
    for (auto i=0; i<orders.size(); ++i) {
      for (auto j=0; j<orders[i].size(); ++j) {
        orders[i][j] = 0;
      }
    }
  } else {
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
  }

  cout << "loading data finished ..." << endl;
  ServerClientSync(config);

  // SERVER holds customer & lineitem
  // CLIENT holds order

  vector<vector<uint32_t>> OC, LOC, outputs;
  vector<bool> eq1, eq2;
  
  if (config.role == CLIENT) {
    JoinServer({1}, orders, OC, eq1, config);
    // SharedJoinServer({1}, orders, customer, OC, eq1, config);
  } else {
    JoinClient({0}, customer, orders, OC, eq1, config);
    // SharedJoinClient({0}, customer, orders, OC, eq1, config);
  }
  // CheckPhase(OC, eq1, config);
  cout << "orders join customer finished" << endl;;
  cout << "communication cost until now = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "time cost until now = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;

  if (config.role == SERVER) {
    SharedJoinWithTagServer({0}, lineitem, OC, eq1, LOC, eq2, config);
  } else {
    SharedJoinWithTagClient({0}, OC, lineitem, eq1, LOC, eq2, config);
  }
  // PurificationCircuit(LOC, eq2, config);
  // CheckPhase(LOC, eq2, config);
  cout << "lineitem join OC finished" << endl;
  cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
  cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
}

std::vector<std::vector<uint32_t>> loadlineardata(string filename, vector<uint32_t> filterindex) {
    std::vector<std::vector<uint32_t>> weights;
    string path = "../../data/linear/" + filename;
    cout << path << " , ";

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
    while (getline(fin, str)) {
        std::vector<uint32_t> values;
        uint32_t val = 0;
        for (auto i=0; i<str.size(); ++i) {
            if (str[i] == ',') {
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
        // if (weights.size() > 100) break;
    }
    fin.close();
    
    return weights;
}

void LinearDemo(PsiAnalyticsContext &config) {
  vector<vector<uint32_t>> features, labels;
  features = loadlineardata("table1.dat", {0, 1, 2});
  labels = loadlineardata("table2.dat", {0, 1});

  if (config.role == SERVER) {
    for (auto i=0; i<labels.size(); ++i) {
      for (auto j=0; j<labels[i].size(); ++j) {
        labels[i][j] = 0;
      }
    }
  } else {
    for (auto i=0; i<features.size(); ++i) {
      for (auto j=0; j<features[i].size(); ++j) {
        features[i][j] = 0;
      }
    }
  }

  vector<vector<uint32_t>> outputs, results;
  vector<bool> eq;

  cout << features[0][0] << ' ' << features[0][1] << endl;
  
  if (config.role == SERVER) {
    JoinServer({0}, features, outputs, eq, config);
  } else {
    JoinClient({0}, labels, features, outputs, eq, config);
  }
  cout << "features join labels finished" << endl;;

  vector<int32_t> filterids = {1,2,4};
  FilterColumns(filterids, outputs, results);
  
  CheckPhase(results, eq, config);
  cout << "join finished" << endl;

  OutputCircuit(results, config);
}

void PuriDemo(ENCRYPTO::PsiAnalyticsContext config) {
    ServerClientSync(config);
    uint32_t neles = 10000, D = 13, nreal = 0;
    double epi = 1;
    vector<vector<uint32_t>> vals (neles);
    vector<bool> tags (neles);
    srand(time(0));
    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<D; ++j) {
          vals[i].push_back(i*10 + j);
        }
        if (config.role == SERVER) {
          tags[i] = (float(rand())/float(RAND_MAX)) < epi ? 1 : 0;
        } else {
          tags[i] = 0;
        }
        // cout << tags[i] << ' ';
    }
    // cout << endl;;

    // HalfCopyCircuit(vals, tags, config);
    // CompactionCircuit(vals, tags, config);
    // DuplicationCircuit(nreal, vals, tags, config);
    // PurificationCircuitMultiWires(vals, tags, config);

    // cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    // cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
    // config.comm_cost = 0;
    // config.total_time = 0;
    // PurificationCircuit(vals, tags, config);

    // GenerateDPNoise(500*7, 500, 7, 1, 1.0, config);
    // GenerateMultTriplet(neles, config);
    GenerateMultTriplet(10, 128, 784, config);
    // CheckPhase(vals, config);
    cout << "total communication cost = " << config.comm_cost / 1024.0 / 1024 << " MB" <<endl;
    cout << "total time cost = " << config.total_time / CLOCKS_PER_SEC << " s" <<endl;
}


int main(int argc, char **argv) {
  auto config = read_test_options(argc, argv);

  config.comm_cost = 0;
  config.total_time = 0;

  // testsharedjoin(config);

  // MovieLensDemo(config);
  // TPCHDemo(config);
  // LinearDemo(config);

  config.comm_cost = 0;
  config.total_time = 0;

  // PlaintextMovieLensDemo(config);
  // cout << endl;
  // PlaintextTPCHDemo(config);

  PuriDemo(config);

  // MovielensLinearDemo(config);

  cout << config.comm_cost << endl;

  return EXIT_SUCCESS;
}
