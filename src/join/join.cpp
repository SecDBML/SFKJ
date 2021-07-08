#include "join.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

namespace ENCRYPTO {

    void CheckPhase(vector<vector<uint32_t>> outputs, ENCRYPTO::PsiAnalyticsContext &context, e_sharing type) {
        cout << "check result" << endl;
        std::unique_ptr<CSocket> sockres = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
        if (context.role == SERVER) {
            std::vector<uint32_t> receive(outputs.size() * (outputs[0].size() + 0));
            sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
            sockres->Close();
            for (auto i=0, j=0; i<outputs.size(); ++i) {
                for (auto k=0; k<outputs[i].size(); ++k) {
                    if (type == S_ARITH) {
                        cout << ((uint32_t)(outputs[i][k] + receive[j])) << '|';
                    } else {
                        cout << ((uint32_t)(outputs[i][k] ^ receive[j])) << '|';
                    }
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

    void ObliviousReveal(vector<vector<uint32_t>> tuples, vector<bool> tags, 
                        vector<vector<uint32_t>> &results,
                        PsiAnalyticsContext &context) {
        uint32_t neles = tuples.size();

        vector<vector<uint32_t>> tagtuples;
        for (auto i=0; i<neles; ++i) {
            vector<uint32_t> temp; temp.push_back(tags[i]);
            tagtuples.push_back(temp);
        }

        vector<uint32_t> orders(neles);
        for (auto i=0; i<neles; ++i) {
            orders[i] = i;
        }
        PRNG grng(sysRandomSeed());
        shuffle(orders.begin(), orders.end(), grng);
        // cout << "orders :  ";
        // for (auto i=0; i<neles; ++i) {
        //     cout << orders[i] << ' ';
        // }
        // cout << endl;

        PsiAnalyticsContext svrcontext = context;
        PsiAnalyticsContext clicontext = context;
        svrcontext.role = SERVER;
        clicontext.role = CLIENT;

        vector<vector<uint32_t>> output1, output2;
        vector<vector<uint32_t>> tag1, tag2;

        // OEP
        // cout << "OEP" << endl;
        if (context.role == SERVER) {
            OEPServer(orders, output1, svrcontext, S_ARITH);
            for (auto i=0; i<output1.size(); ++i) {
                for (auto j=0; j<output1[i].size(); ++j) {
                    output1[i][j] += tuples[orders[i]][j];
                }
            }
            // CheckPhase(output1, context);
            OEPClient(output1, output2, clicontext, S_ARITH);
            // CheckPhase(output2, context);
            OEPServer(orders, tag1, svrcontext, S_BOOL);
            for (auto i=0; i<tag1.size(); ++i) {
                tag1[i][0] ^= tagtuples[orders[i]][0];
            }
            // CheckPhase(tag1, context, S_BOOL);
            OEPClient(tag1, tag2, clicontext, S_BOOL);
            // CheckPhase(tag2, context, S_BOOL);
        } else {
            OEPClient(tuples, output1, clicontext, S_ARITH);
            // CheckPhase(output1, context);
            OEPServer(orders, output2, svrcontext, S_ARITH);
            for (auto i=0; i<output2.size(); ++i) {
                for (auto j=0; j<output2[i].size(); ++j) {
                    output2[i][j] += output1[orders[i]][j];
                }
            }
            // CheckPhase(output2, context);
            OEPClient(tagtuples, tag1, clicontext, S_BOOL);
            // CheckPhase(tag1, context, S_BOOL);
            OEPServer(orders, tag2, svrcontext, S_BOOL);
            for (auto i=0; i<tag2.size(); ++i) {
                tag2[i][0] ^= tag1[orders[i]][0];
            }
            // CheckPhase(tag2, context, S_BOOL);
        }

        // Reveal tag info
        // cout << "Reveal" << endl;
        vector<uint32_t> clrtags(neles), receive(neles);
        for (auto i=0; i<neles; ++i) {
            clrtags[i] = tag2[i][0];
        }
        std::unique_ptr<CSocket> sock = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
        if (context.role == SERVER) {
            sock->Receive(receive.data(), sizeof(uint32_t) * neles);
            for (auto i=0; i<neles; ++i) {
                clrtags[i] ^= receive[i];
            }
            sock->Send(clrtags.data(), sizeof(uint32_t) * neles);
        } else {
            sock->Send(clrtags.data(), sizeof(uint32_t) * neles);
            sock->Receive(clrtags.data(), sizeof(uint32_t) * neles);
        }
        sock->Close();

        // Maintain result
        for (auto i=0; i<neles; ++i) {
            if (clrtags[i]) {
                results.push_back(output2[i]);
            }
        }
    }

    void FilterColumns(vector<int32_t> filterids, vector<vector<uint32_t>> tuples, vector<vector<uint32_t>> &newtuples) {
        for (auto i=0; i<tuples.size(); ++i) {
            vector<uint32_t> values;
            for (auto j=0; j<filterids.size(); ++j) {
                values.push_back(tuples[i][filterids[j]]);
            }
            newtuples.push_back(values);
        }
    }

    void GenerateJoinKey(vector<uint32_t> joinkeyid, vector<vector<uint32_t>> tuples, vector<uint64_t> &joinkey) {
        joinkey.resize(tuples.size());
        uint64_t multkey = 10000079LL;
        for (auto i = 0; i < joinkey.size(); ++i) {
            uint64_t value = 0;
            for (auto j=0; j<joinkeyid.size(); ++j) {
                value = value * multkey + tuples[i][joinkeyid[j]];
            }
            joinkey[i] = value;
        }
    }

    void JoinServer(vector<uint32_t> joinkeyid, vector<vector<uint32_t>> tuples,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context) {
        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = SERVER;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(joinkeyid, tuples, joinkey);
        vector<uint64_t> sortedjoinkey = joinkey;
        sort(sortedjoinkey.begin(), sortedjoinkey.end());
        sortedjoinkey.erase(unique(sortedjoinkey.begin(), sortedjoinkey.end()), sortedjoinkey.end());
        unordered_map<uint64_t, uint32_t> keymapid;
        for (auto i=0; i<sortedjoinkey.size(); ++i) {
            keymapid[sortedjoinkey[i]] = i;
        }

    // communicate tuple size
        uint64_t outputsize = tuples.size();
        uint64_t svrattributes = tuples[0].size();
        uint64_t cliattributes = 0;
        // cout << "establish connection" << endl;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Send(&outputsize, sizeof(uint64_t));
        sock->Send(&svrattributes, sizeof(uint64_t));
        sock->Receive(&cliattributes, sizeof(uint64_t));
        // cout << "establish ended" << endl;
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<int32_t> orders;

        // cout << "PSI phase" << endl;
    // PSI
        PSIpayload(sortedjoinkey, tempweights, rolecontext, orders, tempequaltags);

    // OEP with correct lines
    // cout << "oep phase" << endl;
        uint32_t invordersize = *max_element(orders.begin(), orders.end());
        // cout << orders.size() << ' ' << invordersize << ' ' << *min_element(orders.begin(), orders.end()) << endl;
        vector<uint32_t> invorders(invordersize + 10);
        for (auto i=0; i<orders.size(); ++i) {
            if (orders[i] != -1) {
                invorders[orders[i]] = i;
            }
        }

        vector<uint32_t> oepindices(outputsize);
        oepindices.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            oepindices[i] = invorders[keymapid[joinkey[i]]];
        }
        // for (auto i=0; i<outputsize; ++i) {
        //     cout << i << ' ' << tuples[i][joinkeyid[0]] << ' ' << oepindices[i] << endl;
        // }
        vector<vector<uint32_t>> oepresults;
        vector<vector<uint32_t>> oeptagresults;

        OEPServer(oepindices, oepresults, rolecontext, S_ARITH);
        // cout << "oep tag server" << endl;
        OEPServer(oepindices, oeptagresults, rolecontext, S_BOOL);

        for (auto i=0; i<outputsize; ++i) {
            for (auto j=0; j<cliattributes; ++j) {
                oepresults[i][j] += tempweights[oepindices[i]][j];
            }
        }

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
    // cout << "connect two tables" << endl;
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = tuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][j+svrattributes] = oepresults[i][j];
            }
            // cout << tempequaltags[oepindices[i]] << ' ' << oeptagresults[i][0] << endl;
            equaltags[i] = tempequaltags[oepindices[i]] ^ ((bool)(oeptagresults[i][0] & 1));
        }

        auto end_time = clock();

        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
        // cout << "finished join" << endl;
    }

    void JoinClient(vector<uint32_t> joinkeyid, vector<vector<uint32_t>> tuples,
                    vector<vector<uint32_t>> servertuples,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context) {
        
        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = CLIENT;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(joinkeyid, tuples, joinkey);
    // communicate tuple size
        uint64_t outputsize = 0;
        uint64_t svrattributes = 0;
        uint64_t cliattributes = tuples[0].size();
        // cout << "establish connection" << endl;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Receive(&outputsize, sizeof(uint64_t));
        sock->Receive(&svrattributes, sizeof(uint64_t));
        sock->Send(&cliattributes, sizeof(uint64_t));
        // cout << "establish ended" << endl;
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<std::vector<uint32_t>> oepeqtags;

        tempweights.resize(tuples.size());
        for (auto i=0; i<tempweights.size(); ++i) {
            tempweights[i] = tuples[i];
        }
    // PSI
    // cout << "psi phase" << endl;
        std::vector<int32_t> orders;
        PSIpayload(joinkey, tempweights, rolecontext, orders, tempequaltags);

        oepeqtags.resize(tempequaltags.size());
        for (auto i=0; i<tempequaltags.size(); ++i) {
            oepeqtags[i].resize(1);
            oepeqtags[i][0] = tempequaltags[i];
        }

    // OEP
    // cout << "oep phase" << endl;
        vector<vector<uint32_t>> oepresults, oeptagresults;
        OEPClient(tempweights, oepresults, rolecontext, S_ARITH);
        OEPClient(oepeqtags, oeptagresults, rolecontext, S_BOOL);

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
    // cout << "connect two tables" << endl;
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            equaltags[i] = (bool)(oeptagresults[i][0] & 1);
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = servertuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][svrattributes + j] = oepresults[i][j];
            }
        }
        
        auto end_time = clock();
        
        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;

        // cout << "finished join" << endl;
    }


    void SharedJoinServer(vector<uint32_t> Ajoinkeyid, vector<vector<uint32_t>> Atuples, vector<vector<uint32_t>> Btuples,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                        ENCRYPTO::PsiAnalyticsContext &context) {
        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = SERVER;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(Ajoinkeyid, Atuples, joinkey);
        vector<uint64_t> sortedjoinkey = joinkey;
        sort(sortedjoinkey.begin(), sortedjoinkey.end());
        sortedjoinkey.erase(unique(sortedjoinkey.begin(), sortedjoinkey.end()), sortedjoinkey.end());
        unordered_map<uint64_t, uint32_t> keymapid;
        for (auto i=0; i<sortedjoinkey.size(); ++i) {
            keymapid[sortedjoinkey[i]] = i;
        }

    // communicate tuple size
        uint64_t outputsize = Atuples.size();
        uint64_t svrattributes = Atuples[0].size();
        uint64_t cliattributes = 0;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Send(&outputsize, sizeof(uint64_t));
        sock->Send(&svrattributes, sizeof(uint64_t));
        sock->Receive(&cliattributes, sizeof(uint64_t));
        sock->Close();
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<int32_t> orders;

        // cout << "PSI phase" << endl;

        tempweights.resize(Btuples.size());
        for (auto i=0; i<Btuples.size(); ++i) {
            tempweights[i] = Btuples[i];
        }

    // PSI
        PSIsharedpayload(sortedjoinkey, tempweights, rolecontext, orders, tempequaltags);

    // OEP with correct lines
    // cout << "oep phase" << endl;
        vector<uint32_t> invorders(orders.size());
        for (auto i=0; i<orders.size(); ++i) {
            if (orders[i] != -1) {
                invorders[orders[i]] = i;
            }
        }

        vector<uint32_t> oepindices(outputsize);
        oepindices.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            oepindices[i] = invorders[keymapid[joinkey[i]]];
        }

        // for (auto i=0; i<outputsize; ++i) {
        //     cout << i << ' ' << Atuples[i][Ajoinkeyid[0]] << ' ' << oepindices[i] << endl;
        // }
        vector<vector<uint32_t>> oepresults;
        vector<vector<uint32_t>> oeptagresults;

        OEPServer(oepindices, oepresults, rolecontext, S_ARITH);
        // cout << "oep tag server" << endl;
        OEPServer(oepindices, oeptagresults, rolecontext, S_BOOL);

        for (auto i=0; i<outputsize; ++i) {
            for (auto j=0; j<cliattributes; ++j) {
                oepresults[i][j] += tempweights[oepindices[i]][j];
            }
        }

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = Atuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][j+svrattributes] = oepresults[i][j];
            }
            // cout << tempequaltags[oepindices[i]] << ' ' << oeptagresults[i][0] << endl;
            equaltags[i] = tempequaltags[oepindices[i]] ^ ((bool)(oeptagresults[i][0] & 1));
        }
        auto end_time = clock();
        
        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
    }

    void SharedJoinClient(vector<uint32_t> Bjoinkeyid, vector<vector<uint32_t>> Btuples,
                        vector<vector<uint32_t>> Atuples,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                        ENCRYPTO::PsiAnalyticsContext &context) {

        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = CLIENT;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(Bjoinkeyid, Btuples, joinkey);
    
    // communicate tuple size
        uint64_t outputsize = 0;
        uint64_t svrattributes = 0;
        uint64_t cliattributes = Btuples[0].size();
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Receive(&outputsize, sizeof(uint64_t));
        sock->Receive(&svrattributes, sizeof(uint64_t));
        sock->Send(&cliattributes, sizeof(uint64_t));
        sock->Close();
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<std::vector<uint32_t>> oepeqtags;

        tempweights.resize(Btuples.size());
        for (auto i=0; i<tempweights.size(); ++i) {
            tempweights[i] = Btuples[i];
        }

    // PSI
        std::vector<int32_t> orders;
        PSIsharedpayload(joinkey, tempweights, rolecontext, orders, tempequaltags);

        oepeqtags.resize(tempequaltags.size());
        for (auto i=0; i<tempequaltags.size(); ++i) {
            oepeqtags[i].resize(1);
            oepeqtags[i][0] = tempequaltags[i];
        }

    // OEP
    // cout << "oep phase" << endl;
        vector<vector<uint32_t>> oepresults, oeptagresults;
        OEPClient(tempweights, oepresults, rolecontext, S_ARITH);
        OEPClient(oepeqtags, oeptagresults, rolecontext, S_BOOL);

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            equaltags[i] = (bool)(oeptagresults[i][0] & 1);
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = Atuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][svrattributes + j] = oepresults[i][j];
            }
        }
        auto end_time = clock();
        
        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
    }


    void SharedJoinWithTagServer(vector<uint32_t> Ajoinkeyid, vector<vector<uint32_t>> Atuples, 
                        vector<vector<uint32_t>> Btuples, vector<bool> Btags,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                        ENCRYPTO::PsiAnalyticsContext &context) {
        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = SERVER;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(Ajoinkeyid, Atuples, joinkey);
        vector<uint64_t> sortedjoinkey = joinkey;
        sort(sortedjoinkey.begin(), sortedjoinkey.end());
        sortedjoinkey.erase(unique(sortedjoinkey.begin(), sortedjoinkey.end()), sortedjoinkey.end());
        unordered_map<uint64_t, uint32_t> keymapid;
        for (auto i=0; i<sortedjoinkey.size(); ++i) {
            keymapid[sortedjoinkey[i]] = i;
        }

    // communicate tuple size
        uint64_t outputsize = Atuples.size();
        uint64_t svrattributes = Atuples[0].size();
        uint64_t cliattributes = 0;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Send(&outputsize, sizeof(uint64_t));
        sock->Send(&svrattributes, sizeof(uint64_t));
        sock->Receive(&cliattributes, sizeof(uint64_t));
        sock->Close();
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<int32_t> orders;

        // cout << "PSI phase" << endl;

        tempweights.resize(Btuples.size());
        for (auto i=0; i<Btuples.size(); ++i) {
            tempweights[i] = Btuples[i];
            tempweights[i].push_back((uint32_t) Btags[i]);
        }

    // PSI
        PSIsharedpayload(sortedjoinkey, tempweights, rolecontext, orders, tempequaltags);

        vector<bool> tempbtags(tempweights.size());
        for (auto i=0; i<tempweights.size(); ++i) {
            tempbtags[i] = (bool) (tempweights[i][tempweights[i].size() - 1] & 1);
            tempweights[i].pop_back();
        }

        vector<bool> tmpeqtags = tempequaltags;
        MergeTags(tmpeqtags, tempbtags, tempequaltags, rolecontext);

    // OEP with correct lines
    // cout << "oep phase" << endl;
        vector<uint32_t> invorders(orders.size());
        for (auto i=0; i<orders.size(); ++i) {
            if (orders[i] != -1) {
                invorders[orders[i]] = i;

            }
        }

        vector<uint32_t> oepindices(outputsize);
        oepindices.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            oepindices[i] = invorders[keymapid[joinkey[i]]];
        }

        // for (auto i=0; i<outputsize; ++i) {
        //     cout << i << ' ' << Atuples[i][Ajoinkeyid[0]] << ' ' << oepindices[i] << endl;
        // }
        vector<vector<uint32_t>> oepresults;
        vector<vector<uint32_t>> oeptagresults;

        OEPServer(oepindices, oepresults, rolecontext, S_ARITH);
        // cout << "oep tag server" << endl;
        OEPServer(oepindices, oeptagresults, rolecontext, S_BOOL);

        for (auto i=0; i<outputsize; ++i) {
            for (auto j=0; j<cliattributes; ++j) {
                oepresults[i][j] += tempweights[oepindices[i]][j];
            }
        }

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = Atuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][j+svrattributes] = oepresults[i][j];
            }
            // cout << tempequaltags[oepindices[i]] << ' ' << oeptagresults[i][0] << endl;
            equaltags[i] = tempequaltags[oepindices[i]] ^ ((bool)(oeptagresults[i][0] & 1));
        }
        // cout << "end join" << endl;
        auto end_time = clock();

        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
    }

    void SharedJoinWithTagClient(vector<uint32_t> Bjoinkeyid, vector<vector<uint32_t>> Btuples,
                        vector<vector<uint32_t>> Atuples, vector<bool> Btags,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                        ENCRYPTO::PsiAnalyticsContext &context) {

        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = CLIENT;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(Bjoinkeyid, Btuples, joinkey);
    
    // communicate tuple size
        uint64_t outputsize = 0;
        uint64_t svrattributes = 0;
        uint64_t cliattributes = Btuples[0].size();
        // cout << "establish connection   " << context.address << ':' << context.port << ' ' << rolecontext.role << endl;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Receive(&outputsize, sizeof(uint64_t));
        sock->Receive(&svrattributes, sizeof(uint64_t));
        sock->Send(&cliattributes, sizeof(uint64_t));
        sock->Close();
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<std::vector<uint32_t>> oepeqtags;

        tempweights.resize(Btuples.size());
        for (auto i=0; i<tempweights.size(); ++i) {
            tempweights[i] = Btuples[i];
            tempweights[i].push_back((uint32_t) Btags[i]);
        }

    // PSI
        std::vector<int32_t> orders;
        PSIsharedpayload(joinkey, tempweights, rolecontext, orders, tempequaltags);

        vector<bool> tempbtags(tempweights.size());
        for (auto i=0; i<tempweights.size(); ++i) {
            tempbtags[i] = (bool) (tempweights[i][tempweights[i].size() - 1] & 1);
            tempweights[i].pop_back();
        }

        vector<bool> tmpeqtags = tempequaltags;
        MergeTags(tmpeqtags, tempbtags, tempequaltags, rolecontext);

        oepeqtags.resize(tempequaltags.size());
        for (auto i=0; i<tempequaltags.size(); ++i) {
            oepeqtags[i].resize(1);
            oepeqtags[i][0] = tempequaltags[i];
        }

    // OEP
    // cout << "oep phase" << endl;
        vector<vector<uint32_t>> oepresults, oeptagresults;
        OEPClient(tempweights, oepresults, rolecontext, S_ARITH);
        OEPClient(oepeqtags, oeptagresults, rolecontext, S_BOOL);

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            equaltags[i] = (bool) (oeptagresults[i][0] & 1);
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = Atuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][svrattributes + j] = oepresults[i][j];
            }
        }
        auto end_time = clock();

        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
    }



    void SharedJoinWithTagServer(vector<uint32_t> Ajoinkeyid, vector<vector<uint32_t>> Atuples, 
                        vector<vector<uint32_t>> Btuples, vector<bool> &Btags,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags, vector<uint32_t> &oepindices, 
                        ENCRYPTO::PsiAnalyticsContext &context) {
        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = SERVER;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(Ajoinkeyid, Atuples, joinkey);
        vector<uint64_t> sortedjoinkey = joinkey;
        sort(sortedjoinkey.begin(), sortedjoinkey.end());
        sortedjoinkey.erase(unique(sortedjoinkey.begin(), sortedjoinkey.end()), sortedjoinkey.end());
        unordered_map<uint64_t, uint32_t> keymapid;
        for (auto i=0; i<sortedjoinkey.size(); ++i) {
            keymapid[sortedjoinkey[i]] = i;
        }

    // communicate tuple size
        uint64_t outputsize = Atuples.size();
        uint64_t svrattributes = Atuples[0].size();
        uint64_t cliattributes = 0;
        // cout << "establish connection   " << context.address << ':' << context.port << ' ' << rolecontext.role << endl;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Send(&outputsize, sizeof(uint64_t));
        sock->Send(&svrattributes, sizeof(uint64_t));
        sock->Receive(&cliattributes, sizeof(uint64_t));
        sock->Close();
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<int32_t> orders;

        // cout << "PSI phase" << endl;

        tempweights.resize(Btuples.size());
        for (auto i=0; i<Btuples.size(); ++i) {
            tempweights[i] = Btuples[i];
            tempweights[i].push_back((uint32_t) Btags[i]);
            // cout << "input b tags " << i << " : " << Btags[i] << ' ' << tempweights[i][tempweights[i].size() - 1] << endl;
        }

    // PSI
        vector<uint32_t> perm;
        PSIsharedpayload(sortedjoinkey, tempweights, rolecontext, orders, perm, tempequaltags);

    // OEP with correct lines
    // cout << "oep phase" << endl;
        vector<uint32_t> invorders(orders.size());
        for (auto i=0; i<orders.size(); ++i) {
            if (orders[i] != -1) {
                invorders[orders[i]] = i;
            }
        }

        oepindices.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            oepindices[i] = invorders[keymapid[joinkey[i]]];
        }

        // for (auto i=0; i<outputsize; ++i) {
        //     cout << i << ' ' << Atuples[i][Ajoinkeyid[0]] << ' ' << oepindices[i] << endl;
        // }
        vector<vector<uint32_t>> oepresults;
        vector<vector<uint32_t>> oeptagresults;

        OEPServer(oepindices, oepresults, rolecontext, S_ARITH);
        // cout << "oep tag server" << endl;
        OEPServer(oepindices, oeptagresults, rolecontext, S_BOOL);

        for (auto i=0; i<outputsize; ++i) {
            for (auto j=0; j<oepresults[i].size(); ++j) {
                oepresults[i][j] += tempweights[oepindices[i]][j];
            }
        }

        // for (auto i=0; i<oepindices.size(); ++i) {
        //     cout << oepindices[i] << ' ';
        // }
        // cout << endl;
        // for (auto i=0; i<perm.size(); ++i) {
        //     cout << perm[i] << ' ';
        // }
        // cout << endl;

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        Btags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = Atuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][j+svrattributes] = oepresults[i][j];
            }
            // cout << "equal tags: " << i << ' ' << tempequaltags[oepindices[i]] << ' ' << oeptagresults[i][0] << endl;
            equaltags[i] = tempequaltags[oepindices[i]] ^ ((bool)(oeptagresults[i][0] & 1));
            // cout << "b tag " << i << " : " << oepresults[i][oepresults[i].size() - 1] << ' ' << oepresults[i][oepresults[i].size() - 1] % 2 << endl;
            Btags[i] = static_cast<bool> (oepresults[i][oepresults[i].size() - 1] & 1);
        }

        for (auto i=0; i<outputsize; ++i) {
            oepindices[i] = perm[oepindices[i]];
        }
        // cout << "end join" << endl;
        auto end_time = clock();

        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
    }


    void SharedJoinWithTagClient(vector<uint32_t> Bjoinkeyid, vector<vector<uint32_t>> Btuples,
                        vector<vector<uint32_t>> Atuples, vector<bool> &Btags,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags, vector<uint32_t> &oepindices, 
                        ENCRYPTO::PsiAnalyticsContext &context) {

        PsiAnalyticsContext rolecontext = context;
        rolecontext.role = CLIENT;

        auto start_time = clock();

        vector<uint64_t> joinkey;
        GenerateJoinKey(Bjoinkeyid, Btuples, joinkey);
    
    // communicate tuple size
        uint64_t outputsize = 0;
        uint64_t svrattributes = 0;
        uint64_t cliattributes = Btuples[0].size();
        // cout << "establish connection   " << context.address << ':' << context.port << ' ' << rolecontext.role << endl;
        auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(rolecontext.role));
        sock->Receive(&outputsize, sizeof(uint64_t));
        sock->Receive(&svrattributes, sizeof(uint64_t));
        sock->Send(&cliattributes, sizeof(uint64_t));
        sock->Close();
        uint64_t outputattributes = svrattributes + cliattributes;

        // cout << "communicate round finished " << outputsize << ' ' << outputattributes << endl;

        std::vector<std::vector<uint32_t>> tempweights;
        std::vector<bool> tempequaltags;
        std::vector<std::vector<uint32_t>> oepeqtags;

        tempweights.resize(Btuples.size());
        for (auto i=0; i<tempweights.size(); ++i) {
            tempweights[i] = Btuples[i];
            tempweights[i].push_back((uint32_t) Btags[i]);
        }

    // PSI
        std::vector<int32_t> orders;
        std::vector<uint32_t> perm;
        PSIsharedpayload(joinkey, tempweights, rolecontext, orders, perm, tempequaltags);

        // first permutation from CLIENT
        oepindices = perm;

        oepeqtags.resize(tempequaltags.size());
        for (auto i=0; i<tempequaltags.size(); ++i) {
            oepeqtags[i].resize(1);
            oepeqtags[i][0] = tempequaltags[i];
        }

    // OEP
    // cout << "oep phase" << endl;
        vector<vector<uint32_t>> oepresults, oeptagresults;
        OEPClient(tempweights, oepresults, rolecontext, S_ARITH);
        OEPClient(oepeqtags, oeptagresults, rolecontext, S_BOOL);

        // cout << "finished oep" << endl;
        // for (auto i=0; i<outputsize; ++i) {
        //     for (auto j=0; j<oepresults[i].size(); ++j) {
        //         cout << oepresults[i][j] << ' ';
        //     }
        //     cout << endl;
        // }

    // connect two tables
        outputs.resize(outputsize);
        equaltags.resize(outputsize);
        Btags.resize(outputsize);
        for (auto i=0; i<outputsize; ++i) {
            // cout << "equal tags: " << i << ' ' << oeptagresults[i][0] << endl;
            equaltags[i] = (bool)(oeptagresults[i][0] & 1);
            // cout << "b tag " << i << " : " << oepresults[i][oepresults[i].size() - 1] << ' ' << oepresults[i][oepresults[i].size() - 1] % 2 << endl;
            Btags[i] = static_cast<bool> (oepresults[i][oepresults[i].size() - 1] & 1);
            outputs[i].resize(outputattributes);
            for (uint32_t j=0; j<svrattributes; ++j) {
                outputs[i][j] = Atuples[i][j];
            }
            for (uint32_t j=0; j<cliattributes; ++j) {
                outputs[i][svrattributes + j] = oepresults[i][j];
            }
        }
        auto end_time = clock();

        context.total_time += (end_time - start_time) ;
        context.comm_cost += rolecontext.comm_cost;
    }

    void plaintext_join(vector<uint32_t> Ajoinedid, vector<vector<uint32_t>> Atuples,
                    vector<uint32_t> Bjoinedid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> &outputs, ENCRYPTO::PsiAnalyticsContext &context) {
        std::unique_ptr<CSocket> sock = ENCRYPTO::EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
        auto start_time = clock();
        if (context.role == CLIENT) {
            vector<uint32_t> senddata;
            for (auto i=0; i<Btuples.size(); ++i) {
                senddata.insert(senddata.end(), Btuples[i].begin(), Btuples[i].end());
            }
            sock->Send(senddata.data(), senddata.size() * sizeof(uint32_t));
        } else {
            vector<uint32_t> receivedata (Btuples.size() * Btuples[0].size());
            sock->Receive(receivedata.data(), receivedata.size() * sizeof(uint32_t));
            // cout << "receivedata : ";
            // for (auto i=0; i<receivedata.size(); ++i) {
            //     cout << receivedata[i] << ' ';
            // }
            // cout << endl;
            for (auto i=0, id = 0; i<Btuples.size(); ++i) {
                for (auto j=0; j<Btuples[i].size(); ++j, ++id) {
                    Btuples[i][j] = receivedata[id];
                }
            }
        }

        if (context.role == SERVER) {
            vector<uint32_t> senddata;

            vector<uint64_t> Ajoinedkey, Bjoinedkey;
            GenerateJoinKey(Ajoinedid, Atuples, Ajoinedkey);
            GenerateJoinKey(Bjoinedid, Btuples, Bjoinedkey);

            // for (auto i=0; i<Ajoinedkey.size(); ++i) {
            //     cout << Ajoinedkey[i] << ' ';
            // }
            // cout << endl;
            // for (auto i=0; i<Bjoinedkey.size(); ++i) {
            //     cout << Bjoinedkey[i] << ' ';
            // }
            // cout << endl;
            

            map<uint64_t, uint32_t> idmap;
            for (auto i=0; i<Bjoinedkey.size(); ++i) {
                idmap[Bjoinedkey[i]] = i;
            }

            for (auto i=0; i<Atuples.size(); ++i) {
                if (idmap.find(Ajoinedkey[i]) != idmap.end()) {
                    vector<uint32_t> tuple = Atuples[i];
                    uint32_t Bid = idmap[Ajoinedkey[i]];
                    tuple.insert(tuple.end(), Btuples[Bid].begin(), Btuples[Bid].end());
                    outputs.push_back(tuple);
                    senddata.insert(senddata.end(), tuple.begin(), tuple.end());
                }
            }

            uint32_t sendsize = senddata.size();
            sock->Send(&sendsize, sizeof(uint32_t));
            sock->Send(senddata.data(), senddata.size() * sizeof(uint32_t));
        } else {
            uint32_t sendsize, attributesize = Atuples[0].size() + Btuples[0].size();
            sock->Receive(&sendsize, sizeof(uint32_t));
            vector<uint32_t> receivedata (sendsize);
            sock->Receive(receivedata.data(), receivedata.size() * sizeof(uint32_t));
            
            uint32_t outputsize = sendsize / attributesize;
            outputs.resize(outputsize);
            for (auto i=0, id=0; i<outputs.size(); ++i) {
                outputs[i].resize(attributesize);
                for (auto j=0; j<attributesize; ++j, ++id) {
                    outputs[i][j] = receivedata[id];
                }
            }
        }
        context.comm_cost += sock->getSndCnt() + sock->getRcvCnt();
        sock->Close();
        auto end_time = clock();
        context.total_time += (end_time - start_time) ;
    }

    void plaintext_join(vector<uint32_t> Ajoinedid, vector<vector<uint32_t>> Atuples,
                    vector<uint32_t> Bjoinedid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> &outputs) {

        vector<uint64_t> Ajoinedkey, Bjoinedkey;
        GenerateJoinKey(Ajoinedid, Atuples, Ajoinedkey);
        GenerateJoinKey(Bjoinedid, Btuples, Bjoinedkey);

        map<uint64_t, uint32_t> idmap;
        for (auto i=0; i<Bjoinedkey.size(); ++i) {
            idmap[Bjoinedkey[i]] = i;
        }

        for (auto i=0; i<Atuples.size(); ++i) {
            vector<uint32_t> tuple = Atuples[i];
            if (idmap.find(Ajoinedkey[i]) != idmap.end()) {
                uint32_t Bid = idmap[Ajoinedkey[i]];
                tuple.insert(tuple.end(), Btuples[Bid].begin(), Btuples[Bid].end());
                // tuple.push_back(1); // real tuple
            } /*else {
                uint32_t Bid = rand() % Btuples.size();
                tuple.insert(tuple.end(), Btuples[Bid].begin(), Btuples[Bid].end());
                // tuple.push_back(0); // dummy tuple
            }*/
            outputs.push_back(tuple);
        }
    }

};