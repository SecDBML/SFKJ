#include "join.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include "sort/sort.h"

namespace ENCRYPTO {
        void TSCheckPhase(vector<vector<uint32_t>> outputs, ENCRYPTO::PsiAnalyticsContext context, e_sharing type = S_ARITH) {
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

    void CopyCompactionCircuit(vector<vector<uint32_t>> &vals, uint32_t Bstid, uint32_t Bedid, ENCRYPTO::PsiAnalyticsContext context) {
        uint32_t neles = vals.size();
        uint32_t nattr = vals[0].size();
        uint32_t logn = (uint32_t) ceil( log2(1.0 * neles) );
        uint32_t halfn = (neles + 1) / 2;

        e_role role = (e_role)context.role;
        string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
        uint16_t port = context.port;
        uint32_t bitlen = 32, secparam = 128, nthreads = 1, prot_version = 0;
        e_mt_gen_alg mt_alg = MT_OT;
        seclvl seclvl = get_sec_lvl(secparam);

        ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
        vector<Sharing*>& sharings = party->GetSharings();
        BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
        BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
        BooleanCircuit* ac = (BooleanCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

        vector<vector<share*>> invals(neles), outvals(neles);
        vector<vector<vector<share*>>> circuits(logn + 1);
        vector<share*> tags(neles), shrtags(neles), prefixsum(neles);
        share *zero = bc->PutCONSGate((uint32_t)0u, 32);
        share *one = bc->PutCONSGate((uint32_t)1, 32);
        share *two = bc->PutCONSGate((uint32_t)2, 32);

        for (auto i=0; i<neles; ++i) {
            invals[i].resize(nattr);
            for (auto j=0; j<nattr; ++j) {
                invals[i][j] = ac->PutSharedINGate(vals[i][j], 32);
                invals[i][j] = bc->PutA2BGate(invals[i][j], yc);
            }
        }
    // Copy
        for (auto i=0; i<neles; ++i) {
            share* eq1, *eq2;
            eq1 = bc->PutEQGate(two, invals[i][nattr - 2]);
            if (i > 0) {
                eq2 = bc->PutEQGate(invals[i][nattr - 1], invals[i-1][nattr - 1]);
                eq2 = bc->PutANDGate(eq2, tags[i-1]);
            } else {
                eq2 = zero;
            }
            tags[i] = bc->PutORGate(eq1, eq2);
            if (i > 0) {
                share* selbits = bc->PutEQGate(one, invals[i][nattr - 2]);
                selbits = bc->PutANDGate(selbits, tags[i]);
                for (auto j=Bstid; j<Bedid; ++j) {
                    invals[i][j] = bc->PutMUXGate(invals[i-1][j], invals[i][j], selbits);
                }
            }
        }

        for (auto i=0; i<neles; ++i) {
            invals[i][nattr - 1] = tags[i];
        }
    // Compaction    
        for (auto i=0; i<neles; ++i) {
            shrtags[i] = bc->PutEQGate(one, invals[i][nattr - 2]);
            prefixsum[i] = bc->PutEQGate(two, invals[i][nattr - 2]);
        }

        for (auto i=1; i<neles; ++i) {
            prefixsum[i] = bc->PutADDGate(prefixsum[i-1], prefixsum[i]);
        }

        for (auto i=0; i<=logn; ++i) {
            circuits[i].resize(neles);
            for (auto j=0; j<neles; ++j) {
                circuits[i][j].resize(1 + nattr);
            }
        }

        for (auto i=0; i<neles; ++i) {
            circuits[0][i][0] = bc->PutMUXGate(prefixsum[i], zero, shrtags[i]);
            for (auto j=1; j<=nattr; ++j) {
                circuits[0][i][j] = invals[i][j-1];
            }
        }
        for (auto l=0; l<logn; ++l) {
            auto jump = (1 << l);
            for (auto i=0; i<neles; ++i) {
                for (auto j=0; j<=nattr; ++j) {
                    if (i + jump < neles) {
                        share* selbit = circuits[l][i+jump][0]->get_wire_ids_as_share(l);
                        circuits[l+1][i][j] = bc->PutMUXGate(circuits[l][i+jump][j], circuits[l][i][j], selbit);
                    } else {
                        circuits[l+1][i][j] = circuits[l][i][j];
                    }
                }
            }
        }


        for (auto i=0; i<neles; ++i) {
            outvals[i].resize(nattr);
            for (auto j=0; j<nattr; ++j) {
                outvals[i][j] = ac->PutB2AGate(circuits[logn][i][j+1]);
                outvals[i][j] = ac->PutSharedOUTGate(outvals[i][j]);
            }
        }

        party->ExecCircuit();

        for (auto i=0; i<neles; ++i) {
            for (auto j=0; j<nattr; ++j) {
                vals[i][j] = outvals[i][j]->get_clear_value<uint32_t>();
            }
        }
    }

    void TSJoin(vector<uint32_t> joinkeyidA, vector<vector<uint32_t>> Atuples,
                vector<uint32_t> joinkeyidB, vector<vector<uint32_t>> Btuples,
                vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                ENCRYPTO::PsiAnalyticsContext context) {
        
        cout << "hello " << context.role << ' ' << context.address << ' ' << context.port << endl;

        vector<vector<uint32_t>> outs;
        uint32_t outsize = Atuples.size() + Btuples.size();
        uint32_t attrsize = Atuples[0].size() + Btuples[0].size();

        uint32_t logsize = (uint32_t) ceil(log(1.0 * outsize) / log (2.0));
        uint32_t dummysize = 1 << logsize;
        outs.resize(dummysize);
        for (auto i=0; i<dummysize; ++i) {
            outs[i].resize(3 + attrsize);
        }

        vector<uint64_t> Ajoinkey, Bjoinkey;
        ENCRYPTO::GenerateJoinKey(joinkeyidA, Atuples, Ajoinkey);
        ENCRYPTO::GenerateJoinKey(joinkeyidB, Btuples, Bjoinkey);

        for (auto i=0; i<Atuples.size(); ++i) {
            if (context.role == SERVER) {
                outs[i][0] = Ajoinkey[i] * 2 + 1;
                outs[i][attrsize + 1] = 1;
                outs[i][attrsize + 2] = Ajoinkey[i];
            } else {
                outs[i][0] = outs[i][attrsize + 1] = 0;
            }
            for (auto j=0; j<Atuples[i].size(); ++j) {
                outs[i][j+1] = Atuples[i][j];
            }
        }
        uint32_t Alen = Atuples.size(), Asize = Atuples[0].size();
        for (auto i=0; i<Btuples.size(); ++i) {
            if (context.role == SERVER) {
                outs[i + Alen][0] = Bjoinkey[i] * 2;
                outs[i + Alen][attrsize + 1] = 2;
                outs[i + Alen][attrsize + 2] = Bjoinkey[i];
            } else {
                outs[i+Alen][0] = outs[i + Alen][attrsize + 1] = 0;
            }
            
            for (auto j=0; j<Btuples[i].size(); ++j) {
                outs[i + Alen][j+Asize+1] = Btuples[i][j];
            }
        }
        for (auto i=Alen + Btuples.size(); i < dummysize; ++i) {
            outs[i][0] = (1ULL << 32) - 1;
        }

        bitonicsort(outs, context);

        outs.resize(outsize);
        for (auto i=0; i<outsize; ++i) {
            outs[i].erase(outs[i].begin());
        }

        TSCheckPhase(outs, context);

        CopyCompactionCircuit(outs, Asize, Asize + Btuples[0].size(), context);

        cout << endl;
        outs.resize(Alen);
        for (auto i=0; i<Alen; ++i) {
            outs[i].erase(outs[i].begin() + (outs[i].size() - 2));
        }
        TSCheckPhase(outs, context);
    }

    void UpdateEQTag(vector<vector<uint32_t>> values, uint32_t id1, uint32_t id2, vector<bool> &eqtags, ENCRYPTO::PsiAnalyticsContext &context) {
        e_role role = (e_role)context.role;
        string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
        uint16_t port = context.port;
        uint32_t bitlen = 32, secparam = 128, nthreads = 1, prot_version = 0;
        e_mt_gen_alg mt_alg = MT_OT;
        seclvl seclvl = get_sec_lvl(secparam);

        ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
        vector<Sharing*>& sharings = party->GetSharings();
        BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

        uint32_t len = values.size();
        vector<share*> val1(len), val2(len), eq(len);
        for (auto i=0; i<len; ++i) {
            val1[i] = bc->PutSharedINGate(values[i][id1], 32);
            val2[i] = bc->PutSharedINGate(values[i][id2], 32);
        }
        for (auto i=0; i<len; ++i) {
            eq[i] = bc->PutEQGate(val1[i], val2[i]);
            eq[i] = bc->PutSharedOUTGate(eq[i]);
        }

        party->ExecCircuit();
        context.comm_cost += party->GetSentData(P_ONLINE) + party->GetReceivedData(P_ONLINE);

        eqtags.resize(len);
        for (auto i=0; i<len; ++i) {
            eqtags[i] = (eq[i]->get_clear_value<uint32_t>() & 1);
        }
    }
};