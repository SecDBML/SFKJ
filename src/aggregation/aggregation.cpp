#include "aggregation.h"
#include "sort/sort.h"
#include "OEP/OEP.h"

namespace ENCRYPTO{

void GenerateAggKey(vector<uint32_t> aggidx, vector<vector<uint32_t>> tuples, vector<uint64_t> &aggkey) {
    aggkey.resize(tuples.size());
    uint64_t multkey = 10000079LL;
    for (auto i = 0; i < tuples.size(); ++i) {
        uint64_t value = 0;
        for (auto j=0; j<aggidx.size(); ++j) {
            value = value * multkey + tuples[i][aggidx[j]];
        }
        aggkey[i] = value;
    }
}

void Aggregation(vector<uint32_t> aggidx, vector<vector<uint32_t>> tuples, 
                vector<vector<uint32_t>> &outputs, vector<bool> &sign, 
                ENCRYPTO::PsiAnalyticsContext context) {
    vector<uint64_t> aggkey;
    vector< pair<uint64_t, uint32_t> > sortedpair;
    vector<uint32_t> indices;

    if (context.role == SERVER) {

        GenerateAggKey(aggidx, tuples, aggkey);
        sortedpair.resize(aggkey.size());
        for (auto i=0; i<sortedpair.size(); ++i) {
            sortedpair[i].first = aggkey[i];
            sortedpair[i].second = i;
        }
        sort(sortedpair.begin(), sortedpair.end());
        indices.resize(sortedpair.size());
        for (auto i=0; i<indices.size(); ++i) {
            indices[i] = sortedpair[i].second;
        }

        sign.resize(sortedpair.size());
        sign[0] = true;
        for (auto i=1; i<sign.size(); ++i) {
            sign[i] = (sortedpair[i-1].first == sortedpair[i].second); 
        }
    }
    
    vector<vector<uint32_t>> tempout;
    if (context.role == SERVER) {
        cout << "indices: " << endl;
        for (auto i=0; i<indices.size(); ++i) {
            cout << indices[i] << ' ';
        }
        cout << endl;
        OEPServer(indices, tempout, context, S_ARITH);
        outputs.resize(tempout.size());
        for (auto i=0; i<tempout.size(); ++i) {
            outputs[i] = tempout[i];
            for (auto j=0; j<tempout[i].size(); ++j) {
                outputs[i][j] += tuples[indices[i]][j];
            }
        }
    } else {
        OEPClient(tuples, tempout, context, S_ARITH);
        outputs.resize(tempout.size());
        for (auto i=0; i<outputs.size(); ++i) {
            outputs[i] = tempout[i];
        }
    }
}

void AggFunction(vector<uint32_t> comid, vector<bool> tags, vector<vector<uint32_t>> tuples,
                vector<vector<uint32_t>> &outputs,
                ENCRYPTO::PsiAnalyticsContext context) {
    if (context.role == SERVER) {
        IOService ios;
        Channel recverChl = Session(ios, (context.address + ":" + std::to_string(context.port)), SessionMode::Client).addChannel();
        BitVector choicesOne(weightcnt), choicesZero(weightcnt);
        PRNG prng(sysRandomSeed());
        std::vector<block> messages(weightcnt);
        IknpOtExtReceiver receiver;
        for (auto i=0; i<weightcnt; ++i) {
            choicesOne[i] = 1;
            choicesZero[i] = 0;
        }
        cout << "duplication" << endl;
        for (auto id = 0; id < M; ++id) {
            // cout << id << ' ' << M << endl;
            BitVector choices = dummyTag[id] ? choicesOne : choicesZero;
            receiver.receiveChosen(choices, messages, prng, recverChl);
            for (auto i=0; i<weightcnt; ++i) {
                values[id][i] = values[id - dummyTag[id]][i] + (((uint32_t*)(&messages[i]))[0]);
            }
        }
    } else {
        IOService ios;
        Channel senderChl = Session(ios, (context.address + ":" + std::to_string(context.port)), SessionMode::Server).addChannel();
        std::vector<std::array<block, 2>> sendMessages(weightcnt);
        std::vector<uint32_t> rndWeights(weightcnt);
        PRNG prng(sysRandomSeed());
        IknpOtExtSender sender;
        for (auto id=0; id<M; ++id) {
            uint32_t choiceZero, choiceOne;
            for (auto i=0; i<weightcnt; ++i) {
                rndWeights[i] = prng.get();
                if (type == S_ARITH)
                    choiceZero = values[id][i] - rndWeights[i];
                    if (id == 0) {
                        choiceOne = values[id][i] - rndWeights[i];
                    } else {
                        choiceOne = values[id-1][i] - rndWeights[i];
                    }
                sendMessages[i] = {toBlock(choiceZero), toBlock(choiceOne)};
            }
            sender.sendChosen(sendMessages, prng, senderChl);
            values[id] = rndWeights;
        }
    }
}

};