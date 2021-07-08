#include "OEP.h"
#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "abycore/circuit/booleancircuits.h"
#include "abycore/circuit/arithmeticcircuits.h"
#include "abycore/circuit/circuit.h"
#include "abycore/aby/abyparty.h"
#include "abycore/sharing/boolsharing.h"
#include "abycore/sharing/sharing.h"
#include <vector>
using namespace osuCrypto;

namespace ENCRYPTO{

void BooleanInnerProduct(vector<bool> input, vector<bool>& outputs, ENCRYPTO::PsiAnalyticsContext &context) {
    ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                context.nthreads);
    party.ConnectAndBaseOTs();
    vector<Sharing*>& sharings = party.GetSharings();
    auto bc = dynamic_cast<BooleanCircuit *>(sharings[S_BOOL]->GetCircuitBuildRoutine());

    auto size = input.size();

    share **wirea = (share**) malloc(sizeof(share*) * size);
    share **wireb = (share**) malloc(sizeof(share*) * size);
    share **wirec = (share**) malloc(sizeof(share*) * size);

    for (auto i=0; i<size; ++i) {
        if (context.role == SERVER) {
            wirea[i] = bc->PutINGate((uint32_t)input[i], 1, SERVER);
            wireb[i] = bc->PutDummyINGate(1);
        } else {
            wirea[i] = bc->PutDummyINGate(1);
            wireb[i] = bc->PutINGate((uint32_t)input[i], 1, CLIENT);
        }
    }

    for (auto i=0; i<size; ++i) {
        wirec[i] = new boolshare(1, bc);
        wirec[i] = bc->PutANDGate(wirea[i], wireb[i]);
        wirec[i] = bc->PutSharedOUTGate(wirec[i]);
    }

    party.ExecCircuit();

    outputs.resize(size);
    for (auto i=0; i<size; ++i) {
        outputs[i] = wirec[i]->get_clear_value<bool>();
    }
    return;
}

void MergeTags(std::vector<bool> tag1, std::vector<bool> tag2, std::vector<bool>& newtag, multicom mcom,
                ENCRYPTO::PsiAnalyticsContext &context) {
    
    // cout << "merge tags  " << tag1.size() << ' ' << tag2.size() << endl;
    auto size = tag1.size();
    newtag.resize(size);

    for (auto i=0; i<size; ++i) {
        newtag[i] = newtag[i] ^ (tag1[i] & tag2[i]);
    }

    auto pcnt = mcom.getpcnt();
    auto pid = mcom.getpid();
    for (auto i=0; i<pcnt; ++i) {
        for (auto j=0; j<pcnt; ++j) {
            // cout << "calculating " << i << ' ' << j << endl;
            if (i == j) continue;
            if (i != pid && j != pid) continue;
            PsiAnalyticsContext tconfig = context;
            tconfig.address = context.address;
            tconfig.port = context.port;
            // cout << tconfig.address << ' ' << tconfig.port << endl;
            if (i == pid) {
                tconfig.role = SERVER;
            } else {
                tconfig.role = CLIENT;
            }
            mcom.testconnection(tconfig.address, tconfig.port, static_cast<e_role>(tconfig.role));

            vector<bool> temp;
            if (tconfig.role == SERVER) {
                BooleanInnerProduct(tag1, temp, tconfig);
            } else {
                BooleanInnerProduct(tag2, temp, tconfig);
            }

            for (auto i=0; i<size; ++i) {
                newtag[i] = newtag[i] ^ temp[i];
            }
        }
    }
}

void MergeTags(std::vector<bool> tag1, std::vector<bool> tag2, std::vector<bool>& newtag,
               ENCRYPTO::PsiAnalyticsContext &context) {
    ABYParty party(static_cast<e_role>(context.role), context.address, context.port, LT, 64,
                    context.nthreads);
    party.ConnectAndBaseOTs();
	vector<Sharing*>& sharings = party.GetSharings();
	auto bc = dynamic_cast<BooleanCircuit *>(sharings[S_BOOL]->GetCircuitBuildRoutine());

    auto size = tag1.size();

    share **wirea = (share**) malloc(sizeof(share*) * size);
    share **wireb = (share**) malloc(sizeof(share*) * size);
    share **wirec = (share**) malloc(sizeof(share*) * size);

    for (auto i=0; i<size; ++i) {
        wirea[i] = bc->PutSharedINGate((uint32_t)tag1[i], 1);
    }
    for (auto i=0; i<size; ++i) {
        wireb[i] = bc->PutSharedINGate((uint32_t)tag2[i], 1);
    }

    for (auto i=0; i<size; ++i) {
        wirec[i] = new boolshare(1, bc);
        wirec[i] = bc->PutANDGate(wirea[i], wireb[i]);
        wirec[i] = bc->PutSharedOUTGate(wirec[i]);
    }

	party.ExecCircuit();

    newtag.resize(size);
    for (auto i=0; i<size; ++i) {
        newtag[i] = wirec[i]->get_clear_value<bool>();
    }

    return;
}

void DuplicationNetwork(std::vector< std::vector<uint32_t> > &values, std::vector< bool > dummyTag, 
                        ENCRYPTO::PsiAnalyticsContext &context, e_sharing type) {
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

    uint32_t neles = values.size(), weightcnt = values[0].size();
    vector<share*> invals(neles), muxtags(neles), outvals(neles);

    for (auto i=0; i<neles; ++i) {
        if (type == -1) {
            invals[i] = ac->PutSharedSIMDINGate(weightcnt, values[i].data(), 32);
            invals[i] = bc->PutA2BGate(invals[i], yc);
        } else {
            invals[i] = bc->PutSharedSIMDINGate(weightcnt, values[i].data(), 32);
        }
        muxtags[i] = bc->PutINGate((uint32_t)dummyTag[i], 1, SERVER);
        muxtags[i] = bc->PutRepeaterGate(weightcnt, muxtags[i]);
    }
    for (auto i=1; i<neles; ++i) {
        invals[i] = bc->PutMUXGate(invals[i-1], invals[i], muxtags[i]);
    }
    for (auto i=0; i<neles; ++i) {
        if (type == -1) {
            invals[i] = ac->PutB2AGate(invals[i]);
            invals[i] = ac->PutSharedOUTGate(invals[i]);
        } else {
            invals[i] = bc->PutSharedOUTGate(invals[i]);
        }
    }

    // cout << "start " << endl;
    // cout << "party size " << party->GetTotalDepth() << ' ' << party->GetTotalGates() << endl;
    party->ExecCircuit();

    // cout << "end execute" << endl;

    for (auto i=0; i<neles; ++i) {
        uint32_t *tmpvals, bitlen, nvals;
        invals[i] -> get_clear_value_vec(&tmpvals, &bitlen, &nvals);
        values[i].resize(weightcnt);
        for (auto j=0; j<weightcnt; ++j) {
            values[i][j] = tmpvals[j];
        }
    }

    // cout << "finish dn" << endl;
}

void OEPServer(std::vector< uint32_t > indices, std::vector< std::vector<uint32_t> > &outputs,
               ENCRYPTO::PsiAnalyticsContext &context, e_sharing type) {
    uint32_t N, M, weightcnt;
    M = indices.size();
    // communicate output size
    // cout << "oep start" << endl;
    auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    sock->Send(&M, sizeof(uint32_t));
    sock->Receive(&N, sizeof(uint32_t));
    sock->Receive(&weightcnt, sizeof(uint32_t));
    sock->Close();
    // cout << "oep size" << N << ' ' << M << ' ' << weightcnt << endl;
    uint32_t oriM = M;
    if (M < N) {
        M = N;
    }

    vector<int32_t> indicesCount(M);
    for (int i = 0; i < oriM; i++)
        indicesCount[indices[i]]++;
    vector<uint32_t> firstPermu(M);
    vector<bool> dummyTag(M);
    int32_t dummyIndex = 0, fPIndex = 0;
    for(int32_t i=0;i<M;i++) {
        if (indicesCount[i] > 0) {
            dummyTag[fPIndex] = false;
            firstPermu[fPIndex++] = i;
            for (int32_t j = 0; j < indicesCount[i] - 1; j++) {
                while (indicesCount[dummyIndex] > 0)
                    ++dummyIndex;
                dummyTag[fPIndex] = true;
                firstPermu[fPIndex++] = dummyIndex++;
            }
        }
    }
    while (fPIndex < M) {
        while (indicesCount[dummyIndex] > 0)
            ++dummyIndex;
        firstPermu[fPIndex++] = dummyIndex++;
    }

    // for (uint32_t i=0; i<M; ++i) {
    //     cout << firstPermu[i] << ' ';
    // }
    // cout << endl;

    std::vector<std::vector<uint32_t>> weights(M), values(M);
    for (uint i=0; i<M; ++i) {
        weights[i].resize(weightcnt);
        values[i].resize(weightcnt);
    }
    // cerr << "first permutation" << endl;
    obliviousPermutation(weights, firstPermu, values, context, type);

    // cerr << "duplication" << endl;
    // DuplicationNetwork(values, dummyTag, context, type);
    auto OT_start_time = std::chrono::system_clock::now();
    IOService ios;
    Channel recverChl = Session(ios, (context.address + ":" + std::to_string(context.port)), SessionMode::Client).addChannel();
    BitVector choices(M * weightcnt);
    PRNG prng(sysRandomSeed());
    std::vector<block> messages(M * weightcnt);
    IknpOtExtReceiver receiver;
    // cout << "duplication" << endl;
    uint32_t choicesid = 0;
    for (auto id = 0; id < M; ++id) {
        for (auto j=0; j<weightcnt; ++j) {
            choices[choicesid++] = dummyTag[id];
        }  
    }
    receiver.receiveChosen(choices, messages, prng, recverChl);
    choicesid = 0;
    for (auto id=0; id<M; ++id) {
        if (type == S_ARITH) {
            for (auto i=0; i<weightcnt; ++i) {
                values[id][i] = values[id - dummyTag[id]][i] + (((uint32_t*)(&messages[choicesid++]))[0]);
            }
        } else if (type == S_BOOL) {
            for (auto i=0; i<weightcnt; ++i) {
                values[id][i] = values[id - dummyTag[id]][i] ^ (((uint32_t*)(&messages[choicesid++]))[0]);
            }
        }
    }

    auto OT_end_time = std::chrono::system_clock::now();
    // cout << "OT " << M * weightcnt << " elements, take " << 1.0 * (OT_end_time - OT_start_time).count() / CLOCKS_PER_SEC << "s, transmit " << recverChl.getTotalDataRecv() / 1024.0 / 1024.0 << "MB" << endl;

    vector<uint32_t> secondPermu(M), locid(M);
    vector<bool> usedLoc(M);
    locid[0] = 0;
    for (uint32_t i=1; i<M; ++i) {
        locid[i] = locid[i-1] + indicesCount[i-1];
    }
    for (uint32_t i=0; i<oriM; ++i) {
        secondPermu[i] = locid[indices[i]]++;
        usedLoc[secondPermu[i]] = true;
    }
    for (uint32_t i=oriM, j=0; i<M; ++i) {
        while (j < M && usedLoc[j]) {
            ++j;
        }
        secondPermu[i] = j++;
    }
    // for (uint32_t i=0; i<M; ++i) {
    //     cout << secondPermu[i] << ' ';
    // }
    // cout << endl;

    std::vector<std::vector<uint32_t>> values2(M);
    outputs.resize(M);
    for (uint32_t i=0; i<M; ++i) {
        outputs[i].resize(weightcnt);
        values2[i].resize(weightcnt);
    }

    // cerr << "second permutation" << endl;
    obliviousPermutation(weights, secondPermu, values2, context, type);

    if (type == S_ARITH) {
        for (uint32_t i=0; i<M; ++i) {
            for (uint32_t j=0; j<weightcnt; ++j) {
                outputs[i][j] = values2[i][j] + values[secondPermu[i]][j];
            }
        }
    } else if (type == S_BOOL) {
        for (uint32_t i=0; i<M; ++i) {
            for (uint32_t j=0; j<weightcnt; ++j) {
                outputs[i][j] = (values2[i][j] ^ values[secondPermu[i]][j]) & 1;
            }
        }
    }

    // cout << "final result" << endl;
    // for (auto i=0; i<oriM; ++i) {
    //     for (auto j=0; j<weightcnt; ++j) {
    //         cout << outputs[i][j] << ' ';
    //     }
    //     cout << endl;
    // }

    // cout << "oep check phase" << endl;
    // cout << M << ' ' << weightcnt << endl;
    // std::unique_ptr<CSocket> sockres = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    //     std::vector<uint32_t> receive(M * (weightcnt ));
    //     sockres->Receive(receive.data(), receive.size() * sizeof(uint32_t));
    //     sockres->Close();
    //     for (auto i=0, j=0; i<M; ++i) {
    //     for (auto k=0; k<weightcnt; ++k) {
    //         if (type == S_ARITH) {
    //             cout << ((uint32_t)(outputs[i][k] + receive[j])) << '|';
    //         } else if (type == S_BOOL) {
    //             cout << outputs[i][k] << '^' << receive[j] << '=' << (outputs[i][k] ^ receive[j]) << '|';
    //         }
    //         j++;
    //     }
    //     cout << endl;
    //     }
    // cout << "oep check finished" << endl;
}

void OEPClient(std::vector< std::vector<uint32_t> > weights, std::vector< std::vector<uint32_t> > &outputs, 
               ENCRYPTO::PsiAnalyticsContext &context, e_sharing type) {
    uint32_t N, M, weightcnt;
    N = weights.size();
    weightcnt = weights[0].size();
    // communicate output size
    auto sock = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    sock->Receive(&M, sizeof(uint32_t));
    sock->Send(&N, sizeof(uint32_t));
    sock->Send(&weightcnt, sizeof(uint32_t));
    sock->Close();
    // cout << "oep size" << N << ' ' << M << ' ' << weightcnt << endl;
    uint32_t oriM = M;
    if (M < N) {
        M = N;
    }

    std::vector< std::vector<uint32_t> > extendedWeights(M), values(M);
    for (auto i=0; i<M; ++i) {
        extendedWeights[i].resize(weightcnt);
        values[i].resize(weightcnt);
        if (i < N) {
            extendedWeights[i] = weights[i];
        }
    }
    std::vector<uint32_t> empty_indices(M);
    // cerr << "first permutation" << endl;
    obliviousPermutation(extendedWeights, empty_indices, values, context, type);

    // cerr << "duplication" << endl;

    // vector<bool> dummyTag(M);
    // DuplicationNetwork(values, dummyTag, context, type);
    auto OT_start_time = std::chrono::system_clock::now();
    IOService ios;
    Channel senderChl = Session(ios, ("0.0.0.0:" + std::to_string(context.port)), SessionMode::Server).addChannel();
	std::vector<std::array<block, 2>> sendMessages(weightcnt * M);
    std::vector<uint32_t> rndWeights(weightcnt);
    PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;
    uint32_t choiceid = 0;
    for (auto id=0; id<M; ++id) {
        uint32_t choiceZero, choiceOne;
        for (auto i=0; i<weightcnt; ++i) {
            rndWeights[i] = prng.get();
            if (type == S_ARITH) {
                choiceZero = values[id][i] - rndWeights[i];
                if (id == 0) {
                    choiceOne = values[id][i] - rndWeights[i];
                } else {
                    choiceOne = values[id-1][i] - rndWeights[i];
                }
            } else if (type == S_BOOL) {
                choiceZero = values[id][i] ^ rndWeights[i];
                if (id == 0) {
                    choiceOne = values[id][i] ^ rndWeights[i];
                } else {
                    choiceOne = values[id-1][i] ^ rndWeights[i];
                }
            }
            sendMessages[choiceid++] = {toBlock(choiceZero), toBlock(choiceOne)};
        }
        values[id] = rndWeights;
    }    
    sender.sendChosen(sendMessages, prng, senderChl);
    auto OT_end_time = std::chrono::system_clock::now();
    // cout << "OT " << M * weightcnt << " elements, take " << 1.0 * (OT_end_time - OT_start_time).count() / CLOCKS_PER_SEC << "s, transmit " << senderChl.getTotalDataSent() / 1024.0 / 1024.0 << "MB" << endl;

    std::vector< std::vector<uint32_t> > values2(M);
    outputs.resize(M);
    for (auto i=0; i<M; ++i) {
        values2[i].resize(weightcnt);
        outputs[i].resize(weightcnt);
    }

    // cerr << "second permutation" << endl;
    obliviousPermutation(values, empty_indices, values2, context, type);

    for (auto i=0; i<M; ++i) {
        outputs[i] = values2[i];
        if (type == S_BOOL) {
            for (auto j=0; j<outputs[i].size(); ++j) {
                outputs[i][j] = outputs[i][j] & 1;
            }
        }
    }

    // cout << "oep check phase" << endl;
    // cout << M << ' ' << weightcnt << endl;
    // std::unique_ptr<CSocket> sockres = EstablishConnection(context.address, context.port, static_cast<e_role>(context.role));
    //     std::vector<uint32_t> send;
    //     for (auto i=0; i<M; ++i) {
    //     for (auto j=0; j<weightcnt; ++j) {
    //         send.push_back(outputs[i][j]);
    //     }
    //     }
    //     sockres->Send(send.data(), send.size() * sizeof(uint32_t));
    //     sockres->Close();
    // cout << "oep check finished" << endl;
}

// The function is to generate selection bits with given permutation indices
void permutationToBits(vector<int> permuIndices, int size, bool* bits)
{
    if (size == 2)
        bits[0] = permuIndices[0];
    if (size <= 2)
        return;

    vector<int> invPermuIndices(size);
    for (int i = 0; i < size; i++)
        invPermuIndices[permuIndices[i]] = i;

    bool odd = size & 1;

    // Solve the edge coloring problem

    // flag=0: non-specified; flag=1: upperNetwork; flag=2: lowerNetwork
    vector<char> leftFlag(size);
    vector<char> rightFlag(size);
    int rightPointer = size - 1;
    int leftPointer;
    while (rightFlag[rightPointer] == 0)
    {
        rightFlag[rightPointer] = 2;
        leftPointer = permuIndices[rightPointer];
        leftFlag[leftPointer] = 2;
        if (odd && leftPointer == size - 1)
            break;
        leftPointer = leftPointer & 1 ? leftPointer - 1 : leftPointer + 1;
        leftFlag[leftPointer] = 1;
        rightPointer = invPermuIndices[leftPointer];
        rightFlag[rightPointer] = 1;
        rightPointer = rightPointer & 1 ? rightPointer - 1 : rightPointer + 1;
    }
    for (int i = 0; i < size - 1; i++)
    {
        rightPointer = i;
        while (rightFlag[rightPointer] == 0)
        {
            rightFlag[rightPointer] = 2;
            leftPointer = permuIndices[rightPointer];
            leftFlag[leftPointer] = 2;
            leftPointer = leftPointer & 1 ? leftPointer - 1 : leftPointer + 1;
            leftFlag[leftPointer] = 1;
            rightPointer = invPermuIndices[leftPointer];

            rightFlag[rightPointer] = 1;
            rightPointer = rightPointer & 1 ? rightPointer - 1 : rightPointer + 1;
        }
    }

    // Determine bits on left gates
    int halfSize = size / 2;
    for (int i = 0; i < halfSize; i++)
        bits[i] = leftFlag[2 * i] == 2;

    int upperIndex = halfSize;
    int upperGateSize = estimateGates(halfSize);
    int lowerIndex = upperIndex + upperGateSize;
    int rightGateIndex = lowerIndex + (odd ? estimateGates(halfSize + 1) : upperGateSize);
    // Determine bits on right gates
    for (int i = 0; i < halfSize - 1; i++)
        bits[rightGateIndex + i] = rightFlag[2 * i] == 2;
    if (odd)
        bits[rightGateIndex + halfSize - 1] = rightFlag[size - 2] == 1;

    // Compute upper network
    vector<int> upperIndices(halfSize);
    for (int i = 0; i < halfSize - 1 + odd; i++)
        upperIndices[i] = permuIndices[2 * i + bits[rightGateIndex + i]] / 2;
    if (!odd)
        upperIndices[halfSize - 1] = permuIndices[size - 2] / 2;
    permutationToBits(upperIndices, halfSize, bits + upperIndex);

    // Compute lower network
    int lowerSize = halfSize + odd;
    vector<int> lowerIndices(lowerSize);
    for (int i = 0; i < halfSize - 1 + odd; i++)
        lowerIndices[i] = permuIndices[2 * i + 1 - bits[rightGateIndex + i]] / 2;
    if (odd)
        lowerIndices[halfSize] = permuIndices[size - 1] / 2;
    else
        lowerIndices[halfSize - 1] = permuIndices[2 * halfSize - 1] / 2;
    permutationToBits(lowerIndices, lowerSize, bits + lowerIndex);

}

void obliviousPermutation(vector< vector<uint32_t> > weights, vector< uint32_t > indices, 
                vector< vector<uint32_t> > &value, ENCRYPTO::PsiAnalyticsContext &context, e_sharing type) {
    e_role role = (e_role)context.role;
	string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
    uint16_t port = context.port;
	uint32_t bitlen = 32, secparam = 128, nthreads = 1, prot_version = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

    uint32_t neles = weights.size();
    uint32_t weightlen = weights[0].size();
    uint32_t ng = estimateGates(neles);
    vector<uint32_t> sbits(ng);
    bool temp_sbits[ng * 2];
    vector<int> temp_indices (indices.size() * 2);

    // SERVER provides selection bits for gate
    // cout << "permuitation bits" << ' ' << neles << ' ' << ng << endl;;
    if (role == SERVER) {
        for (uint32_t i=0; i<indices.size(); ++i) {
            temp_indices[i] = (int)indices[i];
        }
        permutationToBits(temp_indices, indices.size(), temp_sbits);
        for (uint32_t i=0; i<ng; ++i) {
            sbits[i] = temp_sbits[i];
            // cout << sbits[i] << ' ';
        }
        // cout << endl;
    }
    // CLIENT provides weight
    // nothing to do

    context.comm_cost += permutation_network(role, address, port, seclvl, neles, bitlen, nthreads, mt_alg, sbits, weights, weightlen, value, type);
    return;
}

// It is a test run for oblivious permutation function
void obliviousPermutation(ENCRYPTO::PsiAnalyticsContext &context) {
    e_role role = (e_role)context.role;
    string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
    uint16_t port = context.port;

	uint32_t bitlen = 32, secparam = 128, nthreads = 1, prot_version = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

    uint32_t neles = 4;
    uint32_t weightlen = 3;
    uint32_t ng = estimateGates(neles);

    vector< vector<uint32_t> > weights(neles);
    vector<uint32_t> sbits(ng);
    for (uint32_t i=0; i<neles; ++i) {
        weights[i].resize(weightlen);
        for (uint32_t wid=0; wid<weightlen; ++wid) {
            if (role == CLIENT) weights[i][wid] = i+1;
            else weights[i][wid] = -100;
        }
    }
    for (uint32_t i=0; i<ng; ++i) {
        if (role == SERVER) {
            sbits[i] = 0;
        } else {
            sbits[i] = 0;
        }
    }
    vector<vector<uint32_t>> values;
	permutation_network(role, address, port, seclvl, neles, bitlen, nthreads, mt_alg, sbits, weights, weightlen, values, S_ARITH);
    return;
}

};