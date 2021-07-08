#include "sort.h"

#include <cmath>
#include <algorithm>

void BitonicMerge(vector<vector<share*>> &circuits, uint32_t start, uint32_t length, bool direction, BooleanCircuit* bc) {
    if (length > 1) {
        uint32_t sublen = length / 2;
        for (auto i=start; i<start + sublen; ++i) {
            share* selbits = new boolshare(1, bc);
            if (direction) {
                selbits = bc->PutGTGate(circuits[i][0], circuits[i + sublen][0]);
            } else {
                selbits = bc->PutGTGate(circuits[i + sublen][0], circuits[i][0]);
            }
            for (auto j=0; j<circuits[i].size(); ++j) {
                share** outs = bc->PutCondSwapGate(circuits[i][j], circuits[i + sublen][j], selbits, true);
                circuits[i][j] = outs[0];
                circuits[i + sublen][j] = outs[1];
            }
        }
        BitonicMerge(circuits, start, sublen, direction, bc);
        BitonicMerge(circuits, start + sublen, sublen, direction, bc);
    }
}

void BitonicSort(vector<vector<share*>> &circuits, uint32_t start, uint32_t length, bool direction, BooleanCircuit* bc) {
    if (length > 1) {
        uint32_t sublen = length / 2;
        BitonicSort(circuits, start, sublen, true, bc);
        BitonicSort(circuits, start+sublen, sublen, false, bc);
        BitonicMerge(circuits, start, length, direction, bc);
    }
}

void bitonicsort(vector<vector<uint32_t>> &vals, ENCRYPTO::PsiAnalyticsContext context, bool direction) {
    uint32_t neles = vals.size();
    uint32_t nattr = vals[0].size();

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

    vector<vector<share*>> shrvals(neles);
    
    for (auto i=0; i<neles; ++i) {
        shrvals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            shrvals[i][j] = ac->PutSharedINGate(vals[i][j], 32);
            shrvals[i][j] = bc->PutA2BGate(shrvals[i][j], yc);
        }
    }

    BitonicSort(shrvals, 0, neles, direction, bc);

    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            shrvals[i][j] = ac->PutB2AGate(shrvals[i][j]);
            // shrvals[i][j] = ac->PutOUTGate(shrvals[i][j], ALL);
            shrvals[i][j] = ac->PutSharedOUTGate(shrvals[i][j]);
        }
    }

    party->ExecCircuit();

    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            vals[i][j] = shrvals[i][j]->get_clear_value<uint32_t>();
        }
    }

    // for (auto i=0; i<neles; ++i) {
    //     for (auto j=0; j<nattr; ++j) {
    //         cout << shrvals[i][j]->get_clear_value<uint32_t>() << ' ';
    //     }
    //     cout << endl;
    // }
}

void sortoep(vector<vector<uint32_t>> &vals, ENCRYPTO::PsiAnalyticsContext context, bool direction) {
    uint32_t neles = vals.size();
    uint32_t nattr = vals[0].size();

    vector< pair<uint64_t, uint32_t> > sortedpair;
    vector<uint32_t> indices;

    if (context.role == SERVER) {
        sortedpair.resize(neles);
        for (auto i=0; i<neles; ++i) {
            sortedpair[i].first = vals[i][0];
            sortedpair[i].second = i;
        }
        sort(sortedpair.begin(), sortedpair.end());
        indices.resize(sortedpair.size());
        for (auto i=0; i<indices.size(); ++i) {
            indices[i] = sortedpair[i].second;
        }
        if (!direction) {
            reverse(indices.begin(), indices.end());
        }
    }

    vector<vector<uint32_t>> tempout, outputs;
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
                outputs[i][j] += vals[indices[i]][j];
            }
        }
    } else {
        OEPClient(vals, tempout, context, S_ARITH);
        outputs.resize(tempout.size());
        for (auto i=0; i<outputs.size(); ++i) {
            outputs[i] = tempout[i];
        }
    }

    vals = outputs;
}