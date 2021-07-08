#include "PurificationCircuit.h"

#include <string>
#include <cmath>
#include <iomanip>
#include <random>
#include <bitset>

void test(ENCRYPTO::PsiAnalyticsContext context) {
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

    share* val;
    if (context.role == SERVER) {
        val = bc->PutSharedINGate((uint32_t)12, 32);
    } else {
        val = bc->PutSharedINGate((uint32_t)6, 32);
    }

    vector<share*> res;
    res.resize(32);
    // val = bc->PutSplitterGate(val);

    for (auto i=0; i<res.size(); ++i) {
        res[i] = val->get_wire_ids_as_share(i);
        res[i] = bc->PutOUTGate(res[i], ALL);
    }

    party->ExecCircuit();

    for (auto i=0; i<res.size(); ++i) {
        cout << res[i]->get_clear_value<uint32_t>() << endl;
    }
}

void GenerateDPNoise(uint32_t length, uint32_t nele, uint32_t D, uint64_t J, double coef, ENCRYPTO::PsiAnalyticsContext &context) {
    assert(length >= nele * D);
    e_role role = (e_role)context.role;
    string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
    uint16_t port = context.port;
	uint32_t bitlen = 64, secparam = 128, nthreads = 1, prot_version = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

	std::string circuit_dir = "../../bin/circ/";
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);
	vector<Sharing*>& sharings = party->GetSharings();
	// BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	BooleanCircuit* ac = (BooleanCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

    auto start = clock();
    // share *valA, *valB, *valC; // C = A / B
    // valA = bc->PutCONSGate((uint64_t)123000000000000000LL, 64);
    // valB = bc->PutCONSGate((uint64_t)456, 64);

    // // Construct integer division gate
    // std::vector<uint32_t> ain = valA -> get_wires();
    // std::vector<uint32_t> bin = valB -> get_wires();
    // ain.insert(ain.end(), bin.begin(), bin.end());
    // std::string fn = "../../bin/circ/int_div_64.aby";
    // std::vector<uint32_t> outc = bc->PutGateFromFile(fn, ain, 1);
    // outc.resize(64);
    // valC = new boolshare(outc, bc);

    // valA = bc->PutOUTGate(valA, ALL);
    // valB = bc->PutOUTGate(valB, ALL);
    // valC = bc->PutOUTGate(valC, ALL);

    // Generate standard gaussian noise
    vector<double> ganoise(length);
    std::random_device rd{};
    std::mt19937 gen{97127};
    std::normal_distribution<> d{3, 1};
    for(auto i=0; i<length; ++i) {
        ganoise[i] = d(gen);
    }

    const uint32_t fixed_fp_len = 12;
    double bias = 1.0 * (1ULL << fixed_fp_len);
    share *valC, *valJ, *delta, *shift_size, *move;
    vector<share*> srvno(length), clino(length), noise(length), output(length);

    // cout << "coef = " << (uint64_t) round(coef * bias) << endl;
    shift_size = bc->PutCONSGate((uint64_t) fixed_fp_len, 64);
    valC = bc->PutCONSGate((uint64_t) round(coef * bias), 64);
    valJ = bc->PutCONSGate((uint64_t) 1, 64);
    // valJ = bc->PutSharedINGate(J, 64);
    // bc->PutPrintValueGate(valJ, "value J");

    std::vector<uint32_t> ain = valC -> get_wires();
    std::vector<uint32_t> bin = valJ -> get_wires();
    ain.insert(ain.end(), bin.begin(), bin.end());
    std::string fn = "../../bin/circ/int_div_64.aby";
    std::vector<uint32_t> outc = bc->PutGateFromFile(fn, ain, 1);
    outc.resize(64);
    delta = new boolshare(outc, bc);
    // bc->PutPrintValueGate(delta, "delta value ");

    move = bc->PutCONSGate((uint64_t)6, 64);
    move = bc->PutMULGate(move, delta);
    move->set_max_bitlength(64);
    // bc->PutPrintValueGate(move, "move value ");

    for (auto i=0; i<length; ++i) {
        srvno[i] = bc->PutINGate((uint64_t) round(ganoise[i] * bias), 64, SERVER);
        clino[i] = bc->PutINGate((uint64_t) round(ganoise[i] * bias), 64, CLIENT);
        // bc->PutPrintValueGate(srvno[i], "SERVER value ");
        // bc->PutPrintValueGate(clino[i], "CLIENT value ");
        noise[i] = bc->PutADDGate(srvno[i], clino[i]);
        noise[i]->set_max_bitlength(64);
        // bc->PutPrintValueGate(noise[i], "sum value ");
        noise[i] = bc->PutMULGate(noise[i], delta);
        noise[i]->set_max_bitlength(64);
        // bc->PutPrintValueGate(noise[i], "mult value ");
        noise[i] = bc->PutBarrelRightShifterGate(noise[i], shift_size);
        noise[i]->set_max_bitlength(64);
        noise[i] = bc->PutSUBGate(noise[i], move);
        noise[i]->set_max_bitlength(64);
        // bc->PutPrintValueGate(noise[i], "right shift value ");

        output[i] = ac->PutB2AGate(noise[i]);
        output[i]->set_max_bitlength(64);
        output[i] = ac->PutSharedOUTGate(output[i]);
        output[i]->set_max_bitlength(64);

        noise[i] = bc->PutOUTGate(noise[i], ALL);
        noise[i]->set_max_bitlength(64);
    }

    valJ = bc->PutOUTGate(valJ, ALL);
    delta = bc->PutOUTGate(delta, ALL);
    move = bc->PutOUTGate(move, ALL);

    party->ExecCircuit();

    // cout << "value J = " << valJ->get_clear_value<uint64_t>() << endl;
    // cout << delta->get_clear_value<uint64_t>() << endl;
    // printf("%.6lf\n", 1.0 * delta->get_clear_value<uint64_t>() / bias );

    // uint64_t valmove = move->get_clear_value<uint64_t>();
    // cout << "move value = " << valmove << ' ' << valmove / bias << endl;
    for (auto i=0; i<length; ++i) {
        // printf("%llu %.6lf\n", output[i]->get_clear_value<uint64_t>(), ((int64_t)(noise[i]->get_clear_value<uint64_t>())) / bias);
    }

    string filename = "dpnoise";
    if (context.role == SERVER) {
        filename += "0";
    } else {
        filename += "1";
    }
    filename += ".txt";
    cout << filename << endl;
    ofstream fout(filename);
    // for (auto i=0; i<length; ++i) {
    //     fout << output[i]->get_clear_value<uint64_t>() << endl;
    // }
    for (auto i=0, id = 0; i<nele; ++i) {
        for (auto j=0; j<D; ++j, ++id) {
            fout << output[id]->get_clear_value<uint64_t>() << ",";
        }
        fout << endl;
    }
    fout.close();

    auto end = clock();
    context.total_time += 1.0 * (end - start) ;
    context.comm_cost += party->GetSentData(P_ONLINE) + party->GetReceivedData(P_ONLINE);
}

void GenerateMultTriplet(uint32_t N, ENCRYPTO::PsiAnalyticsContext &context) {
    auto start = clock();
    vector<uint32_t> A(N), B(N), C(N);
    for (auto i=0; i<N; ++i) {
        A[i] = rand() % 1024;
        B[i] = rand() % 1024;
    }

    e_role role = (e_role)context.role;
    string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
    uint16_t port = context.port;
	uint32_t bitlen = 32, secparam = 128, nthreads = 1, prot_version = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

	std::string circuit_dir = "../../bin/circ/";
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);
	vector<Sharing*>& sharings = party->GetSharings();
	// BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	// BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	BooleanCircuit* ac = (BooleanCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

    vector<share*> shrA(N), shrB(N), shrC(N);
    for (auto i=0; i<N; ++i) {
        shrA[i] = ac->PutSharedINGate(A[i], 32);
        shrB[i] = ac->PutSharedINGate(B[i], 32);
    }
    for (auto i=0; i<N; ++i) {
        shrC[i] = ac->PutMULGate(shrA[i], shrB[i]);

        // shrA[i] = ac->PutOUTGate(shrA[i], ALL);
        // shrB[i] = ac->PutOUTGate(shrB[i], ALL);
        shrC[i] = ac->PutSharedOUTGate(shrC[i]);
    }

    party->ExecCircuit();
    auto end = clock();
    context.total_time += (end - start) ;
    context.comm_cost += party->GetReceivedData(P_ONLINE) + party->GetSentData(P_ONLINE);
    // for (auto i=0; i<N; ++i) {
    //     cout << shrA[i]->get_clear_value<uint32_t>() << ' ' << shrB[i]->get_clear_value<uint32_t>() << ' ' << shrC[i]->get_clear_value<uint32_t>() << endl;
    // }
    // cout << "comm cost = " << (party->GetReceivedData(P_ONLINE) + party->GetSentData(P_ONLINE)) / 1024.0 / 1024.0 << endl;
    // cout << "running time = " << 1.0 * (end - start) / CLOCKS_PER_SEC << endl;
}

void GenerateDPNoise_float(uint32_t length, uint32_t J, float coef, float tauC, ENCRYPTO::PsiAnalyticsContext context) {
    cout << J << ' ' << coef << ' ' << tauC << endl;

    vector<float> gn(length);
    std::random_device rd{};
    std::mt19937 gen{rd()};
    std::normal_distribution<> d{0, 1};
    for(uint32_t idx=0; idx<length; ++idx) {
        gn[idx] = d(gen);
    }

    e_role role = (e_role)context.role;
    string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
    uint16_t port = context.port;
	uint32_t bitlen = 32, secparam = 128, nthreads = 1, prot_version = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

	std::string circuit_dir = "../../bin/circ/";
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);
	vector<Sharing*>& sharings = party->GetSharings();
	// BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	// BooleanCircuit* ac = (BooleanCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

    share *valJ, *oldJ, *valCoef, *sigma, *valtauC, *C;
    vector<share*> noisesrv(length), noisecli(length), dpnoise(length);

    valJ = bc->PutSharedINGate(J, 32);
    oldJ = bc->PutOUTGate(valJ, ALL);
    UINT32 from; FP32 to;
    valJ = bc->PutConvTypeGate(valJ, (ConvType*) &from, (ConvType*) &to);
    valCoef = bc->PutINGate(*(uint32_t*) &coef, 32, SERVER);
    valtauC = bc->PutINGate(*(uint32_t*) &tauC, 32, SERVER);
    sigma = bc->PutFPGate(valJ, valCoef, DIV, 32, 1, no_status);
    C = bc->PutFPGate(sigma, valtauC, MUL, 32, 1, no_status);

    valJ = bc->PutOUTGate(valJ, ALL);
    valCoef = bc->PutOUTGate(valCoef, ALL);
    valtauC = bc->PutOUTGate(valtauC, ALL);
    sigma = bc->PutOUTGate(sigma, ALL);

    for (auto i=0; i<length; ++i) {
        noisesrv[i] = bc->PutINGate(*(uint32_t*) &gn[i], 32, SERVER);
        noisecli[i] = bc->PutINGate(*(uint32_t*) &gn[i], 32, CLIENT);
        dpnoise[i] = bc->PutFPGate(noisesrv[i], noisecli[i], ADD, 32, 1, no_status);
        dpnoise[i] = bc->PutFPGate(dpnoise[i], C, MUL, 32, 1, no_status);
        dpnoise[i] = bc->PutOUTGate(dpnoise[i], ALL);
    }

    C = bc->PutOUTGate(C, ALL);

    party->ExecCircuit();

    cout << "execution finished" << endl;

    uint32_t valueJ = valJ -> get_clear_value<uint32_t>();
    cout << "old J = " << oldJ->get_clear_value<uint32_t>() << endl;
    cout << "value J = " << (*(uint32_t*) (&valueJ)) << endl;
    cout << "value J = " << (*(float*) (&valueJ)) << endl;
    uint32_t valueCoef = valCoef -> get_clear_value<uint32_t>();
    cout << "value Coef = " << (*(float*) (&valueCoef)) << endl;
    uint32_t valuetauC = valtauC -> get_clear_value<uint32_t>();
    cout << "value tauC = " << (*(float*) (&valuetauC)) << endl;
    uint32_t valuesigma = sigma -> get_clear_value<uint32_t>();
    cout << "value sigma = " << (*(float*) (&valuesigma)) << endl;
    uint32_t total = C -> get_clear_value<uint32_t>();
    cout << "final value = " << (*(float*) (&total)) << endl;

    cout << "dp noise" << endl;
    for (auto i=0; i<length; ++i) {
        uint32_t noi = dpnoise[i]->get_clear_value<uint32_t>();
        std::bitset<32> output(noi);
        cout << *(float*) &noi << ' ' << output << endl;
    }
}

void TestMultiWires(vector<vector<uint32_t>> &vals, uint32_t D, ENCRYPTO::PsiAnalyticsContext &context) {

    auto start_time = clock();

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

    vector<share*> invals(neles);
    vector<uint32_t> tmpone = {1, 1};
    share* one = bc->PutSIMDCONSGate(D, tmpone.data(), 32);

    for (auto i=0; i<neles; ++i) {
        // invals[i] = bc->PutSIMDINGate(D, vals[i].data(), 32, SERVER);
        invals[i] = ac->PutSharedSIMDINGate(D, vals[i].data(), 32);
        invals[i] = bc->PutA2BGate(invals[i], yc);
        cout << invals[i]->get_nvals() << endl;
        invals[i] = bc->PutMUXGate(invals[i], invals[i], one);
        cout << invals[i]->get_nvals() << endl;
        invals[i] = bc->PutOUTGate(invals[i], ALL);
    }

    party->ExecCircuit();

    for (auto i=0; i<neles; ++i) {
        uint32_t *tmpvals, bitlen, nvals;
        invals[i] -> get_clear_value_vec(&tmpvals, &bitlen, &nvals);
        cout << bitlen << ' ' << nvals << endl;
        for (auto j=0; j<nvals; ++j) {
            cout << tmpvals[j] << ' ';
        }
        cout << endl;
    }

    return;
}

void GenerateMultTriplet(uint32_t IT, uint32_t B, uint32_t w, ENCRYPTO::PsiAnalyticsContext &context) {
    // In each batch, we need a B*w and w*1 Beaver triplets
    uint32_t totalsize = B * w * 2 * 64;

    IOService ios;
    BitVector choices(totalsize);
    PRNG prng(sysRandomSeed());
    std::vector<block> messages(totalsize);
    IknpOtExtReceiver receiver;

    std::vector<std::array<block, 2>> sendMessages(totalsize);
	IknpOtExtSender sender;

    auto st_time = clock();

    vector<uint64_t> randnum (B * w * 2);
    for (auto i=0; i<randnum.size(); ++i) {
        randnum[i] = (((uint64_t) rand()) << 32) + rand();
    }

    context.comm_cost = 0;

    for (auto itid = 0; itid < IT; ++itid) {
        cout << itid << endl;
        if (context.role == SERVER) {
            Channel senderChl = Session(ios, ("0.0.0.0:" + std::to_string(context.port + 11 + itid % 200)), SessionMode::Server).addChannel();
            uint32_t id = 0;
            for (auto i=0; i<randnum.size(); ++i) {
                for (auto j=0; j<64; ++j) {
                    sendMessages[id++] = {toBlock((uint64_t) 0), toBlock(randnum[i] << j)};
                }
            }
            sender.sendChosen(sendMessages, prng, senderChl);
            context.comm_cost += sendMessages.size() * sizeof(sendMessages[0]);

            senderChl.close();
        } else {
            Channel recverChl = Session(ios, (context.address + ":" + std::to_string(context.port + 11 + itid % 200)), SessionMode::Client).addChannel();
            uint32_t id = 0;
            for (auto i=0; i< randnum.size(); ++i) {
                for (auto j=0; j<64; ++j) {
                    choices[id++] = (randnum[i] >> j) & 1;
                }
            }
            receiver.receiveChosen(choices, messages, prng, recverChl);
            context.comm_cost += messages.size() * sizeof(messages[0]);

            recverChl.close();
        }
    }

    auto ed_time = clock();
    context.total_time = 1.0 * (ed_time - st_time);
}

void PurificationCircuit(vector<vector<uint32_t>> &vals, vector<bool> tags, ENCRYPTO::PsiAnalyticsContext &context) {

    auto start_time = clock();

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
    vector<share*> shrtags(neles), prefixsum(neles);
    share *nreal, *zero, *shri, *one, *actualsize;

    for (auto i=0; i<neles; ++i) {
        invals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            invals[i][j] = ac->PutSharedINGate(vals[i][j], 32);
        }
        shrtags[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
        if (context.role == SERVER) {
            prefixsum[i] = bc->PutSharedINGate(1 - (uint32_t)tags[i], 1);
        } else {
            prefixsum[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
        }
    }

    nreal = shrtags[0];
    for (auto i=1; i<neles; ++i) {
        prefixsum[i] = bc->PutADDGate(prefixsum[i-1], prefixsum[i]);
        nreal = bc->PutADDGate(nreal, shrtags[i]);
    }
    zero = bc->PutSharedINGate((uint32_t)0, 1);
    one = bc->PutINGate((uint32_t)1, 1, SERVER);
    actualsize = bc->PutSharedOUTGate(nreal);
    actualsize->set_max_bitlength(64);

    for (auto i=0; i<=logn; ++i) {
        circuits[i].resize(neles);
        for (auto j=0; j<neles; ++j) {
            circuits[i][j].resize(1 + nattr);
        }
    }

    // First round compaction circuit
    for (auto i=0; i<neles; ++i) {
        circuits[0][i][0] = bc->PutMUXGate(prefixsum[i], zero, shrtags[i]);
        for (auto j=1; j<=nattr; ++j) {
            circuits[0][i][j] = bc->PutA2BGate(invals[i][j-1], yc);
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
        shri = bc->PutINGate((uint32_t)i, 32, SERVER);
        circuits[logn][i][0] = bc->PutGTGate(nreal, shri);
    }

    // Duplication circuit
    for (auto l=logn; l>0; --l) {
        uint32_t jump = (1 << l);
        share *shrjmp = bc->PutINGate(jump, 32, SERVER);
        share *ignoretag = bc->PutGTGate(nreal, shrjmp);
        for (auto i=0; i<neles; ++i) {
            for (auto j=0; j<=nattr; ++j) {
                if (i >= jump) {
                    share *selbits = bc->PutORGate(circuits[l][i][0], ignoretag);
                    circuits[l-1][i][j] = bc->PutMUXGate(circuits[l][i][j], circuits[l][i-jump][j], selbits);
                } else {
                    circuits[l-1][i][j] = circuits[l][i][j];
                }
            }
        }
    }

    // Second round compaction circuit
    nreal = zero;
    for (auto i=0; i<neles; ++i) {
        nreal = bc->PutADDGate(nreal, circuits[0][i][0]);
        prefixsum[i] = bc->PutXORGate(circuits[0][i][0], one);
        if (i > 0) {
            prefixsum[i] = bc->PutADDGate(prefixsum[i], prefixsum[i-1]);
        }
        circuits[0][i][0] = bc->PutMUXGate(prefixsum[i], zero, circuits[0][i][0]);
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
        shri = bc->PutINGate((uint32_t)i, 32, SERVER);
        circuits[logn][i][0] = bc->PutGTGate(nreal, shri);
    }

    // Half copy circuit
    for (auto i=0; i<neles; ++i) {
        outvals[i].resize(nattr);
        for (auto j=1; j<=nattr; ++j) {
            if (i >= halfn) {
                outvals[i][j-1] = bc->PutMUXGate(circuits[logn][i][j], circuits[logn][i-halfn][j], circuits[logn][i][0]);
            } else {
                outvals[i][j-1] = circuits[logn][i][j];
            }
        }
    }

    // for (auto i=0; i<neles; ++i) {
    //     outvals[i].resize(nattr + 1);
    //     for (auto j=0; j<=nattr; ++j) {
    //         outvals[i][j] = circuits[logn][i][j];
    //     }
    // }

    // output
    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            outvals[i][j] = ac->PutB2AGate(outvals[i][j]);
            outvals[i][j] = ac->PutSharedOUTGate(outvals[i][j]);
        }
    }

    party->ExecCircuit();

    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            vals[i][j] = outvals[i][j] -> get_clear_value<uint32_t>();
        }
    }
    uint64_t realsize = actualsize->get_clear_value<uint64_t>();


    auto end_time = clock();

    context.total_time += (end_time - start_time) ;
    context.comm_cost += party->GetReceivedData(P_ONLINE) + party->GetSentData(P_ONLINE);

    // GenerateDPNoise(3000, realsize, 128.0, context);
}


void PurificationCircuitMultiWires(vector<vector<uint32_t>> &vals, vector<bool> tags, ENCRYPTO::PsiAnalyticsContext &context) {

    auto start_time = clock();

    uint32_t neles = vals.size();
    uint32_t nattr = vals[0].size();
    uint32_t logn = (uint32_t) ceil( log2(1.0 * neles) );
    uint32_t halfn = (neles + 1) / 2;
    uint32_t nvals = vals[0].size();

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

    vector<share*> invals(neles), outvals(neles);
    vector<vector<vector<share*>>> circuits(logn + 1);
    vector<share*> shrtags(neles), prefixsum(neles);
    share *nreal, *zero, *shri, *one, *actualsize;

    for (auto i=0; i<neles; ++i) {
        invals[i] = ac->PutSharedSIMDINGate(nvals, vals[i].data(), 32);
        shrtags[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
        if (context.role == SERVER) {
            prefixsum[i] = bc->PutSharedINGate(1 - (uint32_t)tags[i], 1);
        } else {
            prefixsum[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
        }
    }

    nreal = shrtags[0];
    for (auto i=1; i<neles; ++i) {
        prefixsum[i] = bc->PutADDGate(prefixsum[i-1], prefixsum[i]);
        nreal = bc->PutADDGate(nreal, shrtags[i]);
    }
    zero = bc->PutSharedINGate((uint32_t)0, 1);
    one = bc->PutINGate((uint32_t)1, 1, SERVER);
    actualsize = bc->PutSharedOUTGate(nreal);
    actualsize->set_max_bitlength(64);

    for (auto i=0; i<=logn; ++i) {
        circuits[i].resize(neles);
        for (auto j=0; j<neles; ++j) {
            circuits[i][j].resize(2);
        }
    }

    // First round compaction circuit
    for (auto i=0; i<neles; ++i) {
        circuits[0][i][0] = bc->PutMUXGate(prefixsum[i], zero, shrtags[i]);
        circuits[0][i][1] = bc->PutA2BGate(invals[i], yc);
    }
    
    for (auto l=0; l<logn; ++l) {
        auto jump = (1 << l);
        for (auto i=0; i<neles; ++i) {
            if (i + jump < neles) {
                share* selbit = circuits[l][i+jump][0]->get_wire_ids_as_share(l);
                circuits[l+1][i][0] = bc->PutMUXGate(circuits[l][i+jump][0], circuits[l][i][0], selbit);
                share* selbits = bc->PutRepeaterGate(nvals, selbit);
                circuits[l+1][i][1] = bc->PutMUXGate(circuits[l][i+jump][1], circuits[l][i][1], selbits);
            } else {
                circuits[l+1][i][0] = circuits[l][i][0];
                circuits[l+1][i][1] = circuits[l][i][1];
            }
        }
    }
    for (auto i=0; i<neles; ++i) {
        shri = bc->PutINGate((uint32_t)i, 32, SERVER);
        circuits[logn][i][0] = bc->PutGTGate(nreal, shri);
    }
    
    
    // Duplication circuit
    for (auto l=logn; l>0; --l) {
        uint32_t jump = (1 << l);
        share *shrjmp = bc->PutINGate(jump, 32, SERVER);
        share *ignoretag = bc->PutGTGate(nreal, shrjmp);
        for (auto i=0; i<neles; ++i) {
            if (i >= jump) {
                share *selbit = bc->PutORGate(circuits[l][i][0], ignoretag);
                circuits[l-1][i][0] = bc->PutMUXGate(circuits[l][i][0], circuits[l][i-jump][0], selbit);
                share* selbits = bc->PutRepeaterGate(nvals, selbit);
                circuits[l-1][i][1] = bc->PutMUXGate(circuits[l][i][1], circuits[l][i-jump][1], selbits);
            } else {
                circuits[l-1][i][0] = circuits[l][i][0];
                circuits[l-1][i][1] = circuits[l][i][1];
            }
        }
    }
    // Second round compaction circuit
    nreal = zero;
    for (auto i=0; i<neles; ++i) {
        nreal = bc->PutADDGate(nreal, circuits[0][i][0]);
        prefixsum[i] = bc->PutXORGate(circuits[0][i][0], one);
        if (i > 0) {
            prefixsum[i] = bc->PutADDGate(prefixsum[i], prefixsum[i-1]);
        }
        circuits[0][i][0] = bc->PutMUXGate(prefixsum[i], zero, circuits[0][i][0]);
    }
    for (auto l=0; l<logn; ++l) {
        auto jump = (1 << l);
        for (auto i=0; i<neles; ++i) {
            if (i + jump < neles) {
                share* selbit = circuits[l][i+jump][0]->get_wire_ids_as_share(l);
                circuits[l+1][i][0] = bc->PutMUXGate(circuits[l][i+jump][0], circuits[l][i][0], selbit);
                share* selbits = bc->PutRepeaterGate(nvals, selbit);
                circuits[l+1][i][1] = bc->PutMUXGate(circuits[l][i+jump][1], circuits[l][i][1], selbits);
            } else {
                circuits[l+1][i][0] = circuits[l][i][0];
                circuits[l+1][i][1] = circuits[l][i][1];
            }
        }
    }
    for (auto i=0; i<neles; ++i) {
        shri = bc->PutINGate((uint32_t)i, 32, SERVER);
        circuits[logn][i][0] = bc->PutGTGate(nreal, shri);
    }

    // Half copy circuit
    for (auto i=0; i<neles; ++i) {
        if (i >= halfn) {
            share* selbits = bc->PutRepeaterGate(nvals, circuits[logn][i][0]);
            outvals[i] = bc->PutMUXGate(circuits[logn][i][1], circuits[logn][i-halfn][1], selbits);
        } else {
            outvals[i] = circuits[logn][i][1];
        }
    }

    // for (auto i=0; i<neles; ++i) {
    //     outvals[i] = circuits[logn][i][1];
    // }

    // output
    for (auto i=0; i<neles; ++i) {
        // outvals[i] = ac->PutB2AGate(outvals[i]);
        outvals[i] = bc->PutOUTGate(outvals[i], ALL);
    }

    party->ExecCircuit();

    for (auto i=0; i<neles; ++i) {
        uint32_t *tmpvals, bitlen, nvals;
        outvals[i] -> get_clear_value_vec(&tmpvals, &bitlen, &nvals);
        vals[i].resize(nattr);
        // for (auto j=0; j<nattr; ++j) {
        //     cout << tmpvals[j] << ' ';
        // }
        // cout << endl;
        for (auto j=0; j<nattr; ++j) {
            vals[i][j] = tmpvals[j];
        }
    }
    uint64_t realsize = actualsize->get_clear_value<uint64_t>();


    auto end_time = clock();

    context.total_time += (end_time - start_time) ;
    context.comm_cost += party->GetReceivedData(P_ONLINE) + party->GetSentData(P_ONLINE);

    // GenerateDPNoise(3000, realsize, 128.0, context);
}


void CompactionCircuit(vector<vector<uint32_t>> &vals, vector<bool> &tags, ENCRYPTO::PsiAnalyticsContext context) {

    uint32_t neles = vals.size();
    uint32_t nattr = vals[0].size();
    uint32_t logn = (uint32_t) ceil( log2(1.0 * neles) );

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
    vector<share*> shrtags(neles), prefixsum(neles), outtags(neles);
    share *nreal, *zero, *shri;

// Initialize
    for (auto i=0; i<neles; ++i) {
        invals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            invals[i][j] = ac->PutSharedINGate(vals[i][j], 32);
        }
        shrtags[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
        if (context.role == SERVER) {
            prefixsum[i] = bc->PutSharedINGate(1 - (uint32_t)tags[i], 1);
        } else {
            prefixsum[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
        }
    }

    for (auto i=0; i<=logn; ++i) {
        circuits[i].resize(neles);
        for (auto j=0; j<neles; ++j) {
            circuits[i][j].resize(1 + nattr);
        }
    }

    nreal = shrtags[0];
    for (auto i=1; i<neles; ++i) {
        prefixsum[i] = bc->PutADDGate(prefixsum[i-1], prefixsum[i]);
        nreal = bc->PutADDGate(nreal, shrtags[i]);
    }

    zero = bc->PutSharedINGate((uint32_t)0, 1);

// Circuit
    cout << "level 0" << endl;
    for (auto i=0; i<neles; ++i) {
        circuits[0][i][0] = bc->PutMUXGate(prefixsum[i], zero, shrtags[i]);
        for (auto j=1; j<=nattr; ++j) {
            circuits[0][i][j] = bc->PutA2BGate(invals[i][j-1], yc);
        }
    }

    for (auto l=0; l<logn; ++l) {
        cout << "level " << l+1 << endl;
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
        shri = bc->PutINGate((uint32_t)i, 32, SERVER);
        outtags[i] = bc->PutGTGate(nreal, shri);
    }


// Output
    for (auto i=0; i<neles; ++i) {
        outvals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            outvals[i][j] = bc->PutOUTGate(circuits[logn][i][j+1], ALL);
        }
        outtags[i] = bc->PutOUTGate(outtags[i], ALL);
    }
    nreal = bc->PutOUTGate(nreal, ALL);

// Execution
    party->ExecCircuit();

    cout << nreal->get_clear_value<uint32_t>() << endl;
    for (auto i=0; i<neles; ++i) {
        cout << outtags[i]->get_clear_value<uint32_t>() << " : ";
        for (auto j=0; j<nattr; ++j) {
            cout << outvals[i][j]->get_clear_value<uint32_t>() << ' ';
        }
        cout << endl;
    }
}

void DuplicationCircuit(uint32_t shrnreal, vector<vector<uint32_t>> &vals, vector<bool> &tags, ENCRYPTO::PsiAnalyticsContext context) {

    uint32_t neles = vals.size();
    uint32_t nattr = vals[0].size();
    uint32_t logn = (uint32_t) ceil( log2(1.0 * neles) );

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
    vector<share*> shrtags(neles), prefixsum(neles), outtags(neles);
    share *nreal, *zero, *shri;

    for (auto i=0; i<neles; ++i) {
        invals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            invals[i][j] = ac->PutSharedINGate(vals[i][j], 32);
        }
        shrtags[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
    }

    for (auto i=0; i<=logn; ++i) {
        circuits[i].resize(neles);
        for (auto j=0; j<neles; ++j) {
            circuits[i][j].resize(1 + nattr);
        }
    }

    nreal = ac->PutSharedINGate(shrnreal, 32);
    nreal = bc->PutA2BGate(nreal, yc);
    zero = bc->PutSharedINGate((uint32_t)0, 1);

    for (auto i=0; i<neles; ++i) {
        circuits[logn][i][0] = shrtags[i];
        for (auto j=1; j<=nattr; ++j) {
            circuits[logn][i][j] = bc->PutA2BGate(invals[i][j-1], yc);
        }
    }

    for (auto l=logn; l>0; --l) {
        uint32_t jump = (1 << l);
        share *shrjmp = bc->PutINGate(jump, 32, SERVER);
        share *ignoretag = bc->PutGTGate(nreal, shrjmp);
        for (auto i=0; i<neles; ++i) {
            for (auto j=0; j<=nattr; ++j) {
                if (i >= jump) {
                    share *selbits = bc->PutORGate(circuits[l][i][0], ignoretag);
                    circuits[l-1][i][j] = bc->PutMUXGate(circuits[l][i][j], circuits[l][i-jump][j], selbits);
                } else {
                    circuits[l-1][i][j] = circuits[l][i][j];
                }
            }
        }
    }

    for (auto i=0; i<neles; ++i) {
        outvals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            outvals[i][j] = bc->PutOUTGate(circuits[0][i][j+1], ALL);
        }
        outtags[i] = bc->PutOUTGate(circuits[0][i][0], ALL);
    }

    party->ExecCircuit();

    for (auto i=0; i<neles; ++i) {
        cout << outtags[i]->get_clear_value<uint32_t>() << " : ";
        for (auto j=0; j<nattr; ++j) {
            cout << outvals[i][j]->get_clear_value<uint32_t>() << ' ';
        }
        cout << endl;
    }
}

void HalfCopyCircuit(vector<vector<uint32_t>> &vals, vector<bool> &tags, ENCRYPTO::PsiAnalyticsContext context) {

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

    vector<vector<share*>> invals(neles), outvals(neles);
    vector<vector<share*>> circuits(neles);
    vector<share*> shrtags(neles);

    for (auto i=0; i<neles; ++i) {
        invals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            invals[i][j] = ac->PutSharedINGate(vals[i][j], 32);
            invals[i][j] = bc->PutA2BGate(invals[i][j], yc);
        }
        shrtags[i] = bc->PutSharedINGate((uint32_t)tags[i], 1);
    }

    for (auto i=0; i<neles; ++i) {
        circuits[i].resize(nattr);
    }

    uint32_t halfn = (neles+1) / 2;

    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            if (i >= halfn) {
                circuits[i][j] = bc->PutMUXGate(invals[i][j], invals[i-halfn][j], shrtags[i]);
            } else {
                circuits[i][j] = invals[i][j];
            }
        }
    }

    for (auto i=0; i<neles; ++i) {
        outvals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            // outvals[i][j] = new arithshare(32, ac);
            outvals[i][j] = ac->PutB2AGate(circuits[i][j]);
            outvals[i][j] = ac->PutOUTGate(outvals[i][j], ALL);
        }
    }

    party->ExecCircuit();


    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            cout << outvals[i][j] -> get_clear_value<uint32_t>() << ' ';
        }
        cout << endl;
    }
}

void OutputCircuit(vector<vector<uint32_t>> &vals, ENCRYPTO::PsiAnalyticsContext context) {

    uint32_t neles = vals.size();
    uint32_t nattr = vals[0].size();

    e_role role = (e_role)context.role;
    string address = ((context.role == SERVER) ? "0.0.0.0" : context.address);
    uint16_t port = context.port;
	uint32_t bitlen = 64, secparam = 128, nthreads = 1, prot_version = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 4000000);
	vector<Sharing*>& sharings = party->GetSharings();
	BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	BooleanCircuit* ac = (BooleanCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

    vector<vector<share*>> invals(neles), outvals(neles);
    vector<vector<share*>> circuits(neles);
    vector<share*> shrtags(neles);


    share* bound = ac->PutCONSGate((uint64_t)(1ULL<<32), 64);
    bound = bc->PutA2BGate(bound, yc);

    for (auto i=0; i<neles; ++i) {
        invals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            invals[i][j] = new arithshare(64, ac);
            invals[i][j] = ac->PutSharedINGate((uint64_t)vals[i][j], 64);
            if (j == nattr - 1) {
                invals[i][j] = bc->PutA2BGate(invals[i][j], yc);
                share* selb = bc->PutGTGate(invals[i][j], bound);
                share* modval = bc->PutSUBGate(invals[i][j], bound);
                invals[i][j] = bc->PutMUXGate(modval, invals[i][j], selb);
                invals[i][j] = ac->PutB2AGate(invals[i][j]);
            } 
        }
    }

    bound = bc->PutOUTGate(bound, ALL);

    for (auto i=0; i<neles; ++i) {
        outvals[i].resize(nattr);
        for (auto j=0; j<nattr; ++j) {
            outvals[i][j] = new arithshare(64, ac);
            outvals[i][j] = invals[i][j];
            outvals[i][j] = ac->PutSharedOUTGate(outvals[i][j]);
            outvals[i][j]->set_max_bitlength(64);
        }
    }

    // cout << outvals[0][2]->get_bitlength() << ' ' << outvals[0][2]->get_max_bitlength() << endl;

    party->ExecCircuit();

    cout << bound -> get_clear_value<uint64_t>() << endl;
    for (auto i=0; i<neles; ++i) {
        for (auto j=0; j<nattr; ++j) {
            cout << outvals[i][j] -> get_clear_value<uint64_t>() << ' ';
        }
        cout << endl;
    }
}