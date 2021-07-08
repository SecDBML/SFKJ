/**
 \file 		sort_compare_shuffle.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of ABYSetIntersection.
 */

#include "PermutationNetwork.h"
#include "abycore/sharing/sharing.h"

#include <math.h>
#include <cassert>
using namespace std;
#define BUILD_WAKSMAN

uint64_t permutation_network(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t neles, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		vector<uint32_t> sbits, vector< vector<uint32_t> > weights, uint32_t weightcnt,
		vector< vector<uint32_t> > &values, e_sharing type) {
	assert(bitlen <= 32);
	uint64_t mask = ((uint64_t) 1 << bitlen)-1;

	vector< share** > shr_val_set(weightcnt), shr_out(weightcnt), new_out(weightcnt);

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg, 4000000);
	vector<Sharing*>& sharings = party->GetSharings();
	BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	BooleanCircuit* ac = (BooleanCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	assert(yc->GetCircuitType() == C_BOOLEAN && yc->GetCircuitType() == C_BOOLEAN);

	for (uint32_t i=0; i<weightcnt; ++i) {
		shr_val_set[i] = (share**) malloc(sizeof(share*) * neles);
		shr_out[i] = (share**) malloc(sizeof(share*) * neles);
		new_out[i] = (share**) malloc(sizeof(share*) * neles);
	}

	//Set input gates to the circuit
	for (uint32_t wid = 0; wid < weightcnt; ++wid) {
		for (uint32_t i=0; i<neles; ++i) {
			if (role == CLIENT) {
				shr_val_set[wid][i] = yc->PutSIMDINGate(bitlen, weights[i][wid], 1, CLIENT);
			// cout << "input " << wid << ' ' << i << ' ' << shr_val_set[wid][i]->get_wire_id(0) << ' ' << weights[wid][i] << endl;
			} else {
				shr_val_set[wid][i] = yc->PutDummySIMDINGate(bitlen, 1);
			// cout << "input " << wid << ' ' << i << ' ' << shr_val_set[wid][i]->get_wire_id(0) << ' ' << endl;
			}
		}
	}

	//Get inputs for the selection bits of the swap gate in the waksman network

	uint32_t nswapgates = estimateGates(neles);
	assert(sbits.size() == 0 || sbits.size() == nswapgates);
	// cout << "gate count: " << nswapgates << endl;

	vector<uint32_t> selbits(nswapgates);
	for (uint32_t i = 0; i < nswapgates; i++) {
		if (role == SERVER) {
			selbits[i] = ((share*) yc->PutINGate((uint32_t)(sbits[i]), 1, SERVER))->get_wire_id(0);
		} else {
			selbits[i] = ((share*) yc->PutINGate((uint32_t)0, 1, SERVER))->get_wire_id(0);
		}
		// cout << i << ' ' << sbits[i] << endl;
	}

	vector< vector<uint32_t> > temp(weightcnt), out(weightcnt);
	vector< vector<uint32_t> > tempvec(neles);
	for (uint32_t wid = 0; wid < weightcnt; ++wid) {
		temp[wid].resize(neles);
		out[wid].resize(neles);
		for (uint32_t i=0; i<neles; ++i) {
			temp[wid][i] = shr_val_set[wid][i] -> get_wire_id(0);
		}
	}

	PermutationNetwork* perm = new PermutationNetwork(neles, yc);
	//Set the swap program of the gates
	perm->setPermutationGates(selbits);
	//cout << "Constructing Waksman circuit" << endl;
	//construct the actual Waksman permutation circuit
	for (uint32_t i = 0; i < neles; i++) {
		tempvec[i].resize(weightcnt);
		for (uint32_t wid = 0; wid < weightcnt; ++wid) {
			tempvec[i][wid] = temp[wid][i];
		}
	}
	tempvec = perm->buildPermutationCircuit(tempvec);
	// cout << "build finished" << endl;

	for (uint32_t i = 0; i < neles; i++) {
		for (uint32_t wid = 0; wid < weightcnt; ++wid) {
			out[wid][i] = tempvec[i][wid];
			// cout << out[wid][i] << ' ' << tempvec[i][wid] << endl;
		}
	}

	for (uint32_t wid = 0; wid < weightcnt; ++wid) {
		for (uint32_t i=0; i<neles; ++i) {
			shr_out[wid][i] = new boolshare(1, yc);
			shr_out[wid][i]->set_wire_id(0, out[wid][i]);
			shr_out[wid][i] = yc->PutSplitterGate(shr_out[wid][i]);
			if (type == S_ARITH) {
				new_out[wid][i] = new arithshare(bitlen, ac);
				new_out[wid][i] = ac->PutY2AGate(shr_out[wid][i], bc);
				new_out[wid][i] = ac->PutSharedOUTGate(new_out[wid][i]);
			} else if (type == S_BOOL) {
				new_out[wid][i] = new boolshare(1, ac);
				new_out[wid][i] = bc->PutY2BGate(shr_out[wid][i]);
				new_out[wid][i] = bc->PutSharedOUTGate(new_out[wid][i]);
			}

			// new_out[wid][i] = ac->PutOUTGate(new_out[wid][i], ALL);
			// shr_out[wid][i] = yc->PutOUTGate(shr_out[wid][i], ALL);
		}
	}

	party->ExecCircuit();
	uint64_t comm_size = party->GetSentData(P_ONLINE) + party->GetReceivedData(P_ONLINE);
	// cout << "P_TOTAL " << ' ' << party->GetSentData(P_TOTAL) << ' ' << party->GetReceivedData(P_TOTAL) << endl;
	// cout << "P_ONLINE " << ' ' << party->GetSentData(P_ONLINE) << ' ' << party->GetReceivedData(P_ONLINE) << endl;

	values.resize(neles);
	for (uint32_t i=0; i<neles; ++i) {
		values[i].resize(weightcnt);
		for (uint32_t wid=0; wid<weightcnt; ++wid) {
			values[i][wid] = new_out[wid][i]->get_clear_value<uint32_t>();
		}
	}

	//fact check
	// if(role == CLIENT || role == SERVER) {
	// 	cout << "share output:" << endl;
	// 	for(uint32_t i = 0; i < neles; i++) {
	// 		for (uint32_t wid = 0; wid < weightcnt; ++wid) {
	// 			cout << i << ' ' << wid << ": " << new_out[wid][i]->get_clear_value<uint32_t>() << ' ' << shr_out[wid][i]->get_clear_value<uint32_t>() << endl;
	// 		}
	// 		cout << endl;
	// 	}
	// }

	// delete party;
	// for (uint32_t i=0; i<weightcnt; ++i) {
	// 	delete shr_val_set[i];
	// 	delete shr_out[i];
	// 	delete new_out[i];
	// }

	return comm_size;
}

void test_waksman_network(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t neles, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		uint32_t prot_version, bool verify) {

	uint32_t *srv_set, *cli_set, *circ_intersect, *ver_intersect;
	uint32_t ver_inter_ctr = 0, circ_inter_ctr = 0;
	uint32_t nswapgates = estimateGates(neles);
	share **shr_server_set, **shr_client_set, **shr_out;
	assert(bitlen <= 32);
	uint64_t mask = ((uint64_t) 1 << bitlen)-1;

	e_sharing sort, permute;
	sort = permute = S_YAO;
	//vector<uint32_t> sel_bits(nswapgates);

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg, 4000000);

	vector<Sharing*>& sharings = party->GetSharings();

	BooleanCircuit* sortcirc = (BooleanCircuit*) sharings[sort]->GetCircuitBuildRoutine();
	BooleanCircuit* permcirc = (BooleanCircuit*) sharings[permute]->GetCircuitBuildRoutine();


	assert(sortcirc->GetCircuitType() == C_BOOLEAN && permcirc->GetCircuitType() == C_BOOLEAN);

	srv_set = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	cli_set = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	ver_intersect = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	circ_intersect = (uint32_t*) malloc(sizeof(uint32_t) * neles);

	shr_server_set = (share**) malloc(sizeof(share*) * neles);
	shr_out = (share**) malloc(sizeof(share*) * neles);

	//sample random client and server inputs
	vector<uint32_t> ele = {0,1,2,3,4,5,6,7};
	for (uint32_t i=0; i<neles; ++i) {
		srv_set[i] = i;//ele[i];
	}

	//Set input gates to the circuit
	for (uint32_t i = 0; i < neles; i++) {
		shr_server_set[i] = sortcirc->PutSIMDINGate(bitlen, srv_set[i], 1, SERVER);
		// cout << "input no. "<< i << ' ' << shr_server_set[i]->get_wire_id(0)<< endl;
	}

	//Get inputs for the selection bits of the swap gate in the waksman network
	// cout << "gate count: " << nswapgates << endl;
	vector<uint32_t> bits = {0,0,0,0,1};//{0,0,0,0,0,0,0,0,0,0,1,1,1};
	vector<uint32_t> selbits(nswapgates);
	for (uint32_t i = 0; i < nswapgates; i++) {
		if (role == SERVER) {
			selbits[i] = ((share*) permcirc->PutINGate((uint32_t)(bits[i]), 1, SERVER))->get_wire_id(0);
		} else {
			selbits[i] = ((share*) permcirc->PutINGate((uint32_t)0, 1, SERVER))->get_wire_id(0);
		}
		// cout << bits[i] << ' ' ;
	}
	// cout << endl;

	vector<uint32_t> temp(neles), out(neles), out2(neles);
	vector< vector<uint32_t> > tempvec(neles);
	for (uint32_t i=0; i<neles; ++i) {
		temp[i] = shr_server_set[i] -> get_wire_id(0);
	}

	PermutationNetwork* perm = new PermutationNetwork(neles, permcirc);
	//Set the swap program of the gates
	perm->setPermutationGates(selbits);

	//cout << "Constructing Waksman circuit" << endl;
	//construct the actual Waksman permutation circuit
	for (uint32_t i = 0; i < neles; i++) {
		tempvec[i].resize(2);
		tempvec[i][0] = temp[i];
		tempvec[i][1] = temp[(i+1) % neles];
	}
	tempvec = perm->buildPermutationCircuit(tempvec);

	for (uint32_t i = 0; i < tempvec.size(); i++) {
		out[i] = tempvec[i][0];
		out2[i] = tempvec[i][1];
	}

	Circuit* bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
	Circuit* ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
	share **new_out = (share**) malloc(sizeof(share*) * neles);

	for(uint32_t i = 0; i < out.size(); i++) {
		shr_out[i] = new boolshare(1, permcirc);
		shr_out[i]->set_wire_id(0, out2[i]);
	// cout << shr_out[i]->get_bitlength() << ' ' << shr_out[i]->get_share_type() << endl;
		shr_out[i] = permcirc->PutSplitterGate(shr_out[i]);
	// cout << shr_out[i]->get_bitlength() << ' ' << shr_out[i]->get_share_type() << endl;
		new_out[i] = new arithshare(bitlen, ac);
		new_out[i] = ac->PutY2AGate(shr_out[i], bc);
		new_out[i] = ac->PutOUTGate(new_out[i], ALL);
	// cout << new_out[i]->get_bitlength() << ' ' << new_out[i]->get_share_type() << endl;
		shr_out[i] = permcirc->PutOUTGate(shr_out[i], ALL);
		// cout << "bitlength  " << ac->GetShareBitLen() << ' ' << permcirc->GetShareBitLen() << endl;
	}


	party->ExecCircuit();

	// for (uint32_t i=0; i<out.size(); i++) {
	// 	// cout << "output type" << new_out[i]->get_share_type() << ' ' << new_out[i]->get_wire_id(0) << ' ' << endl;
	// }

	// for (uint32_t i=0; i<neles; i++) {
	// 	cout << (hex) << srv_set[i] << ' ' << cli_set[neles - i - 1] << (dec) << endl;
	// }

	//Only the client obtains the outputs and performs the checks
	if(role == CLIENT || role == SERVER) {
		// cout << "share output:" << endl;
		for(uint32_t i = 0; i < out.size(); i++) {
			// cout << i << ": " << (hex) << new_out[i]->get_clear_value<uint32_t>() << ' ' << shr_out[i]->get_clear_value<uint32_t>() << (dec) << endl;
			if(new_out[i]->get_clear_value<uint32_t>() != 0) {
				circ_intersect[circ_inter_ctr] = new_out[i]->get_clear_value<uint32_t>();
				circ_inter_ctr++;
			}
		}
	}

	// delete party;

	// free(srv_set);
	// free(cli_set);
	// free(shr_server_set);
	// free(shr_client_set);
	// free(shr_out);
	// free(ver_intersect);
	// free(circ_intersect);

	return;
}

//type: 0 - Boolean only, 1 - Yao only, 2 - mixed
vector<uint32_t> BuildSCSPSICircuit(share** shr_srv_set, share** shr_cli_set, vector<uint32_t> shr_sel_bits,
		uint32_t neles, uint32_t bitlen, BooleanCircuit* sortcirc, BooleanCircuit* permcirc, uint32_t type) {

	uint32_t seqsize = 2 * neles;
	vector<uint32_t> duptemppos((seqsize - 1) / 2);


	vector<vector<uint32_t> > temp(seqsize / 2);
	vector<vector<uint32_t> > tempvec(seqsize / 2);
	vector<vector<uint32_t> > dupvec(3);
	vector<vector<uint32_t> > tempbits(seqsize);
	vector<uint32_t> duptempvec;
	vector<uint32_t> duptempin((seqsize - 1) / 2);
	vector<uint32_t> a;
	vector<uint32_t> out(seqsize / 2);

	// cout << "before sorting" << endl;
	// for (int i=0; i<neles; ++i) {
	// 	cout << shr_srv_set[i]->get_wire_id(0) << ' ';
	// }
	// cout << endl;
	// for (int i=0; i<neles; ++i) {
	// 	cout << shr_cli_set[i]->get_wire_id(0) << ' ';
	// }
	// cout << endl;

	a = PutVectorBitonicSortGate(shr_srv_set, shr_cli_set, neles, bitlen, sortcirc);

	// cout << "bitonic output" << endl;
	// for (int i=0; i<a.size(); ++i) {
	// 	cout << a[i] << ' ' << endl;
	// }
	// cout << endl;

	if(type == 3) {
		a = permcirc->PutYSwitchRolesGate(a);
		sortcirc = permcirc;
	}
	/*for(uint32_t i = 0; i < a.size(); i++) {
		a[i] = permcirc->PutYSwitchRolesGate(a[i]);
	}*/

	//cout << "Building Duplicate selection layer" << endl;
	//Build 3-input duplicate selection circuit
	for (uint32_t i = 0; i < 3; i++) {
		dupvec[i].resize(bitlen);
		for (uint32_t k = 0; k < bitlen; k++) {
			for (uint32_t j = 0; j < (seqsize - 1) / 2; j++) {
				duptempin[j] = a[2 * j + i];
				duptemppos[j] = k;
			}
			dupvec[i][k] = sortcirc->PutCombineAtPosGate(duptempin, k);
		}
	}

	duptempvec = PutDupSelect3Gate(dupvec[0], dupvec[1], dupvec[2], sortcirc);

	for (uint32_t i = 0; i < seqsize / 2; i++)
		temp[i].resize(bitlen);

	for (uint32_t k = 0; k < bitlen; k++) {
		duptempin = sortcirc->PutSplitterGate(duptempvec[k]);
		for (uint32_t i = 0; i < duptempin.size(); i++) {
			temp[i][k] = duptempin[i];
		}
	}

	//Put remaining DupSelect2 Gate if necessary
	if (seqsize % 2 == 0) {
		tempbits.resize(2);
		tempbits[0] = sortcirc->PutSplitterGate(a[seqsize - 2]);
		tempbits[1] = sortcirc->PutSplitterGate(a[seqsize - 1]);
		temp[seqsize / 2 - 1] = PutDupSelect2Gate(tempbits[0], tempbits[1], sortcirc);
	}

	if (type == 2) {
		for (uint32_t i = 0; i < temp.size(); i++) {
			temp[i] = permcirc->PutY2BCONVGate(temp[i]);
			//for(uint32_t j = 0; j < temp[i].size(); j++)
			//cout << "Putting Y2BConvGate at " << temp[i][0] << endl;
			//cout << m_pGates[temp[i]].
		}
	}

	 //if(permcirc == bc) {
	 //vector<vector<uint32_t> > tempvec(temp.size());
	 //for(uint32_t i = 0; i < seqsize/2; i++)
	 //{
	 //tempvec[i].resize(1);
	 //tempvec[i][0] = permcirc->PutCombinerGate(temp[i]);
	 //temp[i] = tempvec[i];
	 //}
	 //}

	//cout << "Building Waksman network" << endl;
	//Build the swap gates for the waksman network
	PermutationNetwork* perm = new PermutationNetwork(seqsize / 2, permcirc);
	//Set the swap program of the gates
	perm->setPermutationGates(shr_sel_bits);

	//cout << "Constructing Waksman circuit" << endl;
	//construct the actual Waksman permutation circuit
	for (uint32_t i = 0; i < seqsize / 2; i++) {
		tempvec[i].resize(1);
		tempvec[i][0] = permcirc->PutCombinerGate(temp[i]);
		// for (int j=0; j<temp[i].size(); ++j) {
		// 	cout << temp[i][j] << ' ';
		// }
		// cout << endl;
	}

	tempvec = perm->buildPermutationCircuit(tempvec);

	for (uint32_t i = 0; i < tempvec.size(); i++)
		out[i] = tempvec[i][0];

	return out;
}

//vector<uint32_t> PutVectorBitonicSortGate(vector<uint32_t>& a, vector<uint32_t>& b, uint32_t bitlen, BooleanCircuit* circ) {
vector<uint32_t> PutVectorBitonicSortGate(share** srv_set, share** cli_set, uint32_t neles,
		uint32_t bitlen, BooleanCircuit* circ) {

	uint32_t seqsize = 2*neles;
	uint32_t selbitsvec;
	uint32_t i, k, ctr;
	int32_t j;

	vector<uint32_t> compa(seqsize / 2);
	vector<uint32_t> compb(seqsize / 2);
	vector<uint32_t> posa(seqsize / 2);
	vector<uint32_t> posb(seqsize / 2);
	//share **c, *selbits;

	vector<uint32_t> selbits;
	vector<uint32_t> c(seqsize);
	vector<uint32_t> temp;
	vector<uint32_t> tempcmpveca(bitlen);
	vector<uint32_t> tempcmpvecb(bitlen);

	vector<uint32_t> parenta(seqsize / 2);
	vector<uint32_t> parentb(seqsize / 2);


	//c = (share**) malloc(sizeof(share*) * seqsize);

	//Combine all values of a and b into a single vector c
	for (i = 0; i < neles; i++) {
		c[i] = srv_set[i]->get_wire_id(0);
		c[i + neles] = cli_set[i]->get_wire_id(0);
	}

	//Build bitonic sort gate for all values in C
	for (i = 1 << floor_log2(seqsize - 1); i > 0; i >>= 1) {
		ctr = 0;
		for (j = seqsize - 1, ctr = 0; j >= 0; j -= 2 * i) {
			for (k = 0; k < i && j - i - k >= 0; k++) {
				compa[ctr] = j - i - k;
				compb[ctr] = j - k;
				ctr++;
			}
		}

		//TODO: Introduce specific gate that allows the permutation of vector gates from different input gates + bit positions

		for (uint32_t l = 0; l < bitlen; l++) {
			//cout << "l = " << l << endl;
			for (k = 0; k < ctr; k++) {
				parenta[k] = c[compa[k]];
				parentb[k] = c[compb[k]];
				posa[k] = l;
				posb[k] = l;
			}
			tempcmpveca[l] = circ->PutCombineAtPosGate(parenta, l);
			tempcmpvecb[l] = circ->PutCombineAtPosGate(parentb, l);
		}


		selbitsvec = circ->PutGTGate(tempcmpveca, tempcmpvecb);

		selbits = circ->PutSplitterGate(selbitsvec);
		for (k = 0; k < ctr; k++) {
			temp = PutVectorCondSwapGate(c[compa[k]], c[compb[k]], selbits[k], circ);
			c[compa[k]] = temp[0];
			c[compb[k]] = temp[1];
		}
	}

	return c;
}

//CondSwapGates for vectorwise processing
vector<uint32_t> PutVectorCondSwapGate(uint32_t a, uint32_t b, uint32_t s, BooleanCircuit* circ) {
	vector<uint32_t> avec(1, a);
	vector<uint32_t> bvec(1, b);
	vector<uint32_t> out(2);
	//uint32_t svec = circ->PutRepeaterGate(s, 32);
	vector<vector<uint32_t> > temp = circ->PutCondSwapGate(avec, bvec, s, true);
	out[0] = temp[0][0];
	out[1] = temp[1][0];
	return out;
}

vector<uint32_t> PutDupSelect3Gate(vector<uint32_t>& x1, vector<uint32_t>& x2, vector<uint32_t>& x3, BooleanCircuit* circ) {
	uint32_t x1eqx2 = circ->PutEQGate(x1, x2); //8
	uint32_t x2eqx3 = circ->PutEQGate(x2, x3); //8
	uint32_t intersect = circ->PutORGate(x1eqx2, x2eqx3); //1
	return circ->PutELM0Gate(x2, intersect); //3
}

vector<uint32_t> PutDupSelect2Gate(vector<uint32_t>& x1, vector<uint32_t>& x2, BooleanCircuit* circ) {
	uint32_t x1eqx2 = circ->PutEQGate(x1, x2); //8
	return circ->PutELM0Gate(x2, x1eqx2); //3
}
