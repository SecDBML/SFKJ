#include "aby/abyparty.h"
#include "circuit/arithmeticcircuits.h"
#include "circuit/share.h"
#include "sharing/sharing.h"
#include <stdlib.h>
#include <vector>
#include <string>
#include "../core/OEP.h"
#include <iostream>
#include <cassert>
#include "ENCRYPTO_utils/parse_options.h"
using namespace std;

int32_t read_test_options(int *argcp, char ***argvp, e_role *role, uint32_t *seed)
{

	uint32_t int_role = 0;

	parsing_ctx options[] = {
		{(void *)&int_role, T_NUM, "r", "Role: 0/1", false, false},
		{(void *)&seed, T_NUM, "s", "Random seed", false, false}};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx)))
	{
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role)int_role;

	return EXIT_SUCCESS;
}

/* 	test_op(abyparty, role, 10);
	test_op(abyparty, role, 200);
	test_op(abyparty, role, 3000);
*/
int32_t test_op(ABYParty *abyparty, e_role role, int size)
{
	uint32_t temp, index;
	uint32_t* source = new uint32_t[size];
	uint32_t* dest = new uint32_t[size];
	uint32_t* out = new uint32_t[size];
	for (int i = 0; i < size; i++)
		source[i] = dest[i] = i;
	for (int i = 1; i < size; i++)
	{
		index = rand() % (i + 1);
		temp = dest[index];
		dest[index] = dest[0];
		dest[0] = temp;
	}

	if (role == SERVER)
		OEP::Permute(abyparty, OEP::Role::Permutor, dest, size, out);
	else
		OEP::Permute(abyparty, OEP::Role::Owner, source, size, out);
	std::vector<Sharing *> &sharings = abyparty->GetSharings();
	auto circ = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
	share** s_out = new share*[size];
	for(int i=0;i<size;i++)
		s_out[i] = circ->PutOUTGate(circ->PutSharedINGate(out[i], 32), ALL);
	abyparty->ExecCircuit();
	uint32_t v;
	for (int i = 0; i < size; i++){
		v = s_out[i]->get_clear_value<uint32_t>();
		if(v != dest[i]){
			std::cerr << "OP test fail at i=" << i << ": " << v << "!=" << dest[i] << endl;
			exit(EXIT_FAILURE); 
		}
	}
	cout << "OP test passed!" << endl;
	return EXIT_SUCCESS;
}

/* 	test_oep(abyparty, role, 240,30);
	test_oep(abyparty, role, 240,200);
	test_oep(abyparty, role, 240,280);
*/
int32_t test_oep(ABYParty *abyparty, e_role role, int M, int N)
{
	uint32_t* source = new uint32_t[M];
	uint32_t* dest = new uint32_t[N];
	uint32_t* out = new uint32_t[N];
	for(int i=0;i<M;i++) source[i] = i;
	for (int i = 0; i < N; i++) dest[i] = rand() % M;

	if (role == SERVER)
		OEP::ExtendedPermute(abyparty, OEP::Role::Permutor, dest, M, N, out);
	else
		OEP::ExtendedPermute(abyparty, OEP::Role::Owner, source, M, N, out);
	std::vector<Sharing *> &sharings = abyparty->GetSharings();
	auto circ = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
	share** s_out = new share*[N];
	for(int i=0;i<N;i++)
		s_out[i] = circ->PutOUTGate(circ->PutSharedINGate(out[i], 32), ALL);
	abyparty->ExecCircuit();
	uint32_t v;
	for (int i = 0; i < N; i++){
		v = s_out[i]->get_clear_value<uint32_t>();
		if(v != dest[i]){
			std::cerr << "OEP test fail at i=" << i << ": " << v << "!=" << dest[i] << endl;
			exit(EXIT_FAILURE); 
		}
	}
	cout << "OEP test passed!" << endl;
	abyparty->Reset();
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	e_role role = SERVER;
	uint32_t bitlen = 32;
	uint16_t port = 7766;
	uint32_t seed = 14131;
	std::string address = "127.0.0.1";

	//read_test_options(&argc, &argv, &role, &seed);
	if (argc > 1)
		role = CLIENT;
	srand(seed);
	ABYParty *abyparty = new ABYParty(role, address, port, LT, bitlen, 1);
	abyparty->ConnectAndBaseOTs();

	return EXIT_SUCCESS;
}