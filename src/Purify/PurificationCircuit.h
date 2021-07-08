#include <vector>

#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"
#include "abycore/sharing/sharing.h"
#include "common/helpers.h"
#include "common/psi_analytics_context.h"
#include "common/psi_analytics.h"
#include "PermNet/PermutationNetwork.h"
#include "utils/multicom.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include "abycore/circuit/booleancircuits.h"
#include "abycore/circuit/arithmeticcircuits.h"
#include "abycore/circuit/circuit.h"
#include "abycore/aby/abyparty.h"

using namespace std;
using namespace osuCrypto;
using namespace ENCRYPTO;

// void CompactionCircuit();
// void DuplicationCircuit();
// void HalfCopyCircuit();
// void PurificationCircuit();

void GenerateDPNoise_float(uint32_t length, uint32_t J, float coef, float tauC, ENCRYPTO::PsiAnalyticsContext context);
void GenerateDPNoise(uint32_t length, uint32_t nele, uint32_t D, uint64_t J, double coef, ENCRYPTO::PsiAnalyticsContext &context);
void TestMultiWires(vector<vector<uint32_t>> &vals, uint32_t D, ENCRYPTO::PsiAnalyticsContext &context);
void PurificationCircuit(vector<vector<uint32_t>> &vals, vector<bool> tags, ENCRYPTO::PsiAnalyticsContext &context);
void PurificationCircuitMultiWires(vector<vector<uint32_t>> &vals, vector<bool> tags, ENCRYPTO::PsiAnalyticsContext &context);
void GenerateMultTriplet(uint32_t N, ENCRYPTO::PsiAnalyticsContext &context);

void CompactionCircuit(vector<vector<uint32_t>> &vals, vector<bool> &tags, ENCRYPTO::PsiAnalyticsContext context);
void HalfCopyCircuit(vector<vector<uint32_t>> &vals, vector<bool> &tags, ENCRYPTO::PsiAnalyticsContext context);
void DuplicationCircuit(uint32_t shrnreal, vector<vector<uint32_t>> &vals, vector<bool> &tags, ENCRYPTO::PsiAnalyticsContext context);

void OutputCircuit(vector<vector<uint32_t>> &vals, ENCRYPTO::PsiAnalyticsContext context);

void test(ENCRYPTO::PsiAnalyticsContext context);

void GenerateMultTriplet(uint32_t IT, uint32_t B, uint32_t w, ENCRYPTO::PsiAnalyticsContext &context);