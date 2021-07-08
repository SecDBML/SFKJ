#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"
#include "common/helpers.h"
#include "common/psi_analytics_context.h"
#include "common/psi_analytics.h"
#include "PermNet/PermutationNetwork.h"
#include "utils/multicom.h"

namespace ENCRYPTO{
void Aggregation(vector<uint32_t> aggidx, vector<vector<uint32_t>> tuples, 
                vector<vector<uint32_t>> &outputs, vector<bool> &sign, 
                ENCRYPTO::PsiAnalyticsContext context);
};