#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"
#include "common/helpers.h"
#include "common/psi_analytics_context.h"
#include "common/psi_analytics.h"
#include "PermNet/PermutationNetwork.h"
#include "utils/multicom.h"

namespace ENCRYPTO{
void BooleanInnerProduct(vector<bool> input, vector<bool>& outputs, ENCRYPTO::PsiAnalyticsContext &context);
void MergeTags(std::vector<bool> tag1, std::vector<bool> tag2, std::vector<bool>& newtag, multicom mcom,
                ENCRYPTO::PsiAnalyticsContext &context);
void MergeTags(std::vector<bool> tag1, std::vector<bool> tag2, std::vector<bool>& newtag,
               ENCRYPTO::PsiAnalyticsContext &context);
void OEPServer(std::vector<uint32_t> indices, std::vector< std::vector<uint32_t> > &outputs, 
               ENCRYPTO::PsiAnalyticsContext &context, e_sharing type);
void OEPClient(std::vector< std::vector<uint32_t> > weights, std::vector< std::vector<uint32_t> > &outputs, 
               ENCRYPTO::PsiAnalyticsContext &context, e_sharing type);
void obliviousPermutation(vector< vector<uint32_t> > weights, vector< uint32_t > indices, 
                vector< vector<uint32_t> > &value, ENCRYPTO::PsiAnalyticsContext &context, 
                e_sharing type);
void obliviousPermutation(ENCRYPTO::PsiAnalyticsContext &context);
void DuplicationNetwork(std::vector< std::vector<uint32_t> > &values, std::vector< bool > dummyTag, 
                        ENCRYPTO::PsiAnalyticsContext &context, e_sharing type);
};