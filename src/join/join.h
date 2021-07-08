#pragma once

#include <iostream>
#include <vector>

#include "common/helpers.h"
#include "common/psi_analytics_context.h"
#include "common/psi_analytics.h"

#include "OEP/OEP.h"

using namespace std;

namespace ENCRYPTO{
    void ObliviousReveal(vector<vector<uint32_t>> tuples, vector<bool> tags, 
                        vector<vector<uint32_t>> &results, PsiAnalyticsContext &context);
    void FilterColumns(vector<int32_t> filterids, vector<vector<uint32_t>> tuples, vector<vector<uint32_t>> &newtuples);
    void MergeTags(std::vector<bool> tag1, std::vector<bool> tag2, std::vector<bool>& newtag,
               ENCRYPTO::PsiAnalyticsContext &context);
    void GenerateJoinKey(vector<uint32_t> joinkeyid, vector<vector<uint32_t>> tuples, vector<uint64_t> &joinkey);

    // The first setting A join B
    // Server holds A and client holds B
    void JoinServer(vector<uint32_t> joinkeyid, vector<vector<uint32_t>> tuples,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context);

    void JoinClient(vector<uint32_t> joinkeyid, vector<vector<uint32_t>> tuples,
                    vector<vector<uint32_t>> severtuples,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context);

    // The second setting A join B
    // Server holds A and both share B
    void SharedJoinServer(vector<uint32_t> Ajoinkeyid, vector<vector<uint32_t>> Atuples,
                    vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context);
    void SharedJoinClient(vector<uint32_t> Bjoinkeyid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> Atuples,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context);
    
    void SharedJoinWithTagServer(vector<uint32_t> Ajoinkeyid, vector<vector<uint32_t>> Atuples,
                    vector<vector<uint32_t>> Btuples, vector<bool> Btags,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context);
    void SharedJoinWithTagClient(vector<uint32_t> Bjoinkeyid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> Atuples, vector<bool> Btags,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                    ENCRYPTO::PsiAnalyticsContext &context);
    
    // a special protocol for multiparty join
    void SharedJoinWithTagServer(vector<uint32_t> Ajoinkeyid, vector<vector<uint32_t>> Atuples, 
                        vector<vector<uint32_t>> Btuples, vector<bool> &Btags,
                        vector<vector<uint32_t>> &outputs, vector<bool> &equaltags, vector<uint32_t> &oepindices, 
                        ENCRYPTO::PsiAnalyticsContext &context);
    void SharedJoinWithTagClient(vector<uint32_t> Bjoinkeyid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> Atuples, vector<bool> &Btags,
                    vector<vector<uint32_t>> &outputs, vector<bool> &equaltags, vector<uint32_t> &oepindices, 
                    ENCRYPTO::PsiAnalyticsContext &context);
    
    void plaintext_join(vector<uint32_t> Ajoinedid, vector<vector<uint32_t>> Atuples,
                    vector<uint32_t> Bjoinedid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> &outputs, ENCRYPTO::PsiAnalyticsContext &context);
    
    void plaintext_join(vector<uint32_t> Ajoinedid, vector<vector<uint32_t>> Atuples,
                    vector<uint32_t> Bjoinedid, vector<vector<uint32_t>> Btuples,
                    vector<vector<uint32_t>> &outputs);
};