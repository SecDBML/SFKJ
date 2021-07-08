#pragma once

#include <iostream>
#include <vector>

#include "common/helpers.h"
#include "common/psi_analytics_context.h"
#include "common/psi_analytics.h"

#include "OEP/OEP.h"
#include "join/join.h"

using namespace std;

namespace ENCRYPTO{

    void TSJoin(vector<uint32_t> joinkeyidA, vector<vector<uint32_t>> Atuples,
                vector<uint32_t> joinkeyidB, vector<vector<uint32_t>> Btuples,
                vector<vector<uint32_t>> &outputs, vector<bool> &equaltags,
                ENCRYPTO::PsiAnalyticsContext context);
    void UpdateEQTag(vector<vector<uint32_t>> values, uint32_t id1, uint32_t id2, vector<bool> &eqtags, ENCRYPTO::PsiAnalyticsContext &context);
};