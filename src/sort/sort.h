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

#include "OEP/OEP.h"

using namespace std;
using namespace osuCrypto;
using namespace ENCRYPTO;

// void bitonicsort();
// void oepsort();
// void sort();

// tuples are shared by two party. Sort on the the first element, order by direction (default is true / ascending order) 
void bitonicsort(vector<vector<uint32_t>> &vals, ENCRYPTO::PsiAnalyticsContext context, bool direction = true);

// sorting key is shared by SERVER, use OEP to reorder both parties shared tuples (default is true / ascending order) 
void sortoep(vector<vector<uint32_t>> &vals, ENCRYPTO::PsiAnalyticsContext context, bool direction = true);