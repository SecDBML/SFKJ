// This is a single party non-private implementation Compaction & Duplication circuits

#include <iostream>
#include <vector>
#include <array>
#include <cmath>
using namespace std;

uint32_t MUXGate(uint32_t aval, uint32_t bval, bool bit) {
    return bit ? bval : aval;
}

array<uint32_t, 2> MUXGate(array<uint32_t, 2> aval, array<uint32_t, 2> bval, bool bit) {
    return bit ? bval : aval;
}

void CompactionCircuit(uint32_t neles, uint32_t &nreal, vector<uint32_t> &vals, vector<bool> &tags) {
    uint32_t logn = (uint32_t) ceil( log2(1.0 * neles) );
    
    vector<uint32_t> prefixsum(neles);
    prefixsum[0] = 1 - (uint32_t) tags[0];
    for (auto i=1; i<neles; ++i) {
        prefixsum[i] = prefixsum[i-1] + 1 - (uint32_t) tags[i];
    }
    nreal = neles - prefixsum[neles - 1];
    for (auto i=0; i<neles; ++i) {
        prefixsum[i] = MUXGate(0, prefixsum[i], tags[i]);
    }

    // cout << "move steps : ";
    // for (auto i=0; i<neles; ++i) {
    //     cout << prefixsum[i] << ' ';
    // }
    // cout << endl;

    vector< vector< array<uint32_t, 2> > > circuits (logn + 1);

    for (auto i=0; i<=logn; ++i) {
        circuits[i].resize(neles);
    }
    for (auto i=0; i<neles; ++i) {
        circuits[0][i] = {prefixsum[i], vals[i]};
    }

    for (auto i=0; i<logn; ++i) {
        uint32_t jump = (1 << i);
        // cout << "level " << i << " , jump " << jump << " : ";
        for (auto j=0; j<neles; ++j) {
            if (j + jump < neles) {
                circuits[i+1][j] = MUXGate(circuits[i][j], circuits[i][j+jump], (bool)((circuits[i][j+jump][0] >> i) & 1));
            } else {
                circuits[i+1][j] = circuits[i][j];
            }
        }
        // for (auto j=0; j<neles; ++j) {
        //     cout << circuits[i+1][j][1] << ' ';
        // }
        // cout << endl;
    }

    for (auto i=0; i<neles; ++i) {
        vals[i] = circuits[logn][i][1];
        tags[i] = (bool) MUXGate(0, 1, (i < nreal));
    }
}

void DuplicationCircuit(uint32_t neles, uint32_t nreal, vector<uint32_t> &vals, vector<bool> &tags) {
    uint32_t logn = (uint32_t) ceil( log2(1.0 * neles) );

    vector< vector<uint32_t> > circuits(logn + 1);
    vector< vector<bool> > tagscirc(logn + 1);

    for (auto i=0; i<=logn; ++i) {
        circuits[i].resize(neles);
        tagscirc[i].resize(neles);
    }

    circuits[logn] = vals;
    tagscirc[logn] = tags;

    for (int i=logn - 1; i>=0; --i) {
        uint32_t jump = 1 << i;
        bool ignoretag = (jump < nreal);
        // cout << "level " << i << " jump " << jump << " ignore " << ignoretag << " : ";
        for (auto j=0; j<neles; ++j) {
            if (j >= jump) {
                circuits[i][j] = MUXGate(circuits[i+1][j-jump], circuits[i+1][j], tagscirc[i+1][j] | ignoretag);
                tagscirc[i][j] = MUXGate(tagscirc[i+1][j-jump], tagscirc[i+1][j], tagscirc[i+1][j] | ignoretag);
            } else {
                circuits[i][j] = circuits[i+1][j];
                tagscirc[i][j] = tagscirc[i+1][j];
            }
        }
        // for (auto j=0; j<neles; ++j) {
        //     cout << circuits[i][j] << ' ';
        // }
        // cout << endl;
    }

    vals = circuits[0];
    tags = tagscirc[0];

}

void HalfCopyCircuit(uint32_t neles, uint32_t nreal, vector<uint32_t> &vals, vector<bool> &tags) {
    uint32_t halfn = (neles + 1) / 2;

    for (auto i=0; i<neles; ++i) {
        if (i < halfn) {
            vals[i] = vals[i];
        } else {
            vals[i] = MUXGate(vals[i - halfn], vals[i], tags[i]);
        }
        tags[i] = 1;
    }
}

int main() {
    uint32_t neles, nreal;
    vector<uint32_t> vals;
    vector<bool> tags;

    // Set Random Data
    neles = 10;
    vals.resize(neles);
    tags.resize(neles);
    srand(time(0));
    for (auto i=0; i<neles; ++i) {
        vals[i] = i; //rand() % 10000;
        tags[i] = rand() % 2;
    }
    neles = 32;
    vals.resize(neles);
    tags.resize(neles);

            cout << " ================ Original Input ================== " << endl;
            for (auto i=0; i<neles; ++i) {
                printf("%u(%u) ", vals[i], (uint32_t)tags[i]);
            }
            printf("\n");
            cout << " ================================================== " << endl;

    // Compaction
    CompactionCircuit(neles, nreal, vals, tags);

            cout << " =============== First Compaction ================= " << endl;
            cout << "real tuples : " << nreal << endl;
            for (auto i=0; i<neles; ++i) {
                printf("%u(%u) ", vals[i], (uint32_t)tags[i]);
            }
            printf("\n");
            cout << " ================================================== " << endl;


    // Duplication
    DuplicationCircuit(neles, nreal, vals, tags);

            cout << " ================== Duplication ==================== " << endl;
            for (auto i=0; i<neles; ++i) {
                printf("%u(%u) ", vals[i], (uint32_t)tags[i]);
            }
            printf("\n");
            cout << " ================================================== " << endl;


    // Second Round Compaction
    CompactionCircuit(neles, nreal, vals, tags);

            cout << " =============== Second Compaction ================= " << endl;
            cout << "real tuples : " << nreal << endl;
            for (auto i=0; i<neles; ++i) {
                printf("%u(%u) ", vals[i], (uint32_t)tags[i]);
            }
            printf("\n");
            cout << " ================================================== " << endl;

    // Half Copy
    HalfCopyCircuit(neles, nreal, vals, tags);

            cout << " ================== Half  Copy ==================== " << endl;
            for (auto i=0; i<neles; ++i) {
                printf("%u(%u) ", vals[i], (uint32_t)tags[i]);
            }
            printf("\n");
            cout << " ================================================== " << endl;

    return 0;
}