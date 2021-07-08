#include "multicom.h"

using namespace std;
using namespace osuCrypto;

multicom::multicom(uint32_t id) {
    // read config...
    string filepath = "../../data/" + to_string(id) + ".config";
    
    if( access( filepath.c_str(), F_OK ) != -1 ) {
        cout << "config data find" << endl; // file exists
    } else {
        cout << "config data not exists" << endl; // file doesn't exist
    }

    ifstream fin(filepath.c_str(), ios::in);

    fin >> pcnt >> pid;

    assert(id == pid);

    paddress.resize(pcnt);
    pport.resize(pcnt);

    for (auto i=0; i<pcnt; ++i) {
        string taddr;
        uint16_t tport;
        fin >> taddr >> tport;
        paddress[i] = taddr;
        pport[i] = tport;
    }
    std::unique_ptr<CSocket> psocket;
    // psocket.resize(pcnt);
    for (auto i=0; i<pcnt; ++i) {
        if (i == pid) continue;

        string addr;
        uint16_t port;
        e_role role;

        // Special arrangement for 3 parties
        addr = paddress[i + pid - 1];
        port = pport[i + pid - 1];
        if (i < pid) {
            role = CLIENT;
        } else {
            role = SERVER;
        }

        cout << "set up connection with " << addr << ' ' << port << ' ' << role << endl;
        psocket = ENCRYPTO::EstablishConnection(addr, port, role);
        psocket -> Close();
    }

    fin.close();
}

void multicom::testconnection(uint32_t otherid) {
    if (pid == otherid) {
        cout << "assert: try to connect with itself" << endl;
        assert(false);
    }
    string addr;
    uint16_t port;
    e_role role;
    addr = paddress[otherid + pid - 1];
    port = pport[otherid + pid - 1];
    if (pid < otherid) {
        role = SERVER;
    } else {
        role = CLIENT;
    }
    std::unique_ptr<CSocket> temp = ENCRYPTO::EstablishConnection(addr, port, role);
    temp->Close();
    return;
}

void multicom::testconnection(string addr, uint16_t port, e_role role) {
    std::unique_ptr<CSocket> temp = ENCRYPTO::EstablishConnection(addr, port, role);
    temp->Close();
    return;
}

// std::unique_ptr<CSocket> multicom::connect(uint32_t otherid) {
//     if (pid == otherid) {
//         cout << "assert: try to connect with itself" << endl;
//         assert(false);
//     }
//     string addr;
//     uint16_t port;
//     e_role role;
//     addr = paddress[otherid + pid - 1];
//     port = pport[otherid + pid - 1];
//     if (pid < otherid) {
//         role = SERVER;
//     } else {
//         role = CLIENT;
//     }
//     return ENCRYPTO::EstablishConnection(addr, port, role);
// }

