# Secure Machine Learning over Relational Data

A demo for Secure Machine Learning over Relational Data. Our work is based on OPPRF-PSI and ABY framework. We build our system on VMs (Standard_D8s_v3, 8vCPU, 32GB RAM) in Azure.

### Requirements

`cmake (version >=3.13)`, `g++ (vection >=8) `, `libboost-all-dev (version >=1.69) `, `libgmp-dev`, `libssl-dev`, `libntl-dev`, `libglib2.0-dev`

You can install these requirements by using `sudo apt-get install xxx` in Ubuntu.

### Installation & Execution

Clone this repo on GitHub, and then

```
mkdir build; cd build
cmake ..
make -j 4
```

We purpose demo programs for join protocol (demo) and purification circuit (puri). In join protocol, we pick the first 100 rows of TPC-H query 3 and finish the join. You can specify your own program by changing  "loadtpchdata()". For example, for the full query, you can remove the "break" sentence. In purification protocol, we use a demo of 100 rows to show our result. You can also choose your own data and feed into the program. Another protocols and files are in directory  `demo/`.

```
./demo -r 0/1 [-a IP_address]
./puri -r 0/1 [-a IP_address]
```

"-r" chooses the role for the program, 0 represents Alice and 1 represents Bob; The programs use default IP address "127.0.0.1" or you can specify by typing "-a" and IP address of your partner.

### SecureML

The original code of SecureML is in `extern/online `. And our updated codes (DP version linear regression;  purification circuit accuracy checking) is in `secureml/`. 

```
cd src/secureml
mkdir build; cd build
cmake ..
make -j 4
./linear 1/2 12001
```

"./linear 1/2 12001", the first number is role ID and the second number is port ID. Default IP address is "127.0.0.1" as well. If you want to change the IP address, you may change the codes.