#include "OEP.h"

#include "circuit/booleancircuits.h"
#include "circuit/share.h"
#include "sharing/sharing.h"
#include <vector>
#include <iostream>
#include "circuit/arithmeticcircuits.h"

namespace OEP
{

    // "On Arbitrary Waksman Networks and their Vulnerability"

    struct Label
    {
        uint32_t input1;
        uint32_t input2;
        uint32_t output1;
        uint32_t output2;
    };

    struct GateBlinder
    {
        uint32_t upper;
        uint32_t lower;
    };

    static uint8_t gateNumMap[] = {0, 0, 1, 3, 5, 8, 11, 14, 17, 21, 25, 29, 33, 37,
                                   41, 45, 49, 54, 59, 64, 69, 74, 79, 84, 89, 94, 99};
    // return sum(ceil(log2(i))) for i=1 to N
    inline uint32_t ComputeGateNum(int N)
    {
        if (N < sizeof(gateNumMap) / sizeof(uint8_t))
            return gateNumMap[N];
        int power = floor_log2(N) + 1;
        return power * N + 1 - (1 << power);
    }

    void GenSelectionBits(uint32_t *permuIndices, int size, bool *bits)
    {
        if (size == 2)
            bits[0] = permuIndices[0];
        if (size <= 2)
            return;

        uint32_t *invPermuIndices = new uint32_t[size];
        for (int i = 0; i < size; i++)
            invPermuIndices[permuIndices[i]] = i;

        bool odd = size & 1;

        // Solve the edge coloring problem

        // flag=0: non-specified; flag=1: upperNetwork; flag=2: lowerNetwork
        char *leftFlag = new char[size]();
        char *rightFlag = new char[size]();
        int rightPointer = size - 1;
        int leftPointer;
        while (rightFlag[rightPointer] == 0)
        {
            rightFlag[rightPointer] = 2;
            leftPointer = permuIndices[rightPointer];
            leftFlag[leftPointer] = 2;
            if (odd && leftPointer == size - 1)
                break;
            leftPointer = leftPointer & 1 ? leftPointer - 1 : leftPointer + 1;
            leftFlag[leftPointer] = 1;
            rightPointer = invPermuIndices[leftPointer];
            rightFlag[rightPointer] = 1;
            rightPointer = rightPointer & 1 ? rightPointer - 1 : rightPointer + 1;
        }
        for (int i = 0; i < size - 1; i++)
        {
            rightPointer = i;
            while (rightFlag[rightPointer] == 0)
            {
                rightFlag[rightPointer] = 2;
                leftPointer = permuIndices[rightPointer];
                leftFlag[leftPointer] = 2;
                leftPointer = leftPointer & 1 ? leftPointer - 1 : leftPointer + 1;
                leftFlag[leftPointer] = 1;
                rightPointer = invPermuIndices[leftPointer];

                rightFlag[rightPointer] = 1;
                rightPointer = rightPointer & 1 ? rightPointer - 1 : rightPointer + 1;
            }
        }
        delete[] invPermuIndices;

        // Determine bits on left gates
        int halfSize = size / 2;
        for (int i = 0; i < halfSize; i++)
            bits[i] = leftFlag[2 * i] == 2;

        int upperIndex = halfSize;
        int uppergateNum = ComputeGateNum(halfSize);
        int lowerIndex = upperIndex + uppergateNum;
        int rightGateIndex = lowerIndex + (odd ? ComputeGateNum(halfSize + 1) : uppergateNum);
        // Determine bits on right gates
        for (int i = 0; i < halfSize - 1; i++)
            bits[rightGateIndex + i] = rightFlag[2 * i] == 2;
        if (odd)
            bits[rightGateIndex + halfSize - 1] = rightFlag[size - 2] == 1;

        delete[] leftFlag;
        delete[] rightFlag;

        // Compute upper network
        uint32_t *upperIndices = new uint32_t[halfSize];
        for (int i = 0; i < halfSize - 1 + odd; i++)
            upperIndices[i] = permuIndices[2 * i + bits[rightGateIndex + i]] / 2;
        if (!odd)
            upperIndices[halfSize - 1] = permuIndices[size - 2] / 2;
        GenSelectionBits(upperIndices, halfSize, bits + upperIndex);
        delete[] upperIndices;

        // Compute lower network
        int lowerSize = halfSize + odd;
        uint32_t *lowerIndices = new uint32_t[lowerSize];
        for (int i = 0; i < halfSize - 1 + odd; i++)
            lowerIndices[i] = permuIndices[2 * i + 1 - bits[rightGateIndex + i]] / 2;
        if (odd)
            lowerIndices[halfSize] = permuIndices[size - 1] / 2;
        else
            lowerIndices[halfSize - 1] = permuIndices[2 * halfSize - 1] / 2;
        GenSelectionBits(lowerIndices, lowerSize, bits + lowerIndex);
        delete[] lowerIndices;
    }

    // Inputs of the gate: v0=x0-r1, v1=x1-r2
    // Outputs of the gate: if bit==1 then v0=x1-r3, v1=x0-r4; otherwise v0=x0-r3, v1=x1-r4
    // m0=r1-r3, m1=r2-r4
    void EvaluateGate(uint32_t &v0, uint32_t &v1, GateBlinder blinder, bool bit)
    {
        if (bit)
        {
            uint32_t temp = v1 + blinder.upper;
            v1 = v0 + blinder.lower;
            v0 = temp;
        }
        else
        {
            v0 += blinder.upper;
            v1 += blinder.lower;
        }
    }

    // If you want to apply the original exchange operation, set blinders to be 0;
    void EvaluateNetwork(uint32_t *values, int size, bool *bits, GateBlinder *blinders)
    {
        if (size == 2)
            EvaluateGate(values[0], values[1], blinders[0], bits[0]);
        if (size <= 2)
            return;

        int odd = size & 1;
        int halfSize = size / 2;

        // Compute left gates
        for (int i = 0; i < halfSize; i++)
            EvaluateGate(values[2 * i], values[2 * i + 1], blinders[i], bits[i]);
        bits += halfSize;
        blinders += halfSize;

        // Compute upper subnetwork
        uint32_t *upperValues = new uint32_t[halfSize];
        for (int i = 0; i < halfSize; i++)
            upperValues[i] = values[i * 2];
        EvaluateNetwork(upperValues, halfSize, bits, blinders);
        int uppergateNum = ComputeGateNum(halfSize);
        bits += uppergateNum;
        blinders += uppergateNum;

        // Compute lower subnetwork
        int lowerSize = halfSize + odd;
        uint32_t *lowerValues = new uint32_t[lowerSize];
        for (int i = 0; i < halfSize; i++)
            lowerValues[i] = values[i * 2 + 1];
        if (odd) // the last element
            lowerValues[lowerSize - 1] = values[size - 1];
        EvaluateNetwork(lowerValues, lowerSize, bits, blinders);
        int lowergateNum = odd ? ComputeGateNum(lowerSize) : uppergateNum;
        bits += lowergateNum;
        blinders += lowergateNum;

        // Deal with outputs of subnetworks
        for (int i = 0; i < halfSize; i++)
        {
            values[2 * i] = upperValues[i];
            values[2 * i + 1] = lowerValues[i];
        }
        if (odd) // the last element
            values[size - 1] = lowerValues[lowerSize - 1];

        // Compute right gates
        for (int i = 0; i < halfSize - 1 + odd; i++)
            EvaluateGate(values[2 * i], values[2 * i + 1], blinders[i], bits[i]);

        delete[] upperValues;
        delete[] lowerValues;
    }

    void WriteGateLabels(uint32_t *inputLabel, int size, Label *gateLabels)
    {
        if (size == 2)
        {
            gateLabels[0].input1 = inputLabel[0];
            gateLabels[0].input2 = inputLabel[1];
            gateLabels[0].output1 = aby_rand();
            gateLabels[0].output2 = aby_rand();
            inputLabel[0] = gateLabels[0].output1;
            inputLabel[1] = gateLabels[0].output2;
        }

        if (size <= 2)
            return;

        int odd = size & 1;
        int halfSize = size / 2;

        // Compute left gates
        for (int i = 0; i < halfSize; i++)
        {
            gateLabels[i].input1 = inputLabel[2 * i];
            gateLabels[i].input2 = inputLabel[2 * i + 1];
            gateLabels[i].output1 = aby_rand();
            gateLabels[i].output2 = aby_rand();
            inputLabel[2 * i] = gateLabels[i].output1;
            inputLabel[2 * i + 1] = gateLabels[i].output2;
        }
        gateLabels += halfSize;

        // Compute upper subnetwork
        uint32_t *upperInputs = new uint32_t[halfSize];
        for (int i = 0; i < halfSize; i++)
            upperInputs[i] = inputLabel[2 * i];
        WriteGateLabels(upperInputs, halfSize, gateLabels);
        int uppergateNum = ComputeGateNum(halfSize);
        gateLabels += uppergateNum;

        // Compute lower subnetwork
        int lowerSize = halfSize + odd;
        uint32_t *lowerInputs = new uint32_t[lowerSize];
        for (int i = 0; i < halfSize; i++)
            lowerInputs[i] = inputLabel[2 * i + 1];
        if (odd) // the last element
            lowerInputs[lowerSize - 1] = inputLabel[size - 1];
        WriteGateLabels(lowerInputs, lowerSize, gateLabels);
        int lowergateNum = odd ? ComputeGateNum(lowerSize) : uppergateNum;
        gateLabels += lowergateNum;

        // Deal with outputs of subnetworks
        for (int i = 0; i < halfSize; i++)
        {
            inputLabel[2 * i] = upperInputs[i];
            inputLabel[2 * i + 1] = lowerInputs[i];
        }
        if (odd) // the last element
            inputLabel[size - 1] = lowerInputs[lowerSize - 1];

        // Compute right gates
        for (int i = 0; i < halfSize - 1 + odd; i++)
        {
            gateLabels[i].input1 = inputLabel[2 * i];
            gateLabels[i].input2 = inputLabel[2 * i + 1];
            gateLabels[i].output1 = aby_rand();
            gateLabels[i].output2 = aby_rand();
            inputLabel[2 * i] = gateLabels[i].output1;
            inputLabel[2 * i + 1] = gateLabels[i].output2;
        }
        delete[] upperInputs;
        delete[] lowerInputs;
    }
    
    // The data owner
    void OwnerPermute(ABYParty *abyparty, BooleanCircuit *circ, uint32_t *values, int size, uint32_t *outvalues)
    {
        uint32_t gateNum = ComputeGateNum(size);
        // Owner generates blinded inputs
        Label *gateLabels = new Label[gateNum];

        // Locally randomly writes labels for each gate
        std::copy_n(values, size, outvalues);
        WriteGateLabels(outvalues, size, gateLabels);

        uint64_t msg0, msg1;
        
        for (int i = 0; i < gateNum; i++)
        {
            Label label = gateLabels[i];
            msg0 = label.input1 - label.output1;
            msg0 <<= 32;
            msg0 |= label.input2 - label.output2;
            msg1 = label.input2 - label.output1;
            msg1 <<= 32;
            msg1 |= label.input1 - label.output2;
            auto s_m0 = circ->PutINGate(msg0, 64, circ->GetRole());
            auto s_m1 = circ->PutINGate(msg1, 64, circ->GetRole());
            auto s_b = circ->PutDummyINGate(1);
            auto s_mux = circ->PutMUXGate(s_m1, s_m0 , s_b);
            circ->PutOUTGate(s_mux, (e_role)(1 - circ->GetRole()));
        }
        abyparty->ExecCircuit();
        abyparty->Reset();
        delete[] gateLabels;
    }

    // The permutor
    void PermutorPermute(ABYParty *abyparty, BooleanCircuit *circ, uint32_t *permutedIndices, int size, uint32_t *outvalues)
    {
        uint32_t gateNum = ComputeGateNum(size);
        bool *selectionBits = new bool[gateNum];
        GenSelectionBits(permutedIndices, size, selectionBits);
        share **s_out = new share*[gateNum];
        for(int i=0;i<gateNum;i++){
            auto s_m0 = circ->PutDummyINGate(64);
            auto s_m1 = circ->PutDummyINGate(64);
            auto s_b = circ->PutINGate((uint8_t)selectionBits[i], 1, circ->GetRole());
            auto s_mux = circ->PutMUXGate(s_m1,s_m0,s_b);
            s_out[i] = circ->PutOUTGate(s_mux, circ->GetRole());
            
        }
        abyparty->ExecCircuit();
        uint64_t *out = new uint64_t[gateNum];
        for(int i=0;i<gateNum;i++)
            out[i] = s_out[i]->get_clear_value<uint64_t>();
        GateBlinder *gateBlinders = new GateBlinder[gateNum];
        for (int i = 0; i < gateNum; i++)
        {
            gateBlinders[i].upper = out[i] >> 32;
            gateBlinders[i].lower = out[i] & 0xffffffff;
        }
        std::memset(outvalues, 0, size * sizeof(uint32_t));
        EvaluateNetwork(outvalues, size, selectionBits, gateBlinders);
        abyparty->Reset();
        delete[] gateBlinders;
        delete[] out;
    }

    void Permute(ABYParty *abyparty, Role role, uint32_t *data_or_indices, int size, uint32_t *outvalues)
    {
        std::vector<Sharing *> &sharings = abyparty->GetSharings();
        BooleanCircuit *circ = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
        if (role == Role::Permutor)
            PermutorPermute(abyparty, circ, data_or_indices, size, outvalues);
        else
            OwnerPermute(abyparty, circ, data_or_indices, size, outvalues);
    }

    void OwnerReplicate(ABYParty *abyparty, BooleanCircuit *circ, uint32_t *values, int size, uint32_t *outvalues)
    {
        Label *labels = new Label[size - 1];
        for (int i = 0; i < size - 1; i++)
        {
            labels[i].input1 = i == 0 ? values[0] : labels[i - 1].output2;
            labels[i].input2 = values[i + 1];
            outvalues[i] = labels[i].output1 = aby_rand();
            labels[i].output2 = aby_rand();
        }
        outvalues[size - 1] = labels[size - 2].output2;
        for (int i = 0; i < size - 1; i++)
        {
            auto s_upper = circ->PutINGate(labels[i].input1 - labels[i].output1, 32, circ->GetRole());
            auto s_m0 = circ->PutINGate(labels[i].input2 - labels[i].output2, 32, circ->GetRole());
            auto s_m1 = circ->PutINGate(labels[i].input1 - labels[i].output2, 32, circ->GetRole());
            auto s_b = circ->PutDummyINGate(1);
            auto s_mux = circ->PutMUXGate(s_m1, s_m0, s_b);
            circ->PutOUTGate(s_upper, (e_role)(1 - circ->GetRole()));
            circ->PutOUTGate(s_mux, (e_role)(1 - circ->GetRole()));
        }
        abyparty->ExecCircuit();
        abyparty->Reset();
        delete[] labels;
    }

    void PermutorReplicate(ABYParty *abyparty, BooleanCircuit *circ, bool *repBits, int size, uint32_t *outvalues)
    {
        share** s_upperout = new share*[size-1];
        share** s_lowerout = new share*[size-1];
        for (int i = 0; i < size - 1; i++)
        {
            auto s_upper = circ->PutDummyINGate(32);
            auto s_m0 = circ->PutDummyINGate(32);
            auto s_m1 = circ->PutDummyINGate(32);
            auto s_b = circ->PutINGate((uint8_t)repBits[i], 1, circ->GetRole());
            auto s_mux = circ->PutMUXGate(s_m1, s_m0, s_b);
            s_upperout[i]=circ->PutOUTGate(s_upper, circ->GetRole());
            s_lowerout[i]=circ->PutOUTGate(s_mux, circ->GetRole());
        }
        abyparty->ExecCircuit();
        Label *labels = new Label[size-1];
        for (int i = 0; i < size - 1; i++)
        {
            labels[i].input1 = i == 0 ? 0 : labels[i - 1].output2;
            labels[i].input2 = 0;
            outvalues[i] = labels[i].output1 = labels[i].input1 + s_upperout[i]->get_clear_value<uint32_t>();
            labels[i].output2 = (repBits[i]? labels[i].input1: labels[i].input2) + s_lowerout[i]->get_clear_value<uint32_t>();
        }
        outvalues[size - 1] = labels[size - 2].output2;
        abyparty->Reset();
        delete[] s_upperout;
        delete[] s_lowerout;
        delete[] labels;
    }

    void OwnerExtendedPermute(ABYParty *abyparty, BooleanCircuit *circ, uint32_t *values, int M, int N, uint32_t *outvalues)
    {
        std::vector<Sharing *> &sharings = abyparty->GetSharings();
        auto arcirc = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
        int origM = M;
        if (N > M)
            M = N;
        uint32_t *extendedValues = new uint32_t[M]();
        std::copy_n(values, origM, extendedValues);
        uint32_t *out1 = new uint32_t[M];
        uint32_t *out2 = new uint32_t[N];
        OwnerPermute(abyparty, circ, extendedValues, M, out1);
        //arcirc->PutPrintValueGate(arcirc->PutSharedSIMDINGate(M,out1,32),"out1");
        OwnerReplicate(abyparty, circ, out1, N, out2);
        //arcirc->PutPrintValueGate(arcirc->PutSharedSIMDINGate(N,out2,32),"out2");
        OwnerPermute(abyparty, circ, out2, N, outvalues);
        delete[] extendedValues;
        delete[] out1;
        delete[] out2;
    }

    void PermutorExtendedPermute(ABYParty *abyparty, BooleanCircuit *circ, uint32_t *indices, int M, int N, uint32_t *outvalues)
    {
        std::vector<Sharing *> &sharings = abyparty->GetSharings();
        auto arcirc = (ArithmeticCircuit *)sharings[S_ARITH]->GetCircuitBuildRoutine();
        int origM = M;
        if (N > M)
            M = N;
        uint32_t *indicesCount = new uint32_t[M]();
        for (int i = 0; i < N; i++)
            indicesCount[indices[i]]++;
        uint32_t *firstPermu = new uint32_t[M];
        uint32_t dummyIndex = 0, fPIndex = 0;
        bool *repBits = new bool[N - 1];
        uint32_t *out1 = new uint32_t[M];
        uint32_t *out2 = new uint32_t[N];
        // We call those index with indicesCount[index]==0 as dummy index
        for (int i = 0; i < M; i++)
        {
            if (indicesCount[i] > 0)
            {
                firstPermu[fPIndex++] = i;
                for (int j = 0; j < indicesCount[i] - 1; j++)
                {
                    while (indicesCount[dummyIndex] > 0)
                        dummyIndex++;
                    firstPermu[fPIndex++] = dummyIndex++;
                }
            }
        }
        while (fPIndex < M)
        {
            while (indicesCount[dummyIndex] > 0)
                dummyIndex++;
            firstPermu[fPIndex++] = dummyIndex++;
        }
        PermutorPermute(abyparty, circ, firstPermu, M, out1);
        //arcirc->PutPrintValueGate(arcirc->PutSharedSIMDINGate(M,out1,32),"out1");
        for (int i = 0; i < N - 1; i++)
            repBits[i] = indicesCount[firstPermu[i+1]] == 0;
        PermutorReplicate(abyparty, circ, repBits, N, out2);
        int j = 0;
        out2[0] += out1[0];
        for (int i = 1; i < N; i++)
        {
            if (repBits[i-1] == 0)
                j = i;
            out2[i] += out1[j];
        }
        //arcirc->PutPrintValueGate(arcirc->PutSharedSIMDINGate(N,out2,32),"out2");
        int *pointers = new int[M];
        int sum = 0;
        for (int i = 0; i < M; i++)
        {
            pointers[i] = sum;
            sum += indicesCount[i];
        }
        int *totalMap = new int[N];
        for (int i = 0; i < N; i++)
            totalMap[i] = firstPermu[pointers[indices[i]]++];
        uint32_t *invFirstPermu = new uint32_t[M];
        for (int i = 0; i < M; i++)
            invFirstPermu[firstPermu[i]] = i;
        uint32_t *secondPermu = new uint32_t[N];
        for (int i = 0; i < N; i++)
            secondPermu[i] = invFirstPermu[totalMap[i]];
        
        PermutorPermute(abyparty, circ, secondPermu, N, outvalues);
        for (int i = 0; i < N; i++)
            outvalues[i] += out2[secondPermu[i]];

        delete[] out1;
        delete[] out2;
        delete[] indicesCount;
        delete[] firstPermu;
        delete[] invFirstPermu;
        delete[] secondPermu;
        delete[] totalMap;
        delete[] pointers;
    }

    void ExtendedPermute(ABYParty *abyparty, Role role, uint32_t *data_or_indices, int M, int N, uint32_t *outvalues)
    {
        std::vector<Sharing *> &sharings = abyparty->GetSharings();
        BooleanCircuit *circ = (BooleanCircuit *)sharings[S_BOOL]->GetCircuitBuildRoutine();
        if (role == Role::Permutor)
            PermutorExtendedPermute(abyparty, circ, data_or_indices, M, N, outvalues);
        else
            OwnerExtendedPermute(abyparty, circ, data_or_indices, M, N, outvalues);
    }

}; // namespace OEP
