#include <iostream>
#include <vector>
#include <cstdlib>
using namespace std;

void BitonicSortMerge(vector<int> &a, int start, int length, int direction) {
    if (length > 1) {
        int sublen = length / 2;
        for (auto i=start; i<start+sublen; ++i) {
            if (direction == (a[i] > a[i+sublen])) {
                swap(a[i], a[i+sublen]);
            }
        }
        BitonicSortMerge(a, start, sublen, direction);
        BitonicSortMerge(a, start+sublen, sublen, direction);
    }
}

void BitonicSort(vector<int> &a, int start, int length, int direction) {
    if (length > 1) {
        int sublen = length / 2;
        BitonicSort(a, start, sublen, 1);
        BitonicSort(a, start + sublen, sublen, 0);
        BitonicSortMerge(a, start, length, direction);
    }
}

int main() {

    vector<int> a = {123, 21, 435, 343, 77, 1, 199, 7};

    cout << "Original array: " << endl;
    for (auto i=0; i<a.size(); ++i) {
        cout << a[i] << ' ';
    }
    cout << endl;

    BitonicSort(a, 0, a.size(), 1);

    cout << "Sorted array: " << endl;
    for (auto i=0; i<a.size(); ++i) {
        cout << a[i] << ' ';
    }
    cout << endl;

    return 0;
}
