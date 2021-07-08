#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <math.h>
#include <vector>
#include <algorithm>

#include <time.h>

#include <Eigen/Dense>

#define N 1234
#define bigN 10000
//#define N 12665
#define D 784
#define B 128
#define testN 1000
#define Ep 100
#define IT 5000 //N*Ep/B
#define L 20
#define P 64
#define ignorecoef 3

using namespace std;
using namespace Eigen;

typedef unsigned long int uint64;
typedef Matrix<double,Dynamic,Dynamic> Mat;

void load_train_data(Mat& train_data, Mat& train_label){
	ifstream infile( "../data/mnist_train.csv" );
	cout<<"load training data.......\n";
	{
		int count1=0,count2=0;
		int i=0;
		while(infile){	
			string s;
			if (!getline(infile,s)) 
				break;
			istringstream ss(s);
			int temp;
			char c;
			//read label
			ss>>temp;
			ss>>c;
			if(temp == 0 && count1<N/2){
				train_label(i) = 0;
				count1++;
				//read data (last entry 1)
				for(int j=0;j<D-1;j++){
					ss>>train_data(i,j);
					ss>>c;
				}
				train_data(i,D-1) = 1;
				i++;
			}
			if(temp != 0 && count2<N/2){
				train_label(i) = 1;
				count2++;
				//read data (last entry 1)
				for(int j=0;j<D-1;j++){
					ss>>train_data(i,j);
					ss>>c;
				}
				train_data(i,D-1) = 1;
				i++;
			}
			if(i>=N)
				break;
		}
		train_data.conservativeResize(i, D);
		train_label.conservativeResize(i,1);
		cout<<"n= "<<i<<endl;
	}
	infile.close();
}

void load_test_data(Mat& test_data, Mat& test_label){
	ifstream infile2( "../data/mnist_test.csv" );
    int count1=0, count2=0;
	int i=0;
	cout<<"load testing data.......\n";
	while(infile2){
		string s;
		if (!getline(infile2,s)) 
			break;
		istringstream ss(s);
		int temp;
		char c;
		//read label
		ss>>temp;
		ss>>c;
		//if(temp == 0 || temp == 1){
			test_label(i) = (temp!=0);
			//read data (last entry 1)
			for(int j=0;j<D-1;j++){
				ss>>test_data(i,j);
				ss>>c;
			}	
			test_data(i,D-1) = 1;
			i++;
		// }
        if (i >= testN) break;
	}
    cout << "n=" << i << endl;
	test_data.conservativeResize(i, D);
	test_label.conservativeResize(i,1);
	infile2.close();
	return;
}

void next_batch(Mat &batch, uint32_t &start, Mat A) {
    for (auto i=0; i<B; ++i) {
        batch.row(i) = A.row(start);
        start = (start + 1) % A.rows();
    }
}

void next_batch_perm(Mat &batch, uint32_t &start, Mat A, vector<int32_t> perm) {
    for (auto i=0; i<B; ++i) {
        if (perm[start] == -1) {
            batch.row(i).setZero();
        } else {
            batch.row(i) = A.row(perm[start]);
        }
        start = (start + 1) % perm.size();
    }
}

void linear_function(Mat x, Mat w, Mat &fx) {
    fx = x * w;
}

void logistic_function(Mat x, Mat w, Mat &fx) {
    fx = x * w;
    for (auto i=0; i<fx.rows(); ++i) {
        fx(i) = 1 / (1 + exp(fx(i)));
    }
}

double test_model(Mat w, Mat x, Mat y) {
    Mat y_;
    logistic_function(x, w, y_);
    uint32_t count = 0, all = y.rows();
    for (auto i=0; i<all; ++i) {
        if (y_(i) > 0.5 && y(i) == 1) {
            ++count;
        } else if (y_(i) < 0.5 && y(i) == 0) {
            ++count;
        }
    }
    return 1.0 * count / all;
}

int main(int argc, char** argv) {
    // load data
    Mat train_data(N,D), train_label(N,1);
    Mat test_data(testN,D), test_label(testN,1);
    load_train_data(train_data, train_label);
    load_test_data(test_data, test_label);
    srand(time(0));

    for (auto i=0; i<train_data.rows(); ++i) {
        // train_data.row(i) /= train_data.row(i).maxCoeff();
        train_data.row(i).normalize();
    }
    for (auto i=0; i<test_data.rows(); ++i) {
        // test_data.row(i) /= test_data.row(i).maxCoeff();
        test_data.row(i).normalize();
    }
    
    // training phase
    Mat W(D, 1);
    for (auto i=0; i<D; ++i) {W(i) = 0;}
    W.normalize();
    W /= B;
    Mat x_batch(B,D), tx_batch, y_batch(B,1);
    Mat fx_batch(B, 1), delta(D, 1);

    uint32_t batchcheck = 10;
    uint32_t start_data = 0, start_label = 0;
    double lr = 0.0024 / 2.7 / 2.4; 
    //0.0024

    vector<int32_t> perm(N);
    for (auto i=0; i<N; ++i) {
        perm[i] = i;
    }
    random_shuffle(perm.begin(), perm.end());

    vector<double> accuracy;
    for (auto i=0; i<IT; ++i) {
        next_batch_perm(x_batch, start_data, train_data, perm);
        next_batch_perm(y_batch, start_label, train_label, perm);
        tx_batch = x_batch.transpose();
        logistic_function(x_batch, W, fx_batch);
        delta = tx_batch * (fx_batch - y_batch);
        // cout << (fx_batch - y_batch) << endl;
        // delta = delta / delta.norm();
        W = W - delta * lr;
        if (i % batchcheck == 0) {
            accuracy.push_back(test_model(W, test_data, test_label));
            cout << i << ' ' << test_model(W, test_data, test_label) << endl;
        }
    }

    vector<double> acc_dummy, acc_puri;
    vector<int32_t> perm_dummy(bigN), perm_puri(bigN);
    for (auto i=0; i<bigN; ++i) {
        perm_dummy[i] = (i < N) ? i : -1;
        perm_puri[i] = i % N;
    }
    random_shuffle(perm_dummy.begin(), perm_dummy.end());
    // random_shuffle(perm_puri.begin(), perm_dummy.end());

    W.setZero();
    start_data = start_label = 0;
    for (auto i=0; i<IT; ++i) {
        next_batch_perm(x_batch, start_data, train_data, perm_dummy);
        next_batch_perm(y_batch, start_label, train_label, perm_dummy);
        tx_batch = x_batch.transpose();
        logistic_function(x_batch, W, fx_batch);
        delta = tx_batch * (fx_batch - y_batch);
        // delta = delta / delta.norm();
        W = W - delta * lr;
        if (i % batchcheck == 0) {
            acc_dummy.push_back(test_model(W, test_data, test_label));
            cout << i << ' ' << test_model(W, test_data, test_label) << endl;
        }
    }

    W.setZero();
    start_data = start_label = 0;
    for (auto i=0; i<IT; ++i) {
        next_batch_perm(x_batch, start_data, train_data, perm_puri);
        next_batch_perm(y_batch, start_label, train_label, perm_puri);
        tx_batch = x_batch.transpose();
        logistic_function(x_batch, W, fx_batch);
        delta = tx_batch * (fx_batch - y_batch);
        // delta = delta / delta.norm();
        W = W - delta * lr;
        if (i % batchcheck == 0) {
            acc_puri.push_back(test_model(W, test_data, test_label));
            cout << i << ' ' << test_model(W, test_data, test_label) << endl;
        }
    }  

    // output phase
    freopen("train_log.log", "w", stdout);
    for (auto i=1; i<acc_puri.size(); ++i) {
        cout << i * batchcheck << ' ' << accuracy[i] << ' ' << acc_dummy[i] << ' ' << acc_puri[i] << endl;
    }
}
