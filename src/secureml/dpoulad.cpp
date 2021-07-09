#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <math.h>
#include <vector>
#include <algorithm>

#include <time.h>

#include <emp-tool/emp-tool.h>

#include <Eigen/Dense>

#include "./common.h"

using namespace std;
using namespace Eigen;
using namespace emp;

typedef unsigned long int uint64;
typedef Matrix<unsigned long,Dynamic,Dynamic> Mat;
typedef Matrix<double,Dynamic,Dynamic> MatD;

// oulad coefficient
// # -0.00427, 0.00276, -0.168, 0.0206, 0, 0.0127, -0.373

long float_part[] = {(long)(1 * (1LL<<27)), (long)(1.0 * (1LL<<27)), (long)(1 * (1LL<<27)), (long)(1 * (1LL<<27)), (long)(1 * (1LL<<27)), (long)(1 * (1LL<<27)), (long)(1 * (1LL<<27))};
uint32_t normalrate = 4;
uint64_t comm_cost = 0;

NetIO * io;

Mat reconstruct(Mat A, int party, bool div=false, ofstream *of=NULL){
	vector<unsigned long int> A_temp(A.cols()*A.rows());
	
	int tempi = 10;
	if(party==ALICE){
		io->send_data(&tempi,4);
		io->recv_data(&A_temp[0],sizeof(unsigned long int)*A_temp.size());
		Mat A_(A.rows(),A.cols());
		for(int i=0;i<A_.rows();i++){
			for(int j=0;j<A_.cols();j++){
				A_(i,j) = A_temp[i*A_.cols()+j];
			}
		}
		
		Mat A_rec = A+A_;
		// std::cout << "A: \n";
		// for(int i=0;i<A_rec.rows();i++){
		// 	for(int j=0;j<A_rec.cols();j++)
		// 		cout<<A(i,j)<<",";
		// 	cout<<";";
		// }
		// cout<<endl;
		// std::cout << "A_: \n";
		// for(int i=0;i<A_rec.rows();i++){
		// 	for(int j=0;j<A_rec.cols();j++)
		// 		cout<<A_(i,j)<<",";
		// 	cout<<";";
		// }
		// cout<<endl;
		// std::cout << "reconstruct: \n";
		if (div) {
			for(int i=0;i<A_rec.rows();i++){
				for(int j=0;j<A_rec.cols();j++) {
					cout<<static_cast<float>((long)A_rec(i,j))/(1 << (L))<<",";
					if (of != NULL)
						*of << static_cast<float>((long)A_rec(i,j))/(1 << (L))<<",";
				}
				cout<<";";
			}
		} else {
			for(int i=0;i<A_rec.rows();i++){
				for(int j=0;j<A_rec.cols();j++)
					cout<<(long) A_rec(i,j)<<",";
				cout<<";";
			}
		}
		cout<<endl;
		if (of != NULL)
			*of << endl;
		
		
		//cout<<A_rec<<endl;
		
		return A_rec;
	}
	else{
		for(int i=0;i<A.rows();i++){
			for(int j=0;j<A.cols();j++)
				A_temp[i*A.cols()+j] = A(i,j);
		}
		
		io->recv_data(&tempi,4);
		io->send_data(&A_temp[0],sizeof(unsigned long int)*A_temp.size());
		

		return A;
	}


}

void load_dp_noise(Mat& dp, int party) {
    ifstream F( "../data/dpnoise" + to_string(party - 1) + ".txt" );

    cout << "load dp noise data.......\n";

    for (auto i=0; i<IT; ++i) {
        string s;
        if (!getline(F, s)) {
            break;
        }
        istringstream ss(s);
		char c;
        for (auto j=0; j<D; ++j) {
            ss >> dp(i, j);
            ss >> c;
        }
    }
    
    F.close();
    cout << "load finished......\n";
    cout << "load " << dp.rows() << 'X' << dp.cols() << " data" << endl;
    reconstruct(dp.row(0), party, 1);
}

void load_train_data(Mat& train_data0, Mat& train_label0, Mat& xa, int party){
	ifstream F( "../data/data"+to_string(party)+".txt" );
	ifstream F2("../data/xa.txt");
	
	if (party == 1)
		cout << "opened data1.txt\n";
	
	int i=0;
	
	cout<<"load training data.......\n";
	
	while(i<N){
		
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		char c;
		
		
		//read data
		for(int j=0;j<D;j++){
			ss>>train_data0(i,j);
			ss>>c;
			
		}
		
		i++;

	}
	
	
	i=0;
	
	while(i<N){
		
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		char c;
		
		
		//read data
		
		ss>>train_label0(i);
		ss>>c;
		
		
		i++;

	}
	
	i=0;
	
	while(i<N){
		
		string s;
		if (!getline(F2,s)) 
			break;
		istringstream ss(s);
		char c;
		
		
		//read data
		for(int j=0;j<D;j++){
			ss>>xa(i,j);
			ss>>c;
		}
		
		i++;

	}
	
	
	F.close();
	F2.close();
	return;

}

void load_test_data(MatD& data, MatD& label){
	ifstream infile("../data/oulad.dat" );
	int i=0;
    string s;
    // getline(infile,s);
    // getline(infile,s);
    // getline(infile,s);
	//cout<<"load testing data.......\n";
	while(infile){
		if (!getline(infile,s)) 
			break;
		istringstream ss(s);
		int temp;
		char c;

		ss >> label(i);
		ss >> c;
        for (int j=0; j<D-1; ++j) {
            ss>>data(i,j);
			ss>>c;
        }
        data(i,D-1) = 1;
		data.row(i) /= 32;
		// data.row(i).normalize();

        // string name;
        // ss>>name;
        // if (name == "setosa") label(i) = 0;
        // else if (name == "versicolor") label(i) = 1;
        // else if (name == "virginica") label(i) = 2;
        ++i;
		if (i >= testN) break;
        
	}
	data.conservativeResize(i, D);
	label.conservativeResize(i,1);
	infile.close();
	cout << "data = " << data.row(0) << ' ' << label.row(0) << endl;
	return;
}

vector<int> read_MT(Mat& a,Mat& b_1,Mat& c_1,Mat& b_2,Mat& c_2, int party){
	
	
	vector<int> perm(Ep*N,0);
	
	
	ifstream F("../data/MT"+to_string(party)+".txt");
	char temp;
	
	{
		string s;
		getline(F,s);
		
		
		istringstream ss(s);
		
		for(int i=0;i<Ep*N;i++){
			ss>>perm[i];
			ss>>temp;		
		}
	}
	
	
	
	for(int i=0;i<N;i++){
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		for(int j=0;j<D;j++){
			ss>>a(i,j);
			
			ss>>temp;
		}	
	}
	
	
	for(int i=0;i<D;i++){
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		for(int j=0;j<IT;j++){
			ss>>b_1(i,j);
			ss>>temp;
		}	
	}
	
	
	for(int i=0;i<B;i++){
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		for(int j=0;j<IT;j++){
			ss>>b_2(i,j);
			ss>>temp;
		}	
	}
	
	
	for(int i=0;i<B;i++){
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		for(int j=0;j<IT;j++){
			ss>>c_1(i,j);
			ss>>temp;
		}	
	}
	
	
	
	for(int i=0;i<D;i++){
		string s;
		if (!getline(F,s)) 
			break;
		istringstream ss(s);
		for(int j=0;j<IT;j++){
			ss>>c_2(i,j);
			ss>>temp;
		}	
	}
	

	
	F.close();
	
	return perm;
	
}

void next_batch(Mat& batch,int start, vector<int>& perm, Mat& A){
	
	
	for(int i=0;i<B;i++){
		batch.row(i) = A.row(perm[start+i]);
	}
	return ;
}

Mat compute_delta0(Mat& W0,Mat& x0, Mat& y0, Mat& e, Mat& b0,Mat& c0, Mat& Wb1 ){
	Mat f,d, d2;
	f = W0-b0+Wb1;
	d2 = x0*f + e*W0+c0;
	// std::cout << "x:\n";
	// reconstruct(x0, 1);
	// std::cout << "wx\n";
	// reconstruct(d2,1);
	for (int i = 0; i < d2.rows(); i++) {
		for (int j = 0; j < d2.cols(); j++) {
			d2(i, j) = static_cast<long>(d2(i, j)) / (1 << (L));
		}
	}
	d = d2-y0;

	return d;
	
}

Mat compute_delta1(Mat& W1,Mat& x1, Mat& y1, Mat& e, Mat& b1,Mat& c1, Mat& Wb0 ){
	Mat f,d, d2;
	f = W1-b1+Wb0;
	d2 = x1*f + e*(W1-f) + c1;
	// reconstruct(x1, 2);
	// reconstruct(d2,2);
	for (int i = 0; i < d2.rows(); i++) {
		for (int j = 0; j < d2.cols(); j++) {
			d2(i, j) = static_cast<long>(d2(i, j)) / (1 << (L));
		}
	}
	d = d2-y1;
	
	return d;
	
}

void update_W0(Mat& W0,Mat& x0,Mat& e, Mat& b0,Mat& d0, Mat& c0, Mat& db1, Mat dp){
	Mat f, delta;
	Mat regular(W0.rows(), W0.cols());
	for (int i = 0; i < W0.rows(); i++) {
	  for (int j = 0; j < W0.cols(); j++)
	  	regular(i, j) = 0;//(long int)W0(i, j) /(1 << normalrate);
	}
	
	f = d0-b0+db1;
	delta = x0*f+e*d0+c0;
    reconstruct(dp, 2, 1);
    delta = delta + dp;
	
	// std::cout << "delta before division\n";
	reconstruct(delta,2, 1);
	for(int i=0;i<delta.rows();i++){
		delta(i) = ((long int) delta(i) /float_part[i]);
	}
	// reconstruct(delta,2);  reconstruct(regular,2);
	reconstruct(delta+regular, 2, 1);
	
	W0 = W0 - (regular + delta);
	
}

void update_W1(Mat& W1,Mat& x1,Mat& e, Mat& b1,Mat& d1, Mat& c1, Mat& db0, Mat dp){
	Mat f, delta;
	Mat regular(W1.rows(), W1.cols());
	for (int i = 0; i < W1.rows(); i++) {
	  for (int j = 0; j < W1.cols(); j++)
	  	regular(i, j) = 0;//(long int)W1(i, j) /(1 << normalrate);
	}
	f = d1-b1+db0;
	
	delta = x1*f+e*(d1-f)+c1;

    cout << "dp " << endl;
    reconstruct(dp, 1, 1);
    delta = delta + dp;
	cout << "delta before" << endl;
	reconstruct(delta,1, 1);
	
	for(int i=0;i<delta.rows();i++){
		delta(i) = ((long int) delta(i) / float_part[i]);
	}	

	std::cout << "delta after division\n";
	// reconstruct(delta,1);	reconstruct(regular,1);
	reconstruct(regular + delta, 1, 1);

	W1 = W1 - (regular + delta);
	
}

double test_model(Mat& W0, Mat& W1, MatD& x, MatD& y, int flag = 0){
	Mat y_,W;
	double temp1;
	double temp2,temp3;
	Matrix<double,Dynamic,Dynamic> temp(1, D), tempW(D, 1);
	W = W0+W1;
	for (auto i=0; i<D; ++i) {
		tempW(i) = static_cast<float>((long)W(i))/(1 << (L));
	}
	
	int count = 0;

	for(int i=0;i<y.rows();i++){
		for (auto j=0; j<D; ++j) {
			temp(0, j) = x(i, j);
		}
		// temp.normalize();
		double value = 0;
		for (auto j=0; j<D; ++j) {
			value += temp(0, j) * tempW(j, 0);
		}
		temp3 = round(value);
		temp2 = y(i);
		
		//if(temp2>conv<long int>(p)/2)
		//	temp2 = temp2-conv<long int>(p);
		if (flag) {
			cout << "W = " <<  tempW << endl;
			cout << "X = " << temp.row(0) << endl;
			cout << " ========> res = " << value << ' ' << temp3 << ' ' << temp2 << endl;
		}
		float delta = abs(temp3 - temp2) / (float) temp2;
		// std::cout << delta;
		if(round(temp3) == temp2){
			count++;
		}
	}
	// cout << "acc = " << count/(double)y.rows() << endl;
	return count/(double)y.rows();
	
	
}

int main(int argc, char** argv){
	
	clock_t t1,t2,t3;
	
	//setup connection
	int port, party;
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
	io->set_nodelay();
	ofstream wlog;
	if (party == ALICE)
		wlog.open("wlog.txt");
	
	Mat train_data(N,D), train_label(N,1), xa(N,D);
	
	load_train_data(train_data, train_label, xa, party-1);
	
	MatD test_data(testN,D), test_label(testN,1);
    
    Mat dp_noise(IT, D);
    load_dp_noise(dp_noise, party);
    dp_noise.conservativeResize(300, D);

	if (party == ALICE) {
		load_test_data(test_data, test_label);
	}
	
	//cout<<"reading multiplication triples......\n";

	Mat a(N,D),b_1(D,IT),c_1(B,IT),b_2(B,IT),c_2(D,IT);
	
	t1 = clock();

	vector<int> perm = read_MT(a,b_1,c_1,b_2,c_2,party-1);
	
	Mat W(D,1);
	W.setZero();

	Mat x_batch(B,D), tx_batch,txa_batch, y_batch(B,1), xa_batch(B,D), b_IT1(D,1), b_IT2(B,1),c_IT1(B,1), c_IT2(D,1);
	
	Mat W0b(D,1),W1b(D,1),d0_buf(B,1),d1_buf(B,1);
	
		
    double total_time = 0.0, communication = 0.0, computation = 0.0, batchtime = 0.0;
	int start = 0;

	auto sttime = clock();
	// vector<int> itstamp = {150, 400, 450, 650, 700, 1150, 1550, 2200};
	// uint32_t itid = 0;

	//start training
	for(int i=0;i<IT;i++){
		// std::cout << i << " iteration, W\n";
		reconstruct(W, 3 - party, true, &wlog);
		Mat d0,d1,W_rec;
		
		t1=clock();
		
		next_batch(x_batch,start,perm,train_data);
		next_batch(y_batch,start,perm,train_label);
		tx_batch = x_batch.transpose();
		
		
		next_batch(xa_batch,start,perm,xa);
		txa_batch = xa_batch.transpose();
		
		b_IT1=b_1.col(i);
		b_IT2=b_2.col(i);
		c_IT1=c_1.col(i);
		c_IT2=c_2.col(i);
		
		batchtime += (double)(clock()-t1)/CLOCKS_PER_SEC;
		
		start+= B;
		
		t1=clock();
		t3 = clock();
		//send and receive data
		
		
		if(party == ALICE){
			W0b = W-b_IT1;
		}
		else{
			W1b = W-b_IT1;
		}
		
		vector<unsigned long int> temp0(W0b.cols()*W0b.rows()),temp1(W1b.cols()*W1b.rows());
	
		if(party == ALICE){
	
			for(int j=0;j<W0b.rows();j++){
				for(int k=0;k<W0b.cols();k++)
					temp0[j*W0b.cols()+k] = W0b(j,k);
			}
			
			io->send_data(&temp0[0],sizeof(unsigned long int)*temp0.size());
			io->recv_data(&temp1[0],sizeof(unsigned long int)*temp1.size());
			comm_cost += sizeof(unsigned long int)*temp0.size();
			comm_cost += sizeof(unsigned long int)*temp1.size();
			
			for(int j=0;j<W1b.rows();j++){
				for(int k=0;k<W1b.cols();k++)
					W1b(j,k) = temp1[j*W1b.cols()+k];
			}
			
		}
		else{
			for(int j=0;j<W1b.rows();j++){
				for(int k=0;k<W1b.cols();k++)
					temp1[j*W1b.cols()+k] = W1b(j,k);
			}
			
			io->recv_data(&temp0[0],sizeof(unsigned long int)*temp0.size());
			io->send_data(&temp1[0],sizeof(unsigned long int)*temp1.size());
			comm_cost += sizeof(unsigned long int)*temp0.size();
			comm_cost += sizeof(unsigned long int)*temp1.size();

		
			for(int j=0;j<W0b.rows();j++){
				for(int k=0;k<W0b.cols();k++)
					W0b(j,k) = temp0[j*W0b.cols()+k];
			}
		
		}
		
		communication += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();

		if(party == ALICE){
			// std::cout << "x_batch\n";
			// reconstruct(x_batch, ALICE);
			d0 = compute_delta0(W,x_batch, y_batch, xa_batch, b_IT1,c_IT1, W1b );
			d0_buf = d0-b_IT2;
			// reconstruct(d0,party);
		}
		else{
			// std::cout << "x_batch\n";
			// reconstruct(x_batch, BOB);
			d1 = compute_delta1(W,x_batch, y_batch, xa_batch, b_IT1,c_IT1, W0b );
			d1_buf = d1-b_IT2;
			
			// reconstruct(d1,party);
		}
		
		computation += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();

		vector<unsigned long int> d_temp0(d0_buf.cols()*d0_buf.rows()),d_temp1(d1_buf.cols()*d1_buf.rows());
	

		if(party == ALICE){
			for(int j=0;j<d0_buf.rows();j++){
				for(int k=0;k<d0_buf.cols();k++)
					d_temp0[j*d0_buf.cols()+k] = d0_buf(j,k);
			}

			io->send_data(&d_temp0[0],sizeof(unsigned long int)*d_temp0.size());
			io->recv_data(&d_temp1[0],sizeof(unsigned long int)*d_temp1.size());

			comm_cost += sizeof(unsigned long int)*d_temp0.size();
			comm_cost += sizeof(unsigned long int)*d_temp1.size();
		
			for(int j=0;j<d1_buf.rows();j++){
				for(int k=0;k<d1_buf.cols();k++)
					d1_buf(j,k) = d_temp1[j*d1_buf.cols()+k];
			}
		}
		else{
			for(int j=0;j<d1_buf.rows();j++){
				for(int k=0;k<d1_buf.cols();k++)
					d_temp1[j*d1_buf.cols()+k] = d1_buf(j,k);
			}
			
			io->recv_data(&d_temp0[0],sizeof(unsigned long int)*d_temp0.size());
			io->send_data(&d_temp1[0],sizeof(unsigned long int)*d_temp1.size());
			
			comm_cost += sizeof(unsigned long int)*d_temp0.size();
			comm_cost += sizeof(unsigned long int)*d_temp1.size();

			for(int j=0;j<d0_buf.rows();j++){
				for(int k=0;k<d0_buf.cols();k++)
					d0_buf(j,k) = d_temp0[j*d0_buf.cols()+k];
			}
		
		}
		
		
		communication += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();
		
        double var = 0;
		
		if(party == ALICE){
			update_W0(W,tx_batch,txa_batch, b_IT2,d0, c_IT2, d1_buf, dp_noise.row(i % 300).transpose()* (int)((1<<L) * var / 2.0)); 
		}
		else{
			update_W1(W,tx_batch, txa_batch, b_IT2,d1, c_IT2, d0_buf, dp_noise.row(i % 300).transpose()* (int)((1<<L) * var / 2.0));
		}
		
		
		computation += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();
		
		
		
		total_time += (double)(clock()-t3)/CLOCKS_PER_SEC;
		
		
		if(i%10==0){
			// normalrate += 1;
			// for (auto id = 0; id < D; ++id) {
			// 	float_part[id] *= 2.0;
			// }
			vector<long int> W_temp(W.cols()*W.rows());
			int tempi = 10;
			Mat W1(D,1);
			
			if(party==ALICE){
			
				io->send_data(&tempi,4);
				io->recv_data(&W_temp[0],sizeof(unsigned long int)*W_temp.size());
				
				
				for(int j=0;j<W1.rows();j++){
					for(int k=0;k<W1.cols();k++)
						W1(j,k) = W_temp[j*W1.cols()+k];
				}
				
				
				double res = test_model(W,W1,test_data, test_label);
				cout<< "acc = " << res<<endl;
			}
			else{
				for(int j=0;j<W.rows();j++){
					for(int k=0;k<W.cols();k++)
						W_temp[j*W.cols()+k] = W(j,k);
				}
				io->recv_data(&tempi,4);
				io->send_data(&W_temp[0],sizeof(unsigned long int)*W_temp.size());
			}
		}
		// if (i == itstamp[itid]) {
			// auto edt = clock();
			// cout << itstamp[itid] << ' ' << 1.0 * (edt - sttime) / CLOCKS_PER_SEC << endl;
			// itid++;
		// }
	} // for
	

	cout << "final W" << endl;
	reconstruct(W, party, true, &wlog);

	wlog.close();
	cout<<"total time = " << total_time<< endl;
	cout<<"comm cost = " << comm_cost / 1024.0 / 1024.0<< endl;

	{
		vector<long int> W_temp(W.cols()*W.rows());
			int tempi = 10;
			Mat W1(D,1);
			
			if(party==ALICE){
			
				io->send_data(&tempi,4);
				io->recv_data(&W_temp[0],sizeof(unsigned long int)*W_temp.size());
				
				
				for(int j=0;j<W1.rows();j++){
					for(int k=0;k<W1.cols();k++)
						W1(j,k) = W_temp[j*W1.cols()+k];
				}
				
				
				double res = test_model(W,W1,test_data, test_label, 0);
				cout<< "acc = " << res<<endl;
			}
			else{
				for(int j=0;j<W.rows();j++){
					for(int k=0;k<W.cols();k++)
						W_temp[j*W.cols()+k] = W(j,k);
				}
				io->recv_data(&tempi,4);
				io->send_data(&W_temp[0],sizeof(unsigned long int)*W_temp.size());
			}
	}
	delete io;
	
}
