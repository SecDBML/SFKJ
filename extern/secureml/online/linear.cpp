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

#define N 10000
//#define N 12665
#define D 784
#define B 128
#define testN 10000
#define Ep 200
#define IT N*Ep/B
#define L 20
#define P 64

using namespace std;
using namespace Eigen;

typedef unsigned long int uint64;
typedef Matrix<unsigned long int,Dynamic,Dynamic> Mat;

NetIO * io;

Mat reconstruct(Mat A, int party){
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
		
		
		for(int i=0;i<A_rec.rows();i++){
			for(int j=0;j<A_rec.cols();j++)
				cout<<A_rec(i,j)<<",";
			cout<<";";
		}
		cout<<endl;
		
		
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

void load_train_data(Mat& train_data0, Mat& train_label0, Mat& xa, int party){
	ifstream F( "data"+to_string(party)+".txt" );
	ifstream F2("xa.txt");
	
	
	int i=0;
	
	//cout<<"load training data.......\n";
	
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

void load_test_data(Mat& test_data, Mat& test_label){
	ifstream infile2( "../data/mnist_test.csv" );
	int count1=0,count2=0;
	int i=0;
	
	//cout<<"load testing data.......\n";
	
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
		//}

	}
	
	test_data.conservativeResize(i, D);
	test_label.conservativeResize(i,1);
	
	infile2.close();
	
	return;
}

vector<int> read_MT(Mat& a,Mat& b_1,Mat& c_1,Mat& b_2,Mat& c_2, int party){
	
	
	vector<int> perm(Ep*N,0);
	
	
	ifstream F("MT"+to_string(party)+".txt");
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
	Mat f,d;
	f = W0-b0+Wb1;
	d = x0*f+e*W0+c0-y0*(unsigned long int)(1<<(L+8));
	return d;
	
}

Mat compute_delta1(Mat& W1,Mat& x1, Mat& y1, Mat& e, Mat& b1,Mat& c1, Mat& Wb0 ){
	Mat f,d;
	f = W1-b1+Wb0;
	d = x1*f+e*(W1-f)+c1-y1*(unsigned long int)(1<<(L+8));
	return d;
	
}

void update_W0(Mat& W0,Mat& x0,Mat& e, Mat& b0,Mat& d0, Mat& c0, Mat& db1){
	Mat f, delta;
	
	f = d0-b0+db1;
	delta = x0*f+e*d0+c0;
	
	//reconstruct(delta,1);
	
	for(int i=0;i<delta.rows();i++){
		delta(i) = (long int)delta(i)/ ((long int)(1<<23)*B);
	}
	//reconstruct(delta,1);
	
	W0 = W0 - delta;
	
}

void update_W1(Mat& W1,Mat& x1,Mat& e, Mat& b1,Mat& d1, Mat& c1, Mat& db0){
	Mat f, delta;
	
	f = d1-b1+db0;
	
	delta = x1*f+e*(d1-f)+c1;
	
	//reconstruct(delta,2);
	
	for(int i=0;i<delta.rows();i++){
		delta(i) = (long int)delta(i)/ ((long int)(1<<23)*B);
	}
	
	//reconstruct(delta,2);
	
	W1 = W1 - delta;


	
}

double test_model(Mat& W0, Mat& W1, Mat& x, Mat& y){
	Mat y_,W;
	double temp1;
	long int temp2,temp3;
	
	W = W0+W1;
	y_ = x*W;
	
	int count = 0;
	
	for(int i=0;i<y.rows();i++){
		temp3 = (long int)y_(i);
		//temp3 = (temp3<<4);
		
		//if(temp3>conv<long int>(p)/2)
		//	temp3 = temp3-conv<long int>(p);
		
		temp1 = temp3/(double)pow(2,L+8);
		//temp1 = conv<long int>(y_[i][0])/(double)pow(2,L);
		temp2 = (long int)y(i);
		
		//if(temp2>conv<long int>(p)/2)
		//	temp2 = temp2-conv<long int>(p);
		
		if(temp1>0.5 && temp2 == 1){
			count++;
		}
		else if(temp1<0.5 && temp2 == 0){
			count++;
		}
	}
	return count/(double)y.rows();
	
	
}



int main(int argc, char** argv){
	
	clock_t t1,t2,t3;
	
	//setup connection
	int port, party;
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==ALICE ? nullptr : "172.31.13.143", port);
	io->set_nodelay();

	
	Mat train_data(N,D), train_label(N,1), xa(N,D);
	
	load_train_data(train_data, train_label, xa, party-1);
	
	Mat test_data(testN,D), test_label(testN,1);
	
	if(party == ALICE){
		
		load_test_data(test_data, test_label);
	}
	
	//cout<<"reading multiplication triples......\n";

	Mat a(N,D),b_1(D,IT),c_1(B,IT),b_2(B,IT),c_2(D,IT);
	
	t1 = clock();

	vector<int> perm = read_MT(a,b_1,c_1,b_2,c_2,party-1);

	//cout<<(double)(clock()-t1)/CLOCKS_PER_SEC<<"s for reading"<<endl;
	
	
	
	//cout<<(reconstruct(train_data-a,party)==xa)<<"!!!!\n";
	
	Mat W(D,1);
	W.setZero();
	

	Mat x_batch(B,D), tx_batch,txa_batch, y_batch(B,1), xa_batch(B,D), b_IT1(D,1), b_IT2(B,1),c_IT1(B,1), c_IT2(D,1);
	
	Mat W0b(D,1),W1b(D,1),d0_buf(B,1),d1_buf(B,1);
	
		
    double total_time = 0.0, communication = 0.0, computation = 0.0, batchtime = 0.0;
	int start = 0;
	
	//start training
	for(int i=0;i<IT;i++){
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
		
		//Mat a_batch(B,D);
		//next_batch(a_batch,start,perm,a);
		//cout<<(reconstruct(a_batch,party)*reconstruct(b_IT1,party) == reconstruct(c_IT1,party))<<endl;
		
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

		
			for(int j=0;j<W0b.rows();j++){
				for(int k=0;k<W0b.cols();k++)
					W0b(j,k) = temp0[j*W0b.cols()+k];
			}
		
		}
		
		communication += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();
		//t2=clock();
		//cout<<(double)(t2-t1)/CLOCKS_PER_SEC<<endl;
		//t1=clock();
		
		
		//train step1
		
		if(party == ALICE){
			d0 = compute_delta0(W,x_batch, y_batch, xa_batch, b_IT1,c_IT1, W1b );
			d0_buf = d0-b_IT2;
			//reconstruct(d0,party);
		}
		else{
			d1 = compute_delta1(W,x_batch, y_batch, xa_batch, b_IT1,c_IT1, W0b );
			d1_buf = d1-b_IT2;
			
			//reconstruct(d1,party);
		}
		
		computation += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();
		
		//t2=clock();
		//cout<<(double)(t2-t1)/CLOCKS_PER_SEC<<endl;
		//t1=clock();
		
		
		//send and receive data
		vector<unsigned long int> d_temp0(d0_buf.cols()*d0_buf.rows()),d_temp1(d1_buf.cols()*d1_buf.rows());
	

		if(party == ALICE){
			for(int j=0;j<d0_buf.rows();j++){
				for(int k=0;k<d0_buf.cols();k++)
					d_temp0[j*d0_buf.cols()+k] = d0_buf(j,k);
			}

			io->send_data(&d_temp0[0],sizeof(unsigned long int)*d_temp0.size());
			io->recv_data(&d_temp1[0],sizeof(unsigned long int)*d_temp1.size());
		
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
			

			for(int j=0;j<d0_buf.rows();j++){
				for(int k=0;k<d0_buf.cols();k++)
					d0_buf(j,k) = d_temp0[j*d0_buf.cols()+k];
			}
		
		}
		
		
		communication += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();
		
		//t2=clock();
		//cout<<(double)(t2-t1)/CLOCKS_PER_SEC<<endl;
		//t1=clock();
		
		//train step2
		
		if(party == ALICE){
			update_W0(W,tx_batch,txa_batch, b_IT2,d0, c_IT2, d1_buf); 
		}
		else{
			update_W1(W,tx_batch, txa_batch, b_IT2,d1, c_IT2, d0_buf);
		}
		
		
		computation += (double)(clock()-t1)/CLOCKS_PER_SEC;
		t1=clock();
		
		//reconstruct(W,party);
		
		//t2=clock();
		//cout<<(double)(t2-t1)/CLOCKS_PER_SEC<<endl;
		
		
		total_time += (double)(clock()-t3)/CLOCKS_PER_SEC;
		

		
		
		if(i%1==1){
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
				cout<<res<<endl;
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
		
	}
	
	
	
	cout<<total_time<<endl;
	//cout<<"total time:"<<total_time<<"s!!"<<endl;
	//cout<<"batch time:"<<batchtime<<"s!!"<<endl;
	//cout<<"communication time:"<<communication<<"s!!"<<endl;
	//cout<<"computation time:"<<computation<<"s!!"<<endl;
	
	delete io;
	
}