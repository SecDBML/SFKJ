#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <math.h>
#include <vector>
#include <algorithm>

#include <time.h>

#include <Eigen/Dense>

#define N 5500*2
//#define N 12665
#define D 785
#define B 128
#define testN 10000
#define Ep 5
#define IT N*Ep/B
#define L 20
#define P 64

using namespace std;
using namespace Eigen;

typedef unsigned long int uint64;
typedef Matrix<unsigned long int,Dynamic,Dynamic> Mat;

int myrandom (int i) { return rand()%i;}

uint64 randomlong(){
	uint64 rand1 = abs(rand());
    uint64 rand2 = abs(rand());
    rand1 = rand1 << (sizeof(int)*8);   
    uint64 randULL = (rand1 | rand2);   
    return randULL;

}

vector<int> random_perm(){
	vector<int> temp,perm;
	for(int i=0;i<N;i++)
		temp.push_back(i);
	
	for(int i = 0;i<Ep;i++){
		random_shuffle(temp.begin(),temp.end(),myrandom);
		perm.insert(perm.end(),temp.begin(),temp.end());
		
	}
	return perm;
}

void next_batch(Mat& batch,int start, vector<int>& perm, Mat& A){
	
	
	for(int i=0;i<B;i++){
		batch.row(i) = A.row(perm[start+i]);
	}
	return ;
}

void set_multiplication_triples(Mat& a0,Mat& a1,Mat& b0_1,Mat& b1_1,Mat& c0_1,Mat& c1_1,Mat& b0_2,Mat& b1_2,Mat& c0_2,Mat& c1_2,vector<int> perm){
	
	for(int i=0;i<a0.rows();i++){
		for(int j=0;j<a0.cols();j++){
			a0(i,j) = randomlong();
			a1(i,j) = randomlong();
		}
	}
	
	for(int i=0;i<b0_1.rows();i++){
		for(int j=0;j<b0_1.cols();j++){
			b0_1(i,j) = randomlong();
			b1_1(i,j) = randomlong();
		}
	}
	
	for(int i=0;i<b0_2.rows();i++){
		for(int j=0;j<b0_2.cols();j++){
			b0_2(i,j) = randomlong();
			b1_2(i,j) = randomlong();
		}
	}
	
	/*
	a0.setRandom();
	a1.setRandom();
	b0_1.setRandom();
	b1_1.setRandom();
	c0_1.setRandom();
	b0_2.setRandom();
	b1_2.setRandom();
	c0_2.setRandom();
	*/
	
	int start_setup = 0;
	for(int i=0;i<IT;i++){
		Mat c_1, c_2, a_batch0(B,D), a_batch1(B,D), b1(D,1),b2(B,1), a(B,D);
		
		next_batch(a_batch0, start_setup,perm,a0);
		next_batch(a_batch1, start_setup,perm,a1);
		
		a = a_batch0+a_batch1;
		
		b1 = b0_1.col(i)+b1_1.col(i);
		
		c_1 = a*b1;
		
		c1_1.col(i)=c_1-c0_1.col(i);
		for(int j=0;j<B;j++){
			c0_1(j,i) = randomlong();
			c1_1(j,i) = c_1(j) - c0_1(j,i);
		}
		
		
		b2 = b0_2.col(i)+b1_2.col(i);
		
		c_2 = a.transpose()*b2;
		
		//c1_1.col(i)=c_1-c0_1.col(i);
		
		for(int j=0;j<D;j++){
			c0_2(j,i) = randomlong();
			c1_2(j,i) = c_2(j) - c0_2(j,i);
		}
		
		start_setup+=B;
		
	}
	
	
	return;
}

int main(int argc, char** argv){
	
	srand ( unsigned ( time(NULL) ) );
	clock_t t1,t2;
	
	
	
	Mat a0(N,D),a1(N,D),b0_1(D,IT),b1_1(D,IT),c0_1(B,IT),c1_1(B,IT),b0_2(B,IT),b1_2(B,IT),c0_2(D,IT),c1_2(D,IT);
	
	vector<int> perm = random_perm();
	
	cout<<"generating multiplication triples......\n";
	
	t1=clock();
	
	set_multiplication_triples(a0,a1,b0_1,b1_1,c0_1,c1_1,b0_2,b1_2,c0_2,c1_2,perm);
	
	cout<<(double)(clock()-t1)/CLOCKS_PER_SEC<<"s"<<endl;
	
	
	t1=clock();
	
	ofstream F1, F2;
	
	F1.open ("MT0.txt");
	F2.open ("MT1.txt");
	
	for(int i=0;i<perm.size();i++){
		F1<<perm[i]<<",";
		F2<<perm[i]<<",";
		
	}
	F1<<endl;
	F2<<endl;
	
	for(int i=0;i<a0.rows();i++){
		for(int j=0;j<a0.cols();j++){
			F1<<a0(i,j)<<",";
			F2<<a1(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}
	
	for(int i=0;i<b0_1.rows();i++){
		for(int j=0;j<b0_1.cols();j++){
			F1<<b0_1(i,j)<<",";
			F2<<b1_1(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}
		
	for(int i=0;i<b0_2.rows();i++){
		for(int j=0;j<b0_2.cols();j++){
			F1<<b0_2(i,j)<<",";
			F2<<b1_2(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}

	for(int i=0;i<c0_1.rows();i++){
		for(int j=0;j<c0_1.cols();j++){
			F1<<c0_1(i,j)<<",";
			F2<<c1_1(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}
	
	for(int i=0;i<c0_2.rows();i++){
		for(int j=0;j<c0_2.cols();j++){
			F1<<c0_2(i,j)<<",";
			F2<<c1_2(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}
		
	F1.close();
	F2.close();
	
	cout<<(double)(clock()-t1)/CLOCKS_PER_SEC<<"s"<<endl;
	
	t1=clock();
	
	Mat train_data(N,D), train_label(N,1);
	
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
	
	cout<<(double)(clock()-t1)/CLOCKS_PER_SEC<<"s"<<endl;
	t1=clock();
	
	cout<<"writing data shares......\n";
	
	Mat train_data0(N,D), train_data1(N,D), train_label0(N,1), train_label1(N,1);
	
	
	for(int i=0;i<train_data.rows();i++){
		for(int j=0;j<train_data.cols();j++){
			train_data0(i,j) = randomlong();
			train_data1(i,j) = train_data(i,j)- train_data0(i,j);
		}
	}
	
	for(int i=0;i<train_label.rows();i++){
		for(int j=0;j<train_label.cols();j++){
			train_label0(i,j) = randomlong();
			train_label1(i,j) = train_label(i,j)- train_label0(i,j);
		}
	}
	
	
	F1.open ("data0.txt");
	F2.open ("data1.txt");
	
	for(int i=0;i<train_data.rows();i++){
		for(int j=0;j<train_data.cols();j++){
			F1<<train_data0(i,j)<<",";
			F2<<train_data1(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}
	
	for(int i=0;i<train_label.rows();i++){
		for(int j=0;j<train_label.cols();j++){
			F1<<train_label0(i,j)<<",";
			F2<<train_label1(i,j)<<",";
		}
		F1<<endl;
		F2<<endl;
	}
	
	F1.close();
	F2.close();
	
	
	
	Mat xa= train_data0-a0+train_data1-a1;
	
	F1.open("xa.txt");
	
	for(int i=0;i<train_data.rows();i++){
		for(int j=0;j<train_data.cols();j++){
			F1<<xa(i,j)<<",";
		}
		F1<<endl;
	}
	
	F1.close();
	
	cout<<(double)(clock()-t1)/CLOCKS_PER_SEC<<"s"<<endl;
}
