#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <math.h>
#include <vector>
#include <algorithm>

#include <time.h>


#include <Eigen/Dense>

#define N 100000
//#define N 1280
#define D 1000
#define B 128
#define testN 10000
#define Ep 2
#define IT N*Ep/B
#define L 20
#define P 64

using namespace std;
using namespace Eigen;

typedef unsigned long int uint64;
typedef Array<unsigned long int,Dynamic,Dynamic> Mat;

int myrandom (int i) { return rand()%i;}

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

uint64 randomlong(){
	uint64 rand1 = abs(rand());
    uint64 rand2 = abs(rand());
    rand1 = rand1 << (sizeof(int)*8);   
    uint64 randULL = (rand1 | rand2);   
    return randULL;

}



int main(int argc, char** argv){
	
	srand ( unsigned ( time(NULL) ) );
	clock_t t1,t2;
	
	//Mat::Random(N,D*Ep) a0,a1,b0_1,b1_1,c0_1,b0_2,b1_2,c0_2;
	Mat a0(N,D),a1(N,D),b0_1(N,D),b1_1(N,D),c0_1(N,D),c1_1(N,D),b0_2(N,D),b1_2(N,D),c0_2(N,D),c1_2(N,D);
	
	vector<int> perm = random_perm();
	
	//Mat c1_1,c1_2;
	
	//cout<<"generating multiplication triples......\n";
	t1=clock();

	
	for(int i=0;i<a0.rows();i++){
		for(int j=0;j<a0.cols();j++){
			a0(i,j) = randomlong();
			a1(i,j) = randomlong();
		}
	}
	
	
	
	
	Mat tempc(N,D);
	
	
	
	for(int round=0;round<Ep;round++){
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
		
		for(int i=0;i<c0_1.rows();i++){
			for(int j=0;j<c0_2.cols();j++){
				c0_1(i,j) = randomlong();
				c0_2(i,j) = randomlong();
			}
		}
		
		tempc=(a0+a1)*(b0_1+b1_1);
	
		c1_1= tempc-c0_1;
		
		tempc=(a0+a1)*(b0_2+b1_2);
		
		c1_2= tempc-c0_2;
		

		
	}
	
	
	
	
	cout<<(double)(clock()-t1)/CLOCKS_PER_SEC<<endl;
	
	
}