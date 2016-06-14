#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>

/* Questions:
   Why use findM to get the value for m? Why not just set a value?
   R - number of rounds of what?
   w - hamming weight of the secret key: Why weight?
   r - What is lifting?
   d - What is field extension?
   c - What are key-switching matrices?
   L - What is a modulus chain?
   s - What about the maximum number of slots? Why can't the computation be done in one number only (i.e., without ciphertext)?
   p - why does it take much longer to find m if given larger p?
   addSome1DMatrices - what does this do?
   
 */

/* To do:
   - Extract method to generate context, keys and encrypted array
   - Write keys to file for transfer
   - Read keys from file to encrypt data
   - 

 */


int main(int argc, char **argv)
{
//	long R = 1;           // Number of rounds [default=1]
	long m = 0;           // Specific modulus
	long p = 257;         // Plaintext base [default=2], should be a prime number
	long r = 1;           // Lifting [default=1]
	long L = 16;          // Number of levels in the modulus chain [default=heuristic]
	long c = 3;           // Number of columns in key-switching matrix [default=2]
	long w = 64;          // Hamming weight of secret key
	long d = 0;           // Degree of the field extension [default=1]
	long k = 128;         // Security parameter [default=80] 
    long s = 0;           // Minimum number of slots [default=0]
    ZZX G;                // Polynomial

	cout << "Finding m... ";
	m = FindM(k,L,c,p, d, s, 0);             // Find a value for m given the specified values
	cout << "m = " << m << endl;

	cout << "Initializing context... ";
	FHEcontext context(m, p, r); 	         // Initialize context
	buildModChain(context, L, c);            // Modify the context, adding primes to the modulus chain
	cout << "OK!" << endl;

	cout << "Creating polynomial... ";
	G = context.alMod.getFactorsOverZZ()[0];
	cout << "OK!" << endl;

	cout << "Generating keys... ";
	FHESecKey secretKey(context);            // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;  // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);                  // Actually generate a secret key with Hamming weight w
	addSome1DMatrices(secretKey);
	cout << "OK!" << endl;

	EncryptedArray ea(context, G);
	long nslots = ea.size();
	Ctxt ctx1(publicKey);
	Ctxt ctx2(publicKey);
	vector<long> ptx1;
	for(uint i = 0; i < nslots; i++) {
		ptx1.push_back(2);
	}
	vector<long> ptx2;
	for(uint i = 0; i < nslots; i++) {
		ptx2.push_back(3);
	}	

	ea.encrypt(ctx1, publicKey, ptx1);
	ea.encrypt(ctx2, publicKey, ptx2);

	Ctxt ctSum = ctx1;
	ctSum += ctx2;
	
	vector<long> p_decrypted;
	ea.decrypt(ctx1, secretKey, p_decrypted);
	cout << "ctx1: " << p_decrypted << endl;

	ea.decrypt(ctx2, secretKey, p_decrypted);
	cout << "ctx2: " << p_decrypted << endl;
	
	ea.decrypt(ctSum, secretKey, p_decrypted);
	cout << "ctSum: " << p_decrypted << endl;

	return 0;
}
