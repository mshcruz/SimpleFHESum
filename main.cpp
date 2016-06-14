#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>


int main(int argc, char **argv)
{
//	long R = 1;                              // Number of rounds [default=1]
	long m = 0;                              // Specific modulus
	long p = 257;                            // Plaintext base [default=2], should be a prime number
	long r = 1;                              // Lifting [default=1]
	long L = 16;                             // Number of levels in the modulus chain [default=heuristic]
	long c = 3;                              // Number of columns in key-switching matrix [default=2]
	long w = 64;                             // Hamming weight of secret key
	long d = 0;                              // Degree of the field extension [default=1]
	long k = 128;                            // Security parameter [default=80] 
    long s = 0;                              // Minimum number of slots [default=0]
    ZZX G;                                   // Polynomial

	cout << "Finding m... " << std::flush;
	m = FindM(k,L,c,p, d, s, 0);             // Find a value for m given the specified values
	cout << "m = " << m << endl;
	
	cout << "Initializing context... " << std::flush;
	FHEcontext context(m, p, r); 	         // Initialize context
	buildModChain(context, L, c);            // Modify the context, adding primes to the modulus chain
	cout << "OK!" << endl;

	cout << "Creating polynomial... " << std::flush;
	G = context.alMod.getFactorsOverZZ()[0];          // Creates the polynomial used to encrypt the data
	cout << "OK!" << endl;

	cout << "Generating keys... " << std::flush;
	FHESecKey secretKey(context);                 // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;       // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);                       // Actually generate a secret key with Hamming weight w
	cout << "OK!" << endl;

	EncryptedArray ea(context, G);       // Encrypted arrays are helpers that support encryption/decryption over the ring (Z/(p^r)[X])/(G)
	long nslots = ea.size();             // Number of slots in the encrypted array
	Ctxt ctx1(publicKey);                // Initialize the first ciphertext (ctx1) using publicKey
	Ctxt ctx2(publicKey);                // Initialize the first ciphertext (ctx2) using publicKey

	vector<long> ptx1;                   // Container to hold the first plaintext
	vector<long> ptx2;                   // Container to hold the second plaintext

	for(uint i = 0; i < nslots; i++) {
		ptx1.push_back(2);               // Insert the first plaintext (the value 2) multiple times
	}
	for(uint i = 0; i < nslots; i++) {
		ptx2.push_back(3);               // Insert the first plaintext (the value 3) multiple times
	}	

	ea.encrypt(ctx1, publicKey, ptx1);      // Encrypt the plaintext ptx1 into the ciphertext ctx1 using key publicKey
	ea.encrypt(ctx2, publicKey, ptx2);      // Encrypt the plaintext ptx2 into the ciphertext ctx2 using key publicKey

	Ctxt ctSum = ctx1;      // Initialize the sum with the first ciphertext (ctx1)
	ctSum += ctx2;          // Increment the sum by the second ciphertext (ctx2)
	
	vector<long> p_decrypted;                    // Initialize the vector that hold the decrypted ciphertexts (i.e., hold plaintext)
	ea.decrypt(ctx1, secretKey, p_decrypted);    // Decrypt the first ciphertext (ctx1) into p_decrypt using secretKey
	cout << "ctx1: " << p_decrypted << endl;

	ea.decrypt(ctx2, secretKey, p_decrypted);    // Decrypt the second ciphertext (ctx2) into p_decrypt using secretKey
	cout << "ctx2: " << p_decrypted << endl;
	
	ea.decrypt(ctSum, secretKey, p_decrypted);   // Decrypt the sum of  ciphertexts (ctx1 + ctx2) into p_decrypt using secretKey
	cout << "ctSum: " << p_decrypted << endl;

	return 0;
}
