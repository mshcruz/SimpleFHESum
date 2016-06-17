#include "FHE.h"

int main(int argc, char **argv)
{
	/*** BEGIN INITIALIZATION ***/
	long m = 0;                   // Specific modulus
	long p = 1021;                // Plaintext base [default=2], should be a prime number
	long r = 1;                   // Lifting [default=1]
	long L = 16;                  // Number of levels in the modulus chain [default=heuristic]
	long c = 3;                   // Number of columns in key-switching matrix [default=2]
	long w = 64;                  // Hamming weight of secret key
	long d = 0;                   // Degree of the field extension [default=1]
	long k = 128;                 // Security parameter [default=80] 
    long s = 0;                   // Minimum number of slots [default=0]

	std::cout << "Finding m... " << std::flush;
	m = FindM(k, L, c, p, d, s, 0);                            // Find a value for m given the specified values
	std::cout << "m = " << m << std::endl;
	
	std::cout << "Initializing context... " << std::flush;
	FHEcontext context(m, p, r); 	                        // Initialize context
	buildModChain(context, L, c);                           // Modify the context, adding primes to the modulus chain
	std::cout << "OK!" << std::endl;

	std::cout << "Creating polynomial... " << std::flush;
	ZZX G =  context.alMod.getFactorsOverZZ()[0];                // Creates the polynomial used to encrypt the data
	std::cout << "OK!" << std::endl;

	std::cout << "Generating keys... " << std::flush;
	FHESecKey secretKey(context);                           // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;                 // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);                                 // Actually generate a secret key with Hamming weight w
	std::cout << "OK!" << std::endl;
	/*** END INITIALIZATION ***/
	
	Ctxt ctx1(publicKey);                // Initialize the first ciphertext (ctx1) using publicKey
	Ctxt ctx2(publicKey);                // Initialize the first ciphertext (ctx2) using publicKey

	publicKey.Encrypt(ctx1, to_ZZX(2));  // Encrypt the value 2
	publicKey.Encrypt(ctx2, to_ZZX(3));  // Encrypt the value 3
	
	Ctxt ctSum = ctx1;                   // Create a ciphertext to hold the sum and initialize it with Enc(2)
	ctSum += ctx2;                       // Perform Enc(2) + Enc(3)

	ZZX ptSum;                           //	Create a plaintext to hold the plaintext of the sum
	secretKey.Decrypt(ptSum, ctSum);	 // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey

	std::cout << "2 + 3 = " << ptSum[0] << std::endl;
	
	return 0;
}
