#include <stdio.h>
#include <assert.h>
#include <gmp.h>
#include "misc.h"

/* EDIT these definitions to see how the scheme behaves */
#define VERBOSE 0 // verbosity flag
#define VECTORS 100 // number of the message vectors that will be generated
#define VECTORS_LENGTH 30 // length of the vectors (x and y)			 	--> n
#define X_MSG_LENGTH 10	 // size of each message in vector X (in bits)	--> m
#define Y_MSG_LENGTH 20	// size of each message in vector Y(in bits)	--> k

/* DO NOT EDIT the following unless you know what you're doing */
#define KEY_SIZE1 2048 // p size
#define KEY_SIZE2 224 // q size
#define FUNCTIONAL_MR_ITERATIONS 12 // for the Miller-Rabin primality test

struct functional_keys_s {
	mpz_t p;	// secure prime number		//
	mpz_t g;	// generator				// base value for encryption
	
	mpz_t* msk;	// random exponents s		// master secret key
	mpz_t q;	// p-1's divider (prime)	//
	
	mpz_t* mpk;	// h_i=g^(s_i)				// master public key
	
	mpz_t sky;	// sk_y						// derivated secret key for the y vector
};
typedef struct functional_keys_s functional_keys_t[1];

struct functional_ciphertext_s {
	mpz_t ct0;
	mpz_t* cti;
};
typedef struct functional_ciphertext_s functional_ciphertext_t[1];

typedef mpz_t* functional_plaintext_t;

void functional_generate_keys(functional_keys_t keys, unsigned int p_bits, unsigned int q_bits, gmp_randstate_t state);
void functional_ciphertext_init(functional_ciphertext_t ciphertext);
void functional_encrypt(functional_ciphertext_t ciphertext, functional_keys_t keys, functional_plaintext_t x, gmp_randstate_t state);
void functional_key_der(functional_keys_t keys, mpz_t* y);
void functional_decrypt(functional_ciphertext_t ciphertext, functional_keys_t keys, mpz_t* y, mpz_t innerprod, int length);
void functional_keys_clear(functional_keys_t keys);
void functional_ciphertext_mid_clear(functional_ciphertext_t ciphertext);
void functional_ciphertext_clear(functional_ciphertext_t ciphertext);
void bg_step(mpz_t g, mpz_t X, mpz_t m, mpz_t p, mpz_t x);
void lsearch(mpz_t key,mpz_t* base,unsigned long int size,mpz_t index); 
