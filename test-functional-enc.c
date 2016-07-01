#include <stdio.h>
#include <gmp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "functional-enc.h"
#include "misc.h"
#include <stdlib.h>
#include <time.h>

int main() {
	gmp_randstate_t prng; //initial random state
	functional_plaintext_t plaintext;
	functional_ciphertext_t ciphertext;
	functional_keys_t keys;
	mpz_t* y; // vector taken by the key-derivator
	mpz_t innerprod, innerprod2, aux; // will contain the inner products (computed and decrypted) and the auxiliary value
	double base_time=0, time_enc=0, time_keyder=0, time_dec=0;
	unsigned long prng_seed;
	int dev_random_fd, length=0, flag=0;
	time_t now = time(0); // will be used for the timestamp feature

	printf("\nTest Functional Encryption cryptosystem...\n");
	
	/*------------timestamp------------*/	
	time(&now); 
	printf("start time: %s", ctime(&now));
	/*---------------------------------*/
	
	if (VERBOSE==0) 
		msglevel=0;	// no message during cryptographic operations
	else
		msglevel=2;	// verbose messages during cryptographic operations

	// initializing PRNG using a seed from the system entropy collector
	dev_random_fd=open("/dev/random", O_RDONLY); 
	gmp_randinit_default(prng);
	read (dev_random_fd, &prng_seed , sizeof(prng_seed));
	close(dev_random_fd);
	gmp_randseed_ui(prng, prng_seed);
	// paranoid: prng_seed is 64 bit long: it should be at least 80 bit
	
	// y generation
	// malloc
	y = malloc(VECTORS_LENGTH*sizeof(mpz_t)); // allocates a space large: n * the size of a mpz_t(int) variable
	/* memory debug */	
	if (NULL == y) {
		gmp_printf("ERROR: Out of memory\n");
	}
	
	// automatic generation of the values in y
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_init(y[i]);
		mpz_urandomb(y[i], prng, Y_MSG_LENGTH); // generates number between 0 and 2^length-1
	}	
	
	// x generation
	// malloc
	plaintext = malloc(VECTORS_LENGTH*sizeof(mpz_t)); // allocates a space large: n * the size of a mpz_t(int) variable
	/* memory debug */	
	if (NULL == plaintext) {
		gmp_printf("ERROR: Out of memory\n");
	}
	// initialization
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_init(plaintext[i]);
	}
	
	// public/secret keys generation
	base_time=cputime();
	functional_generate_keys(keys, KEY_SIZE1, KEY_SIZE2, prng);
	base_time=cputime()-base_time;
	printf("key-generation - time elapsed: %0.6lfms\n", base_time);
	
	// initializations
	functional_ciphertext_init(ciphertext);
	mpz_init(innerprod2);
	mpz_init(aux);
	mpz_init(keys->sky);	
		
	// start of the test
	for(long i=0; i<VECTORS&&flag==0; i++){
		/*-----------timestamp-----------*/	
		time(&now); 
		printf("iteration %ld/%d started %s",i+1, VECTORS, ctime(&now));
		/*-------------------------------*/	
		
		// automatic generation of the message (plaintext)
		for(long i=0;i<VECTORS_LENGTH;i++){
			mpz_urandomb(plaintext[i], prng, X_MSG_LENGTH); // generates number between 0 and 2^length-1
		}
		
		// encryption
		functional_ciphertext_mid_clear(ciphertext); // sets all the cyphertext's values to zero
		base_time=cputime();
		functional_encrypt(ciphertext, keys, plaintext, prng);
		time_enc=time_enc+(cputime()-base_time);
		
		// key derivation
		base_time=cputime();
		functional_key_der(keys, y);
		time_keyder=time_keyder+(cputime()-base_time);
		
		// decryption		
		/* computes the inner product <plaintext, y> */
		mpz_set_ui(innerprod2, 0);
		for(long i=0; i<VECTORS_LENGTH; i++){
			mpz_mul(aux, plaintext[i], y[i]); // x_i*y_i 	
			mpz_add(innerprod2, innerprod2, aux); // innerprod2=innerprod2+aux	
		}
		mpz_mod(innerprod2, innerprod2, keys->p); // innerprod2 mod p
		/*-------------------------------------------*/
		
		length=mpz_sizeinbase(innerprod2, 2);
		base_time=cputime();
		functional_decrypt(ciphertext, keys, y, innerprod, length);
		time_dec=time_dec+(cputime()-base_time);
		
		// verification	
		if (mpz_cmp(innerprod, innerprod2) != 0){ // "innerprod" has been computed in the bg_step algorithm
			flag=1;
			printf("verification failed at index %li\n",i);
		}
		
	}
	
	if(flag==0){
		// compute the means of the times
		time_enc=time_enc/VECTORS;
		time_keyder=time_keyder/VECTORS;
		time_dec=time_dec/VECTORS;
		// show the results
		printf("encryption - time elapsed: %0.6lfms\n", time_enc);
		printf("key derivation - time elapsed: %0.6lfms\n", time_keyder);
		printf("decryption - time elapsed: %0.6lfms\n", time_dec);
		printf("verifications: ok\n");
	}
	
	/*-----------timestamp-----------*/	
	time(&now); 
	printf("end time: %s", ctime(&now));
	/*-------------------------------*/	
	
	/* memory cleaning */
	functional_keys_clear(keys);
	functional_ciphertext_clear(ciphertext);
	
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_clear(plaintext[i]);
	}	
	free(plaintext);
	mpz_clear(innerprod);
	mpz_clear(innerprod2);
	mpz_clear(aux);
	
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_clear(y[i]);
	}
	free(y);
	gmp_randclear(prng);
}
