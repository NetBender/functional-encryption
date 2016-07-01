#include "functional-enc.h"

// generate a pair of public/secret keys: they are stored in the structure 'keys'
void functional_generate_keys(functional_keys_t keys, unsigned int p_bits, unsigned int q_bits, gmp_randstate_t state) {
	pmesg(1, "generation of secret/public keys...\n");
	
	mpz_t z,t;
	long i=0; //index for the loops
	
	assert(keys);/* writes diagnostic informations on the standard error file */
	assert((p_bits > 0) && (q_bits > 0) && (q_bits < p_bits));

	// we need a group Zp* such that the order p-1 has at least a big prime factor q to prevent attack based on Pohlig-Hellman algorithm 
	// (see Algorithm 3.63 of "Handbook of Applied Cryptography")
	
	// we start selecting a random prime modulus q of q_bits
	mpz_init2(keys->q, q_bits);
	do
		mpz_urandomb(keys->q, state, q_bits);
	while ((mpz_sizeinbase(keys->q, 2) < q_bits) || !mpz_probab_prime_p(keys->q, FUNCTIONAL_MR_ITERATIONS));
 	// then we search r such that p=2rq+1 is a prime of p_bits: 
	// to do that we select z of p_bits, then compute p = z - ((z mod 2q) - 1) and test if p is prime (p is congruous 1 modulus 2q)
	// (see Section 4.4.4 of "Handbook of Applied Cryptography" on "Constructive techniques for provable primes")
	mpz_init2(keys->p, p_bits);
	mpz_init2(z, p_bits);
	mpz_init2(t, p_bits);
	do {
		mpz_urandomb(z, state, p_bits);
		mpz_mul_ui(t, keys->q, 2L);			// t = 2q
		mpz_mod(t, z, t);					// t = z mod t = z mod 2q
		mpz_sub_ui(z, z, 1L);				// t = t - 1 = (z mod 2q) - 1
		mpz_sub(keys->p, z, t);				// p = z - t = z - ((z mod 2q) - 1)
	} while ((mpz_sizeinbase(keys->p, 2) < p_bits) || !mpz_probab_prime_p(keys->p, FUNCTIONAL_MR_ITERATIONS));

	// search a generator g of the subgroup of order q: scan for a value z, such that g=z^((p-1)/q) mod p is different than 1
	// (see Note 4.81 of "Handbook of Applied Cryptography")
	mpz_init(keys->g);
	mpz_sub_ui(t, keys->p, 1L); // t = p - 1
	mpz_divexact(t, t, keys->q); // t = t / q = ( p-1 ) / q
	mpz_set_ui(z, 1L);
	do {
		mpz_add_ui(z, z, 1L);
		mpz_powm(keys->g, z, t, keys->p); // g=z^((p-1)/q) mod p
	} while (mpz_cmp_ui(keys->g, 1L) == 0);
	
	//msk allocation
	keys->msk = malloc(VECTORS_LENGTH*sizeof(mpz_t));
	/* memory debug */	
	if (NULL == keys->msk) {
		gmp_printf("ERROR: Out of memory\n");
	}
	
	// n random secret exponents s[i] in Zq*
	for(i=0;i<VECTORS_LENGTH;i++){
		mpz_init2(keys->msk[i],q_bits);
		do
			mpz_urandomm(keys->msk[i], state, keys->q);
		while (mpz_cmp_ui(keys->msk[i], 0L) == 0);
	}
	
	// mpk allocation
	keys->mpk = malloc(VECTORS_LENGTH*sizeof(mpz_t));
	/* memory debug */	
	if (NULL == keys->mpk) {
		gmp_printf("ERROR: Out of memory\n");
	}

	// computes mpk[i]=h_i=g^(s_i) mod p
	for(i=0;i<VECTORS_LENGTH;i++){
		mpz_init2(keys->mpk[i],p_bits);
		mpz_powm(keys->mpk[i], keys->g, keys->msk[i], keys->p); // g^(s_i) mod p
	}
	
	gmp_pmesg(1, "prime modulus 'p' (%d bits): %Zu\n", mpz_sizeinbase(keys->p, 2), keys->p);
	gmp_pmesg(1, "prime order subgroup 'q' (%d bits): %Zu\n", mpz_sizeinbase(keys->q, 2), keys->q);
	gmp_pmesg(1, "generator 'g' (%d bits): %Zu\n", mpz_sizeinbase(keys->g, 2), keys->g);
	
	for(i=0;i<VECTORS_LENGTH;i++){
		gmp_pmesg(1, "secret exponent 's_%d' (%d bits): %Zu\n", i, mpz_sizeinbase(keys->msk[i], 2), keys->msk[i]);
	}
	
	for(i=0;i<VECTORS_LENGTH;i++){
		gmp_pmesg(1, "base 'h_%d' (%d bits): %Zu\n", i, mpz_sizeinbase(keys->mpk[i], 2), keys->mpk[i]);
	}
	
	mpz_clear(z);
	mpz_clear(t);
	
	return;
}

// initialized the structure for a ciphertext (necessary before any use)
void functional_ciphertext_init(functional_ciphertext_t ciphertext) {
	assert(ciphertext);/* writes diagnostic informations on the standard error file */

	//Cti malloc
	ciphertext->cti = malloc(VECTORS_LENGTH*sizeof(mpz_t)); //allocates a space large: n * the size of a mpz_t(int) variable
	/* memory debug */	
	if (NULL == ciphertext->cti) {
		gmp_printf("ERROR: Out of memory\n");
	}
	
	//initialization
	mpz_init(ciphertext->ct0);
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_init(ciphertext->cti[i]);
	}
	
	return;
}

void functional_encrypt(functional_ciphertext_t ciphertext, functional_keys_t keys, functional_plaintext_t x, gmp_randstate_t state) {
	mpz_t r,gx; // gxi will contain g^(x_i)
	mpz_init(r);
	mpz_init(gx);

	pmesg(1, "encryption...\n");

	for(long i=0;i<VECTORS_LENGTH;i++){
		gmp_pmesg(1, "plaintext 'x_%d' (%d bits):  %Zu\n", i, mpz_sizeinbase(x[i], 2), x[i]);
	}

	// a random (secret) ephemeral exponent r in Z(p-1)*
	do
		mpz_urandomm(r, state, keys->q);
	while (mpz_cmp_ui(r, 0L) == 0);
	
	// computes ct0
	mpz_powm(ciphertext->ct0, keys->g, r, keys->p); // Ct_0=g^r mod p

	// computes ct_i		
	for(long i=0;i<VECTORS_LENGTH;i++){	
		mpz_powm(gx, keys->g, x[i], keys->p); // g^(x_i) mod p
		mpz_powm(ciphertext->cti[i], keys->mpk[i], r, keys->p); // h(_i)^r mod p
		mpz_mul(ciphertext->cti[i], ciphertext->cti[i], gx); // h(_i)^r*g^(x_i) 
		mpz_mod(ciphertext->cti[i], ciphertext->cti[i], keys->p); // sender's encrypted message
	}

	gmp_pmesg(1, "ephemeral exponent 'r' (%d bits): %Zu\n", mpz_sizeinbase(r, 2), r);
	gmp_pmesg(1, "ciphertext component 'ct0' (%d bits):  %Zu\n", mpz_sizeinbase(ciphertext->ct0, 2), ciphertext->ct0);
	for(long i=0;i<VECTORS_LENGTH;i++){
		gmp_pmesg(1, "ciphertext component 'cti_%d' (%d bits):  %Zu\n", i, mpz_sizeinbase(ciphertext->cti[i], 2), ciphertext->cti[i]);
	}
	
	mpz_clear(gx);
	mpz_clear(r);	// paranoid: all the bits of the secret ephemeral exponent should be overwritten for security
	return;
}

void functional_key_der(functional_keys_t keys, mpz_t* y){
	pmesg(1, "key derivation...\n");
	mpz_t aux; // auxiliary variable, will contain the "y_i*s_i" multiplication
	mpz_init(aux);
	mpz_set_ui(keys->sky, 0); // sky=0
	
	// calculates the inner-product <y,s>
	for(long i=0; i<VECTORS_LENGTH; i++){
		mpz_mul(aux, y[i], keys->msk[i]); // y_i*s_i 	
		mpz_add(keys->sky,keys->sky,aux); // sky=sky+aux	
	}
	mpz_mod(keys->sky, keys->sky, keys->p); // sky mod p
	mpz_clear(aux);
	
	return;
}

// decrypt the given ciphertext using the secret-key in 'keys'; the result is stored in 'plaintext (already initialized)
void functional_decrypt(functional_ciphertext_t ciphertext, functional_keys_t keys, mpz_t* y, mpz_t innerprod, int length) {
	pmesg(1, "decryption...\n");
	
	mpz_t ct0sk, ctiyi, order, base;	
	mpz_init_set_ui(innerprod, 1); // innerprod=1
	mpz_init(order); // the order of the group
	mpz_init(ct0sk); // will contain ct0^sky
	mpz_init(ctiyi); // will contain ct_i^y_i	
	mpz_init_set_ui(base, 2); // base for the following exponentiation
	mpz_pow_ui(order, base, length); // sets the restricted order to 2^length

	mpz_powm(ct0sk, ciphertext->ct0, keys->sky, keys->p); // computes ct0^sky mod p
	mpz_invert(ct0sk, ct0sk, keys->p); // computes 1/(ct0^sky)
	
	// computes the products of sequences
	for(long i=0; i<VECTORS_LENGTH; i++){
		mpz_powm(ctiyi, ciphertext->cti[i], y[i], keys->p); // ct_i^y_i mod p
		mpz_mul(innerprod,innerprod,ctiyi); // product of the previous
	}
	mpz_mul(innerprod, innerprod, ct0sk); // products/(ct0^sky)
	mpz_mod(innerprod, innerprod, keys->p); // g^<x,y>
	
	gmp_pmesg(1, "decrypted 'g^<x,y>' (%d bits):  %Zu\n", mpz_sizeinbase(innerprod, 2), innerprod); // intermediate step
	
	// inner product decryption	(by calculating the discrete logarithm)
	bg_step(keys->g, innerprod, order, keys->p, innerprod); // generator, g^msg, order, prime number, value to return (index)
	
	gmp_pmesg(1, "function '<x,y>' (%d bits):  %Zu\n", mpz_sizeinbase(innerprod, 2), innerprod); // final message
	
	mpz_clear(base);
	mpz_clear(order);
	mpz_clear(ct0sk);
	mpz_clear(ctiyi);
	
	return;
}
// baby-step giant-step algorithm
void bg_step(mpz_t g, mpz_t X, mpz_t m, mpz_t p, mpz_t x){
	// creation
	mpz_t n,N,exp,Y,x0,x1;
	mpz_t* Xgb; // will contain the precomputed Xgb
	
	// initialization
	mpz_init(n); 
	mpz_init(N);
	mpz_init(exp);
	mpz_init(Y);
	mpz_init_set_ui(x0,0);
	mpz_init(x1);
	
	// manipulation		
	mpz_sqrt(n,m);		 	
	mpz_add_ui(n,n,1);
	mpz_powm(N,g,n,p); // N= g^n (mod p)
	
	// malloc
	Xgb = malloc((mpz_get_ui(n)+1)*sizeof(mpz_t)); // allocates a space large: n+1 * the size of a mpz_t(int) variable
	/* memory debug */	
	if (NULL == Xgb) {
		gmp_printf("ERROR: Out of memory\n");
	}
	mpz_init(Xgb[0]); // this space won't be initialized in the following "for". This because we keep this space as a blank
	
	//algorithm
	// for b=1 to n --> B[Xg^(-b)]<-b
	for(long b=1;b <=mpz_get_ui(n);b++) {
		mpz_set_ui(exp,(b-1)); // auxiliary variable for the exponentiation (needed for GMP casting)
		mpz_init(Xgb[b]);
		mpz_powm(Xgb[b], g, exp, p); // g^b mod p
		mpz_invert(Xgb[b], Xgb[b], p); // g^(-b) mod p
		mpz_mul(Xgb[b], Xgb[b], X); // X*g^(-b)
		mpz_mod(Xgb[b], Xgb[b], p); // X*g^(-b) mod p
	}
	
	for(long a=0;a <=mpz_get_ui(n);a++) {
		mpz_set_ui(exp,a); //auxiliary variable for the exponentiation (needed for GMP casting)
		mpz_powm(Y, N, exp, p); //Y=(N^a) mod p
		
		lsearch(Y,Xgb,mpz_get_ui(n),x0); // parameters: key,base,size,space,returned index --> //x0=B[Y]
		if(mpz_cmp_ui(x0,0)!=0){ // if x0 is not 0, then there's a value b that makes Y=Xg^(-b)
			mpz_set(x1, exp); // x1=a
			mpz_sub_ui(x0, x0, 1); // x0=x0-1
			mpz_mul(x1, x1, n); // x1=n*x1
			mpz_mod(x1, x1, p); // x1=n*x1 mod p
			mpz_add(x, x1, x0); // msg=(n*x1)+x0 (returned value)
			break;
		}
	}
	//clear
	for(long i=0;i<(mpz_get_ui(n));i++){
		mpz_clear(Xgb[i]);
	}	
	free(Xgb);
	mpz_clear(n); 
	mpz_clear(N);
	mpz_clear(exp);
	mpz_clear(Y);
	mpz_clear(x0);
	mpz_clear(x1);
	
	return;
}
//linear search for the baby-step giant-step algorithm
void lsearch(mpz_t key, mpz_t* base, unsigned long int size, mpz_t index){
	for(long i=1;i<=size;i++){
		if(mpz_cmp(key,base[i])==0){ // if the value has been found
			mpz_set_ui(index,i); // x0=B[Y]
			break; // returns immediately
		}
	}
	
	return;
}
// cleanup of the structures to avoid old values
void functional_ciphertext_mid_clear(functional_ciphertext_t ciphertext) {
	
	// cleaning
	mpz_set_ui(ciphertext->ct0, 0);
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_set_ui(ciphertext->cti[i], 0);
	}
	
	return;
}

// cleanup and free sub-structures in 'keys'
void functional_keys_clear(functional_keys_t keys) {

	mpz_clear(keys->p);
	mpz_clear(keys->g);
	
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_clear(keys->mpk[i]);
	}
	free(keys->mpk);
	
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_clear(keys->msk[i]);
	}	
	free(keys->msk);		// paranoid: all the bits should be overwritten
	mpz_clear(keys->q);		//
	mpz_clear(keys->sky);	//

	return;
}

// cleanup and free sub-structures in 'ciphertext'
void functional_ciphertext_clear(functional_ciphertext_t ciphertext) {

	mpz_clear(ciphertext->ct0);
	
	for(long i=0;i<VECTORS_LENGTH;i++){
		mpz_clear(ciphertext->cti[i]);
	}	
	free(ciphertext->cti);
	
	return;
}
