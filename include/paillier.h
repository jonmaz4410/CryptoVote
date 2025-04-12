#ifndef PAILLIER_H
#define PAILLIER_H

#include <gmpxx.h>
#include <vector>
#include <string>
#include <gmp.h>
#include <cstdint> 

using namespace std;
using Byte = unsigned char;

/*
###########################################################################
    STRUCT DEFINITIONS
###########################################################################
*/

/**
 * @brief Holds the public and private key components for Paillier.
 *
 * @param n The modulus (p * q).
 * @param nSquared n * n.
 * @param g The generator (often n + 1).
 * @param lambda Carmichael function lambda(n) = lcm(p-1, q-1).
 * @param mu Private key component mu = (L(g^lambda mod n^2))^-1 mod n.
 */
struct PaillierKeys {
    mpz_class n;        // Modulus (p * q)
    mpz_class nSquared; // n * n
    mpz_class g;        // Generator (often n + 1)
    mpz_class lambda;   // Carmichael function lambda(n) = lcm(p-1, q-1)
    mpz_class mu;       // Private key component mu = (L(g^lambda mod n^2))^-1 mod n
};

/**
 * @brief Represents an encrypted ballot containing PII and vote weight.
 *
 * @param aesEncryptedPII IV + AES Ciphertext of "FirstName LastName".
 * @param encWeight Paillier Ciphertext of encoded vote weight (M^i).
 */
struct EncryptedBallot {
    vector<Byte> aesEncryptedPII;      // IV + DES Ciphertext of "FirstName LastName"
    mpz_class encWeight;                        // Paillier Ciphertext of encoded vote weight (M^i)
};

/*
###########################################################################
    FUNCTION PROTOTYPES
###########################################################################
*/

/**
 * @brief Computes the Paillier L function.
 * @details Calculates L(x) = (x - 1) / n using integer division.
 * @param x The input value (typically c^lambda mod n^2).
 * @param n The Paillier modulus n.
 * @return The result of the L function as an mpz_class.
 */
mpz_class L_function(const mpz_class& x, const mpz_class& n);

/**
 * @brief Computes the modular multiplicative inverse.
 * @details Calculates the inverse of 'a' modulo 'n' using the GMP library.
 * @param a The number to find the inverse of.
 * @param n The modulus.
 * @return The modular inverse of a modulo n as an mpz_class.
 */
mpz_class mod_inverse(const mpz_class& a, const mpz_class& n);

/**
 * @brief Generates a random number 'r' for Paillier encryption.
 * @details Generates 'r' such that 1 <= r < n and gcd(r, n) == 1.
 * @param n The Paillier modulus n. Must be greater than 1.
 * @param rand_state An initialized GMP random state object.
 * @return A suitable random number 'r' as an mpz_class.
 */
mpz_class gen_rand_r(const mpz_class& n, gmp_randstate_t& rand_state);

/**
 * @brief Generates a probable prime number of a specified bit size.
 * @details Uses GMP functions to find a probable prime number.
 * @param bits The desired bit length of the prime (must be > 1).
 * @param rand_state An initialized GMP random state object.
 * @return A probable prime number as an mpz_class.
 */
mpz_class generate_prime(int bits, gmp_randstate_t& rand_state);

/**
 * @brief Creates the plaintext weights for base-M encoding.
 * @details Calculates weights M^i where M = max_voters + 1.
 * @param numCandidates The number of candidates.
 * @param max_voters The maximum expected number of voters (k).
 * @return A vector containing the weights [M^0, M^1, ... M^(numCandidates-1)].
 */
vector<mpz_class> calcWeights(int numCandidates, int max_voters);

/**
 * @brief Retrieves the pre-computed weight for a candidate index.
 * @details Looks up the weight M^i from the precomputed vector.
 * @param candidateIndex The index of the chosen candidate (0 to numCandidates-1).
 * @param precomputedWeights A vector containing the pre-calculated M^i weights.
 * @return The corresponding plaintext weight (M^candidateIndex) as an mpz_class.
 */
mpz_class getVoteWeight(int candidateIndex, const vector<mpz_class>& precomputedWeights);

/**
 * @brief Generates Paillier public and private keys.
 * @details Generates two large primes p and q, then computes n, lambda, g, and mu.
 * @param bitSize The desired bit length for the modulus 'n'.
 * @return A PaillierKeys struct containing the generated keys.
 */
PaillierKeys genKeyPaillier(int bitSize);

/**
 * @brief Encrypts a plaintext vote weight using the Paillier public key.
 * @details Applies the Paillier encryption formula: c = g^vote * r^n mod n^2.
 * @param vote The plaintext vote weight (M^i) to encrypt (0 <= vote < n).
 * @param keys A PaillierKeys struct containing the public key components.
 * @param rand_state An initialized GMP random state object for generating 'r'.
 * @return The resulting Paillier ciphertext as an mpz_class.
 */
mpz_class encVote(const mpz_class& vote, const PaillierKeys& keys, gmp_randstate_t& rand_state);

/**
 * @brief Decrypts a Paillier ciphertext using the private key.
 * @details Applies the Paillier decryption formula: m = L(c^lambda mod n^2) * mu mod n.
 * @param ciphertext The Paillier ciphertext to decrypt (0 <= ciphertext < n^2).
 * @param keys A PaillierKeys struct containing the private key components.
 * @return The resulting plaintext message (original vote weight) as an mpz_class.
 */
mpz_class decVote(const mpz_class& ciphertext, const PaillierKeys& keys);

/**
 * @brief Homomorphically adds two encrypted Paillier votes.
 * @details Exploits the property E(m1) * E(m2) = E(m1 + m2) by multiplying ciphertexts.
 * @param c1 The first Paillier ciphertext.
 * @param c2 The second Paillier ciphertext.
 * @param keys A PaillierKeys struct.
 * @return A new ciphertext representing the encryption of (plaintext1 + plaintext2) mod n.
 */
mpz_class addVotes(const mpz_class& c1, const mpz_class& c2, const PaillierKeys& keys);

/**
 * @brief Prompts user for a ballot index and decrypts/displays the PII and vote weight.
 * @details Handles user input for the index and calls decryption functions.
 * @param allBallots The vector containing all encrypted ballots.
 * @param paillierKeys The PaillierKeys struct needed for vote decryption.
 * @param des_key The 64-bit DES key needed for PII decryption.
 * @return Void.
 */
void decryptBallot(const vector<EncryptedBallot>& allBallots,
    const PaillierKeys& paillierKeys,
    const array<Byte, 32>& aes_key);


/**
 * @brief Generates a random 32-byte AES key.
 * @param rand_state An initialized GMP random state object.
 * @return A 32-byte array representing the AES key.
 */
array<Byte, 32> genKeyAES(gmp_randstate_t& rand_state);

/**
 * @brief Prints the decrypted tally and verifies the results against the actual vote counts.
 * @param decryptedTally The final decrypted tally.
 * @param numCandidates The number of candidates.
 * @param max_voters The maximum number of voters.
 * @param actualVoteCounts The vector of actual vote counts for each candidate.
 * @param num_votes The total number of votes simulated.
 * @return True if the results were printed and verified successfully, false otherwise.
 */
bool printResults(
    const mpz_class& decryptedTally,
    int numCandidates,
    int max_voters,
    const std::vector<int>& actualVoteCounts,
    int num_votes);


#endif // PAILLIER_H
