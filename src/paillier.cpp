/*
Names:      Jonathan Mazurkiewicz and Julia Antunes
Class:      Practical Aspects of Modern Cryptography
Project:    Final Project - Secure Voting System with Paillier Encryption
Professor:  Mehrdad Nojoumian
Due Date:   4/17/2025
*/

/*
###########################################################################
    LIBRARIES
###########################################################################
*/

#include "paillier.h"
#include "aes.h"        // For AES encryption/decryption
//-------------------------------------------------------------
#include <iostream>
#include <gmpxx.h>     
#include <stdexcept>  
#include <ctime>
#include <string>
#include <vector> 
#include <cstdlib>      
#include <iomanip>      
#include <cctype>     
#include <sstream>

using namespace std;
using Byte = unsigned char;

/*
###########################################################################
    FUNCTION DEFINITIONS
###########################################################################
*/

// Computes the Paillier L function: L(x) = (x - 1) / n.
mpz_class L_function(const mpz_class& x, const mpz_class& n) {
    // Basic check to prevent division by zero
    if (n == 0) {
         throw invalid_argument("L_function: n cannot be zero.");
    }
    // Perform integer division
    return (x - 1) / n;
}

// Computes the modular multiplicative inverse of a modulo n.
mpz_class mod_inverse(const mpz_class& a, const mpz_class& n) {

    mpz_class result;
    int success = mpz_invert(result.get_mpz_t(), a.get_mpz_t(), n.get_mpz_t());
    // Check if the inverse exists (gcd(a,n) must be 1)
    if (success == 0) {
        throw runtime_error("Modular inverse does not exist. Check key generation inputs/logic.");
    }
    return result;
}

// Generates a random number 'r' such that 1 <= r < n and gcd(r, n) == 1.
mpz_class gen_rand_r(const mpz_class& n, gmp_randstate_t& rand_state) {
    // Ensure n is valid for the operation
    if (n <= 1) {
        throw invalid_argument("gen_rand_r: n must be greater than 1");
    }
    mpz_class random_r;
    mpz_class gcd_result;

    do {
        // Generate random number in [0, n-1]
        mpz_urandomm(random_r.get_mpz_t(), rand_state, n.get_mpz_t());
        if (random_r == 0) {
            continue;
        }
        // Check if gcd(r, n) is 1
        mpz_gcd(gcd_result.get_mpz_t(), random_r.get_mpz_t(), n.get_mpz_t());
    } while (gcd_result != 1);
    return random_r;
}

// Generates a probable prime number of a specified bit size.
mpz_class generate_prime(int bits, gmp_randstate_t& rand_state) {

    mpz_class prime_candidate;
    mpz_class probable_prime;

    // Generate random bits
    mpz_urandomb(prime_candidate.get_mpz_t(), rand_state, bits);
    // Set top and bottom bits to increase likelihood of primality and ensure size
    mpz_setbit(prime_candidate.get_mpz_t(), bits - 1);
    // Ensures odd number
    mpz_setbit(prime_candidate.get_mpz_t(), 0);
    // Find the next probable prime after the candidate
    mpz_nextprime(probable_prime.get_mpz_t(), prime_candidate.get_mpz_t());
    return probable_prime;
}

// Generates Paillier public and private keys.
PaillierKeys genKeyPaillier(int bitSize) {

    PaillierKeys keys;
    mpz_class p, q;
    int primeBits = bitSize / 2;

    // Use a local random state for key generation for isolation
    gmp_randstate_t key_rand_state;
    gmp_randinit_mt(key_rand_state);

    // Generate first prime p
    p = generate_prime(primeBits, key_rand_state);
    q = generate_prime(primeBits, key_rand_state);

    // Calculate n = p * q
    keys.n = p * q;

    // Calculate nSquared = n * n
    keys.nSquared = keys.n * keys.n;

    // Calculate lambda(n) = lcm(p-1, q-1)
    mpz_class p_minus_1 = p - 1;
    mpz_class q_minus_1 = q - 1;
    mpz_lcm(keys.lambda.get_mpz_t(), p_minus_1.get_mpz_t(), q_minus_1.get_mpz_t());

    // Set generator g = n + 1
    keys.g = keys.n + 1;

    // Calculate mu = (L(g^lambda mod n^2))^-1 mod n
    mpz_class temp1;

    // Calculate g^lambda mod n^2
    mpz_powm(temp1.get_mpz_t(), keys.g.get_mpz_t(), keys.lambda.get_mpz_t(), keys.nSquared.get_mpz_t());

    // Apply L function
    mpz_class temp2 = L_function(temp1, keys.n);

    // Calculate modular inverse to get mu
    keys.mu = mod_inverse(temp2, keys.n);

    // Clean up local random state
    gmp_randclear(key_rand_state);
    return keys;
}

// Encrypts a plaintext vote weight using the Paillier public key.
mpz_class encVote(const mpz_class& vote, const PaillierKeys& keys, gmp_randstate_t& rand_state) {

    // Generate random r co-prime to n
    mpz_class r = gen_rand_r(keys.n, rand_state);
    mpz_class term1; // To store g^vote mod n^2
    mpz_class term2; // To store r^n mod n^2

    // Calculate g^vote mod n^2
    mpz_powm(term1.get_mpz_t(), keys.g.get_mpz_t(), vote.get_mpz_t(), keys.nSquared.get_mpz_t());
    // Calculate r^n mod n^2
    mpz_powm(term2.get_mpz_t(), r.get_mpz_t(), keys.n.get_mpz_t(), keys.nSquared.get_mpz_t());

    // Combine terms: ciphertext = (g^vote * r^n) mod n^2
    mpz_class ciphertext = (term1 * term2) % keys.nSquared;
    return ciphertext;
}

// Decrypts a Paillier ciphertext using the private key.
mpz_class decVote(const mpz_class& ciphertext, const PaillierKeys& keys) {

    mpz_class term1;
    
    // Calculate c^lambda mod n^2
    mpz_powm(term1.get_mpz_t(), ciphertext.get_mpz_t(), keys.lambda.get_mpz_t(), keys.nSquared.get_mpz_t());

    // Apply L function: L(c^lambda mod n^2)
    mpz_class term2 = L_function(term1, keys.n);

    // Calculate plaintext
    mpz_class plaintext = (term2 * keys.mu) % keys.n;
    return plaintext;
}

// Homomorphically adds two encrypted votes.
mpz_class addVotes(const mpz_class& c1, const mpz_class& c2, const PaillierKeys& keys) {

    // Perform homomorphic addition via ciphertext multiplication modulo n^2
    mpz_class result_ciphertext = (c1 * c2) % keys.nSquared;
    return result_ciphertext;
}

// Calculates and displays the Base-M weights for Paillier encoding.
vector<mpz_class> calcWeights(int numCandidates, int max_voters) {

    mpz_class M = mpz_class(max_voters) + 1;

    // Print parameters used for calculation
    cout << "\nCalculating weights based on:" << endl;
    cout << " - Number of Candidates: " << numCandidates << endl;
    cout << " - Max Expected Voters (k): " << max_voters << endl;
    cout << " - Encoding Base (M = k + 1): " << M << endl;
    cout << "-----------------------------------" << endl;

    // Initialize vector to store weights
    vector<mpz_class> weights(numCandidates);
    mpz_class currentWeight = 1;

    for (int i = 0; i < numCandidates; ++i) {
        weights[i] = currentWeight;
        // Display the calculated weight for the candidate index
        cout << " Candidate " << i << ": Weight = " << weights[i] << endl;

        if (i < numCandidates - 1) {
             currentWeight *= M;
        }
    }
    cout << "-----------------------------------" << endl;

    return weights;
}


// Retrieves the pre-calculated plaintext weight for a candidate index.
mpz_class getVoteWeight(int candidateIndex, const vector<mpz_class>& precomputedWeights) {

    return precomputedWeights[candidateIndex];
}

// Prompts user for a ballot index and decrypts/displays the PII and vote weight.
void decryptBallot(const vector<EncryptedBallot>& allBallots,
    const PaillierKeys& paillierKeys,
    const array<Byte, 32>& aes_key) {

    long ballot_index = -1; // Variable to store user's chosen index
    long max_index = static_cast<long>(allBallots.size()) - 1;

    // Prompt user for the index
    cout << "Enter the ballot index to decrypt (0 to " << max_index << "): ";
    cin >> ballot_index;
    cout << "\n--- Decrypting Ballot #" << ballot_index << " ---" << endl;
    const EncryptedBallot& selectedBallot = allBallots[ballot_index];

    // Attempt to decrypt PII
    try {
        string decrypted_pii = decryptAES256(selectedBallot.aesEncryptedPII, aes_key);;

        cout << " Decrypted PII: \"" << decrypted_pii << "\"" << endl;
    } catch (const exception& e) {
        cerr << " Error decrypting PII: " << e.what() << endl;
    }

    // Attempt to decrypt Vote Weight
    try {
        mpz_class decrypted_weight = decVote(selectedBallot.encWeight, paillierKeys);
        cout << " Decrypted Plaintext Vote Weight (M^i): " << decrypted_weight << endl;
    } catch (const exception& e) {
         cerr << " Error decrypting vote weight: " << e.what() << endl;
    }
    cout << "------------------------------" << endl;
}

array<Byte, 32> genKeyAES(gmp_randstate_t& rand_state) {
    array<Byte, 32> aes_key;
    cout << "\nGenerating random 256-bit AES key using GMP..." << endl;
    mpz_class rand_aes_key;
    // Generate 256 random bits using the provided random state
    mpz_urandomb(rand_aes_key.get_mpz_t(), rand_state, 256);

    // --- Export mpz_class bytes to array ---
    fill(aes_key.begin(), aes_key.end(), 0); // Initialize the array
    size_t bytes_exported = 0;
    // Export the bits into the byte array
    mpz_export(aes_key.data(),        // Pointer to the output array
               &bytes_exported,       // Pointer to store the number of bytes written
               1,                     // Order (most significant byte first)
               sizeof(Byte), // Size of each element in the array
               0,                     // Endianness (0 for native)
               0,                     // Nails (0)
               rand_aes_key.get_mpz_t()); // GMP integer to export

    // --- Optional: Print the generated key ---
    char* hex_key_str = mpz_get_str(nullptr, 16, rand_aes_key.get_mpz_t());
    cout << "Generated AES Key (Hex): " << hex_key_str << endl;
    free(hex_key_str);
    cout << "----------------------------------------" << endl;

    return aes_key; // Return the generated key
}

bool printResults(
    const mpz_class& decryptedTally,
    int numCandidates,
    int max_voters, // This is k
    const vector<int>& actualVoteCounts,
    int num_votes)
{
    // Calculate M = k + 1
    mpz_class M = mpz_class(max_voters) + 1;
    cout << "Decoding Paillier results (using M = " << M << ")..." << endl;
    vector<long> decodedCounts(numCandidates);
    mpz_class temp_total = decryptedTally;

    // Loop through each candidate to extract their count via modulo M
    for (int i = 0; i < numCandidates; i++) {
        mpz_class remainder = temp_total % M;
        decodedCounts[i] = remainder.get_si();
        // Integer division to prepare for the next candidate's count
        temp_total = temp_total / M;
    }

    // --- Verify & Print Results ---
    cout << "\n--- Simulation Results ---" << endl;
    bool verification_passed = true;
    long total_decoded_votes = 0;

    // Loop through decoded counts and compare with actual simulated counts
    for (int i = 0; i < numCandidates; ++i) {
        total_decoded_votes += decodedCounts[i];
        cout << " Candidate " << i << ": " << decodedCounts[i] << " votes";

        // Check if actual counts are available and indices match
        if (static_cast<long>(actualVoteCounts[i]) == decodedCounts[i]) {
            cout << " (Verification: Passed)" << endl;
             verification_passed = true;
        } 
        else {
            cout << " (Verification: FAIL! Expected " << actualVoteCounts[i] << ")" << endl;
            verification_passed = false;
        }
    }

    // Verify total decoded vote count against the number simulated
    cout << " Total votes decoded: " << total_decoded_votes << endl;
    if (total_decoded_votes != num_votes){
        cerr << " WARNING: Total decoded votes (" << total_decoded_votes
             << ") does not match number of simulated votes (" << num_votes << ")!" << endl;
        verification_passed = false;
    }

    // Print final verification status
    if (verification_passed) {
        cout << "\n SUCCESS: Paillier tally simulation verified." << endl;
    } else {
        cout << "\n FAILED: Discrepancy found in Paillier tally simulation." << endl;
    }

    return verification_passed;
}