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

#include "des.h"
#include "paillier.h"
//-------------------------------------------------------------
#include <iostream>
#include <gmpxx.h>      // For GMP C++ wrapper
#include <stdexcept>    // For exception handling
#include <ctime>
#include <string>
#include <vector> 
#include <cstring>      // For memcpy
#include <cstdlib>      // For srand, rand
#include <iomanip>      // For hex formatting of DES key output
#include <cctype>       // For isxdigit
#include <sstream>      // For stringstream
#include <limits>       // Required for error clearing fallback in DES key input

using namespace std;

/*
###########################################################################
    FUNCTION DEFINITIONS
###########################################################################
*/

// Computes the Paillier L function: L(x) = (x - 1) / n.
mpz_class L_function(const mpz_class& x, const mpz_class& n) {
    // Basic check to prevent division by zero
    if (n == 0) {
         throw std::invalid_argument("L_function: n cannot be zero.");
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
        throw std::runtime_error("Modular inverse does not exist. Check key generation inputs/logic.");
    }
    return result;
}

// Generates a random number 'r' such that 1 <= r < n and gcd(r, n) == 1.
mpz_class gen_rand_r(const mpz_class& n, gmp_randstate_t& rand_state) {
    // Ensure n is valid for the operation
    if (n <= 1) {
        throw std::invalid_argument("gen_rand_r: n must be greater than 1");
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
PaillierKeys generateKeys(int bitSize) {

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

    // Set generator g = n + 1 (a common choice)
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

// Homomorphically adds two encrypted votes (Paillier ciphertexts).
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

// Runs the main voting simulation logic.
void simulateVotes() {
    int numCandidates = 0;
    int max_voters_k = 0;
    int num_votes_to_simulate = 0;
    gmp_randstate_t paillier_rand_state;
    bool rand_init = false;
    uint64_t des_key = 0; 
    vector<EncryptedBallot> allBallots;
    vector<int> actualVoteCounts;
    PaillierKeys paillierKeys;

    try {

        cout << "\n--- Paillier+DES Voting Simulation Setup ---" << endl;
        cout << "Enter the number of candidates: ";
        cin >> numCandidates;
        cout << "Enter the maximum expected total number of voters (k): ";
        cin >> max_voters_k;
        cout << "Enter the number of votes to simulate for this test run: ";
        cin >> num_votes_to_simulate;
        cout << "----------------------------------------" << endl;
        cout << "Generating Paillier keys..." << endl;
        int keySize = 256;

        // --- Generate Paillier Keys
        paillierKeys = generateKeys(keySize);
        cout << "Paillier keys generated." << endl;

        // --- Get DES Key from User
        string key_hex_str;
        cout << "\nEnter a 64-bit DES key as up to 16 hexadecimal digits (e.g., 133457799BBCDFF1): ";
        while (true) {

            if (!getline(cin >> ws, key_hex_str)) {
                 cerr << " Input error reading key." << endl;
                 // Consider how to handle fatal input errors
                 throw runtime_error("Failed to read DES key input.");
            }

            // Validate length
            if (key_hex_str.length() > 16) {
                 cerr << " Input too long. Please enter up to 16 hex digits." << endl;
                 cout << "Enter up to 16 hex digits: ";
                 continue;
            }
             // Validate hex
             bool valid_hex = true;
             if (key_hex_str.empty()){
                 valid_hex = false;
             } else {
                 for(char c : key_hex_str) {
                     if (!isxdigit(c)) {
                         valid_hex = false;
                         break;
                     }
                 }
             }

             if (!valid_hex) {
                 cerr << " Invalid characters or empty input. Please use 0-9, a-f, A-F." << endl;
                 cout << "Enter up to 16 hex digits: ";
                 continue;
             }

            // Attempt to parse hex string
            stringstream ss;
            ss << hex << key_hex_str;
            ss >> des_key;

            // Check if parsing succeeded
            if (!ss.fail() && ss.peek() == EOF) {
                 cout << "Using DES key: 0x"
                      << hex << setfill('0') << setw(16) << des_key << dec
                      << endl;
                 break;
            } else {
                cerr << " Invalid hex format or unexpected characters." << endl;
                cout << "Enter up to 16 hex digits: ";
            }
        }

        // Calculate weights for encoding
        cout << "\nCalculating weights..." << endl;

        if (numCandidates <= 0 || max_voters_k < 0) {
             throw runtime_error("Invalid parameters for weight calculation (Candidates must be > 0, Max Voters >= 0).");
        }
        vector<mpz_class> weights = calcWeights(numCandidates, max_voters_k);
        mpz_class M = mpz_class(max_voters_k) + 1;
        cout << "Paillier weights calculated (Using M=" << M << ")" << endl;

        // --- Initialize Random State for Paillier
        cout << "\nInitializing random states..." << endl;
        gmp_randinit_mt(paillier_rand_state);
        srand(time(nullptr));
        rand_init = true;
        cout << "Random states initialized." << endl;

        // --- Simulate Votes, Encode, Encrypt (Paillier + DES)
        cout << "Simulating and encrypting " << num_votes_to_simulate << " votes..." << endl;
        allBallots.clear(); // Ensure vector starts empty
        allBallots.reserve(num_votes_to_simulate);
        actualVoteCounts.assign(numCandidates, 0);

        // --- Simulate votes
        for (int i = 0; i < num_votes_to_simulate; i++) {
            // Generate simulated names
            string firstName = "FName_" + to_string(i);
            string lastName = "LName_" + to_string(i);
            string pii = firstName + " " + lastName;

            // Encrypt PII using DES
            string enc_pii = encryptStringDES(pii, des_key);

            // Simulate a random vote choice
            int voterChoice = rand() % numCandidates;
            actualVoteCounts[voterChoice]++;

            // Get the corresponding plaintext weight (M^voterChoice)
            mpz_class plaintextWeight = getVoteWeight(voterChoice, weights);

            // Encrypt the weight using Paillier
            mpz_class enc_weight = encVote(plaintextWeight, paillierKeys, paillier_rand_state);

            // Store the encrypted PII and vote weight in the ballot vector
            allBallots.push_back({enc_pii, enc_weight});
        }
        cout << num_votes_to_simulate << " votes processed and encrypted." << endl;


        // --- Homomorphic Tallying
        cout << "Tallying Paillier encrypted votes..." << endl;
        mpz_class talliedVotes;
        if (allBallots.empty()) {
             cout << " No votes to tally." << endl;
                return;
        } else {
            // Initialize the tally with the first vote
            talliedVotes = allBallots[0].encWeight;

            // Loop through remaining votes
            for (size_t i = 1; i < allBallots.size(); i++) {
                talliedVotes = addVotes(talliedVotes, allBallots[i].encWeight, paillierKeys);
            }
        }
        cout << "Tallying complete." << endl;

        // --- Decrypt Final Paillier Tally
        cout << "Decrypting final Paillier tally..." << endl;
        mpz_class m_total = decVote(talliedVotes, paillierKeys);
        cout << " Decrypted total sum (m_total): " << m_total << endl;

        // --- Decode Paillier Tally
        cout << "Decoding Paillier results (using M = " << M << ")..." << endl;
        vector<long> decodedCounts(numCandidates);
        mpz_class temp_total = m_total;

        // Loop through each candidate to extract their count
        for (int i = 0; i < numCandidates; i++) {

            // Calculate remainder to get current candidate's count
            mpz_class remainder = temp_total % M;

            // Takes advantage of encoding to extract number of votes per candidate
            decodedCounts[i] = remainder.get_si();

            // Update the total by removing the current candidate's count
            temp_total = temp_total / M;
        }

        // --- Verify & Print Results
        cout << "\n--- Simulation Results ---" << endl;
        bool verification_passed = true;
        long total_decoded_votes = 0;

        // Loop through decoded counts and compare with actual simulated counts
        for (int i = 0; i < numCandidates; ++i) {
            total_decoded_votes += decodedCounts[i];
            cout << " Candidate " << i << ": " << decodedCounts[i] << " votes";

            // Compare decoded count with the actual count
            if (static_cast<long>(actualVoteCounts[i]) == decodedCounts[i]) {
                cout << " (Verification: Passed)" << endl;
            } else {
                cout << " (Verification: FAIL! Expected " << actualVoteCounts[i] << ")" << endl;
                verification_passed = false;
            }
        }

        // Verify decoded vote count
        cout << " Total votes decoded: " << total_decoded_votes << endl;
        if (total_decoded_votes != num_votes_to_simulate && !allBallots.empty()){
            cerr << " WARNING: Total decoded votes (" << total_decoded_votes
                 << ") does not match number of simulated votes (" << num_votes_to_simulate << ")!" << endl;
            verification_passed = false;
        }

        // Print verification status
        if (verification_passed) {
            cout << "\n SUCCESS: Paillier tally simulation verified." << endl;
        } else {
            cout << "\n FAILED: Discrepancy found in Paillier tally simulation." << endl;
        }

        // --- Ask user if they want to decrypt a ballot
        cout << "\n----------------------------------------" << endl;
        // Only offer if ballots exist
        if (!allBallots.empty()) {
            char choice = 'n'; // Default choice
            string line_buffer; // Buffer for user input line

            cout << "Do you want to decrypt a specific ballot? (y/n): ";
            // Read user's response
            if (getline(cin >> ws, line_buffer) && !line_buffer.empty()) {
                choice = line_buffer[0]; // Take the first character of the response
            }

            if (choice == 'y' || choice == 'Y') {
                decryptBallot(allBallots, paillierKeys, des_key);
            } else {
                cout << "Skipping individual ballot decryption." << endl;
            }
        } else {
             // Message if no ballots were created
             cout << "No ballots were generated to decrypt." << endl;
        }
    } catch (const exception& e) {
        // Catch standard exceptions during simulation
        cerr << "\nError during simulation: " << e.what() << endl;
    }

    // --- Cleanup
    if (rand_init) {
        gmp_randclear(paillier_rand_state);
        cout << "\nPaillier random state cleared." << endl;
    }
    cout << "===== Simulation Finished =====\n" << endl;

}

// Encrypts a std::string using DES CBC mode from the C implementation.
string encryptStringDES(const string& plaintext, uint64_t key) {

    // Generate random IV
    uint64_t iv = 0;
    unsigned char* iv_bytes = reinterpret_cast<unsigned char*>(&iv);
    for (int i = 0; i < 8; ++i) {
        iv_bytes[i] = static_cast<unsigned char>(rand() % 256);
    }

    // Convert plaintext to byte vector
    vector<unsigned char> byte_vector(plaintext.begin(), plaintext.end());
    size_t original_size = byte_vector.size();

    // Apply Zero Padding to make the data a multiple of the block size
    const int BLOCK_SIZE = 8;
    // Calculate number of blocks needed, ensuring at least one block for empty input
    size_t num_blocks_calc = (original_size == 0) ? 1 : (original_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    size_t padded_size = num_blocks_calc * BLOCK_SIZE;

    // Resize vector, filling new elements with 0
    byte_vector.resize(padded_size, '\0');

    int num_blocks = padded_size / BLOCK_SIZE;
    vector<uint64_t> blocks(num_blocks);
    if (padded_size > 0) {
        memcpy(blocks.data(), byte_vector.data(), padded_size);
    }

    // Call the C DES encryption function (defined in des.c/des.h)
    if (num_blocks > 0) {
        des_encrypt_cbc(blocks.data(), num_blocks, key, iv);
    }

    // Combine the generated IV and the resulting Ciphertext for output
    string result = "";
    const size_t IV_SIZE = 8;
    result.reserve(IV_SIZE + padded_size); // Pre-allocate space for efficiency

    // Prepend the 8-byte IV to the result string
    const char* iv_cbytes = reinterpret_cast<const char*>(&iv);
    result.append(iv_cbytes, IV_SIZE);

    // Append the encrypted blocks to the result string
    if (num_blocks > 0) {
        const char* ciphertext_bytes = reinterpret_cast<const char*>(blocks.data());
        result.append(ciphertext_bytes, padded_size);
    }

    return result; // Return "IV + Ciphertext"
}

// Decrypts a string (IV + Ciphertext) using DES CBC mode
string decryptStringDES(const string& iv_and_ciphertext, uint64_t key) {
    const int BLOCK_SIZE = 8;
    const size_t IV_SIZE = 8;

    // Validate input length: ciphertext part must be multiple of block size
    size_t ciphertext_size = iv_and_ciphertext.length() - IV_SIZE;
    if (ciphertext_size % BLOCK_SIZE != 0) {
        throw invalid_argument("decryptStringDES: Ciphertext length not a multiple of block size.");
    }

    // Extract the 8-byte IV from the beginning of the input string
    uint64_t iv = 0;
    memcpy(&iv, iv_and_ciphertext.data(), IV_SIZE);
    int num_blocks = ciphertext_size / BLOCK_SIZE;
    vector<uint64_t> blocks(num_blocks);

    // Copy the ciphertext part (after the IV) into the block buffer
    if (num_blocks > 0) {
        memcpy(blocks.data(), iv_and_ciphertext.data() + IV_SIZE, ciphertext_size);
    }

    // Decrypt
    if (num_blocks > 0) {
         des_decrypt_cbc(blocks.data(), num_blocks, key, iv);
    }

    // Convert decrypted blocks back to a byte vector
    vector<unsigned char> decrypted_bytes(ciphertext_size);
    if (num_blocks > 0) {
        memcpy(decrypted_bytes.data(), blocks.data(), ciphertext_size);
    }

    // Attempt to Remove Zero Padding
    // Find the last non-null character, assuming nulls were only used for padding.
    size_t actual_size = 0;
    for (size_t i = decrypted_bytes.size(); i > 0; --i) {
        if (decrypted_bytes[i - 1] != '\0') {
            actual_size = i; // Mark the end of the actual data
            break;
        }
    }
    // Resize the vector to remove trailing padding bytes
    decrypted_bytes.resize(actual_size);

    // Convert the unpadded byte vector back to a string
    string plaintext(decrypted_bytes.begin(), decrypted_bytes.end());

    return plaintext;
}

// Prompts user for a ballot index and decrypts/displays the PII and vote weight.
void decryptBallot(const vector<EncryptedBallot>& allBallots,
                   const PaillierKeys& paillierKeys,
                   uint64_t des_key) {

    long ballot_index = -1; // Variable to store user's chosen index
    long max_index = static_cast<long>(allBallots.size()) - 1;

    // Prompt user for the index
    cout << "Enter the ballot index to decrypt (0 to " << max_index << "): ";
    cin >> ballot_index;
    cout << "\n--- Decrypting Ballot #" << ballot_index << " ---" << endl;
    const EncryptedBallot& selectedBallot = allBallots[ballot_index];

    // Attempt to decrypt PII
    try {
        string decrypted_pii = decryptStringDES(selectedBallot.desEncryptedPII, des_key);
        cout << " Decrypted PII: \"" << decrypted_pii << "\"" << endl;
    } catch (const std::exception& e) {
        cerr << " Error decrypting PII: " << e.what() << endl;
    }

    // Attempt to decrypt Vote Weight
    try {
        mpz_class decrypted_weight = decVote(selectedBallot.encWeight, paillierKeys);
        cout << " Decrypted Plaintext Vote Weight (M^i): " << decrypted_weight << endl;
    } catch (const std::exception& e) {
         cerr << " Error decrypting vote weight: " << e.what() << endl;
    }
    cout << "------------------------------" << endl;
}