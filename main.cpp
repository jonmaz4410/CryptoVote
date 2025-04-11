#include "paillier.h" // Include the Paillier header
#include "aes.h"      // Include AES header for encryptAES256
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <gmpxx.h>
#include <ctime>
#include <cstdlib>
#include <limits> // For clearing input buffer in decrypt prompt

using namespace std;

int main() {
    // --- Variable Declarations ---
    int numCandidates = 0;
    int max_voters_k = 0;
    int num_votes_to_simulate = 0;
    int paillierKeySize = 1024; // Paillier key size

    gmp_randstate_t rand_state; // GMP random state
    bool rand_init = false;

    PaillierKeys paillierKeys;
    array<unsigned char, 32> aes_key;
    vector<mpz_class> weights;
    vector<EncryptedBallot> allBallots; // Declare here
    vector<int> actualVoteCounts; // Declare here
    mpz_class encryptedTally;
    mpz_class decryptedTally;

    try {
        // --- User Input ---
        cout << "\n--- Paillier+AES Voting Simulation Setup ---" << endl;
        cout << "Enter the number of candidates: "; cin >> numCandidates; /* Add validation */
        cout << "Enter the maximum expected total number of voters (k): "; cin >> max_voters_k; /* Add validation */
        cout << "Enter the number of votes to simulate for this test run: "; cin >> num_votes_to_simulate; /* Add validation */
        cout << "----------------------------------------" << endl;


        // --- Initialization ---
        cout << "\nInitializing random states..." << endl;
        gmp_randinit_mt(rand_state);
        unsigned long seed = static_cast<unsigned long>(time(nullptr));
        gmp_randseed_ui(rand_state, seed);
        srand(time(nullptr)); // Seed C's rand()
        rand_init = true;
        cout << "Random states initialized." << endl;


        // --- Key Generation ---
        cout << "Generating Paillier keys (Size: " << paillierKeySize << " bits)..." << endl;
        paillierKeys = genKeyPaillier(paillierKeySize);
        cout << "Paillier keys generated." << endl;
        aes_key = genKeyAES(rand_state); // Call function



        


        // --- Simulation & Encryption Loop (Now in main) ---
        cout << "Simulating and encrypting " << num_votes_to_simulate << " votes..." << endl;
        weights = calcWeights(numCandidates, max_voters_k); // Call function
        allBallots.clear();
        allBallots.reserve(num_votes_to_simulate);
        actualVoteCounts.assign(numCandidates, 0); // Initialize counts

        for (int i = 0; i < num_votes_to_simulate; i++) {
            // Generate simulated PII
            string firstName = "FName_" + to_string(i);
            string lastName = "LName_" + to_string(i);
            string pii = firstName + " " + lastName;

            // Encrypt PII using AES (Call function from aes.cpp via aes.h)
            vector<unsigned char> enc_pii = encryptAES256(pii, aes_key);

            // Simulate a random vote choice
            int voterChoice = rand() % numCandidates;
            actualVoteCounts[voterChoice]++;

            // Get the corresponding plaintext weight (Call function from paillier.cpp)
            mpz_class plaintextWeight = getVoteWeight(voterChoice, weights);

            // Encrypt the weight using Paillier (Call function from paillier.cpp)
            mpz_class enc_weight = encVote(plaintextWeight, paillierKeys, rand_state);

            // Store the encrypted ballot
            allBallots.push_back({enc_pii, enc_weight});
        }
        cout << num_votes_to_simulate << " votes processed and encrypted." << endl;


        // --- Tallying (Loop in main) ---
        cout << "Tallying Paillier encrypted votes..." << endl;
        if (!allBallots.empty()) {
            encryptedTally = allBallots[0].encWeight;
            for (size_t i = 1; i < allBallots.size(); i++) {
                // Call function from paillier.cpp
                encryptedTally = addVotes(encryptedTally, allBallots[i].encWeight, paillierKeys);
            }
            cout << "Tallying complete." << endl;
        } else {
             cout << " No votes to tally." << endl;
        }


        // --- Decryption ---
        if (!allBallots.empty()) {
             cout << "Decrypting final Paillier tally..." << endl;
             // Call function from paillier.cpp
             decryptedTally = decVote(encryptedTally, paillierKeys);
             cout << " Decrypted total sum (m_total): " << decryptedTally << endl;
        } else {
            decryptedTally = 0;
             cout << "No votes tallied, decrypted sum is 0." << endl;
        }


        // --- Results & Verification ---
        // Call function from paillier.cpp
        bool success = printResults(decryptedTally, numCandidates, max_voters_k, actualVoteCounts, num_votes_to_simulate);


        // --- Optional Individual Decryption (Prompt in main) ---
        cout << "\n----------------------------------------" << endl;
        cout << "\n----------------------------------------" << endl;
        if (!allBallots.empty()) {
            char choice = 'n';
            cout << "Do you want to decrypt a specific ballot? (y/n): ";
            cin >> choice; // Assume y/Y/n/N input

            if (choice == 'y' || choice == 'Y') {

                decryptBallot(allBallots, paillierKeys, aes_key);
            } else {
                cout << "Skipping individual ballot decryption." << endl;
            }
        } else {
             cout << "No ballots were generated to decrypt." << endl;
        }


    } catch (const exception& e) {
        cerr << "\nCritical Error in Main: " << e.what() << endl;
        if (rand_init) { gmp_randclear(rand_state); cout << "\nGMP random state cleared due to error." << endl; }
        return 1;
    }

    // --- Cleanup ---
    if (rand_init) {
        gmp_randclear(rand_state);
        cout << "\nGMP random state cleared." << endl;
    }
    cout << "===== Simulation Finished =====\n" << endl;
    return 0;
}