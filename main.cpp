#include "paillier.h" 
#include "aes.h"      
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <gmpxx.h>
#include <unistd.h> 

using namespace std;
using Byte = unsigned char;

int main() {
    // --- Variable Declarations ---
    int numCandidates = 0;
    int max_voters = 0;
    int num_votes = 0;
    int paillierKeySize = 1024;
    gmp_randstate_t rand_state;
    bool rand_init = false;
    PaillierKeys paillierKeys;
    array<Byte, 32> aes_key;
    vector<mpz_class> weights;
    vector<EncryptedBallot> allBallots;
    vector<int> actualVoteCounts;
    mpz_class encryptedTally;
    mpz_class decryptedTally;

    try {
        // --- User Input ---
        cout << "\n--- Paillier+AES Voting Simulation Setup ---" << endl;
        if (isatty(fileno(stdin))) {
            // Interactive mode
            cout << "Enter the number of candidates: ";
            cin >> numCandidates;
            cout << "Enter the maximum expected total number of voters (k): ";
            cin >> max_voters;
            cout << "Enter the number of votes to simulate for this test run: ";
            cin >> num_votes;
        } else {
            // Piped from backend
            cin >> numCandidates >> max_voters >> num_votes;
        }
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
        aes_key = genKeyAES(rand_state);

        // --- Simulation & Encryption ---
        cout << "Simulating and encrypting " << num_votes << " votes..." << endl;
        weights = calcWeights(numCandidates, max_voters);
        allBallots.clear();
        allBallots.reserve(num_votes);
        actualVoteCounts.assign(numCandidates, 0);

        for (int i = 0; i < num_votes; i++) {
            // Generate simulated PII
            string firstName = "FName_" + to_string(i);
            string lastName = "LName_" + to_string(i);
            string pii = firstName + " " + lastName;

            // Encrypt PII using AES
            vector<Byte> enc_pii = encryptAES256(pii, aes_key);

            // Simulate a random vote choice
            int voterChoice = rand() % numCandidates;
            actualVoteCounts[voterChoice]++;

            // Get the corresponding plaintext weight
            mpz_class plaintextWeight = getVoteWeight(voterChoice, weights);

            // Encrypt the weight using Paillier
            mpz_class enc_weight = encVote(plaintextWeight, paillierKeys, rand_state);

            // Store the encrypted ballot
            allBallots.push_back({enc_pii, enc_weight});
        }
        cout << num_votes << " votes processed and encrypted." << endl;

        // --- Tallying---
        cout << "Tallying Paillier encrypted votes..." << endl;
        if (!allBallots.empty()) {
            encryptedTally = allBallots[0].encWeight;
            for (size_t i = 1; i < allBallots.size(); i++) {
                encryptedTally = addVotes(encryptedTally, allBallots[i].encWeight, paillierKeys);
            }
            cout << "Tallying complete." << endl;
        }
        else {
            cout << " No votes to tally." << endl;
        }

        // --- Decryption ---
        if (!allBallots.empty()) {
             cout << "Decrypting final Paillier tally..." << endl;
             decryptedTally = decVote(encryptedTally, paillierKeys);
             cout << " Decrypted total sum: " << decryptedTally << endl;
        }
        else {
            decryptedTally = 0;
            cout << "No votes tallied." << endl;
        }


        // --- Results & Verification ---
        bool success = printResults(decryptedTally, numCandidates, max_voters, actualVoteCounts, num_votes);
        if (success) {
            cout << "Results verified successfully." << endl;
        } else {
            cout << "Results verification failed." << endl;
        }

        // --- Individual Decryption with PII ---
        cout << "\n----------------------------------------" << endl;
        if (!allBallots.empty()) {
            char choice = 'n';
            cout << "Do you want to decrypt a specific ballot? (y/N): ";
            cin >> choice; // Assume y/Y/x input

            while (choice == 'y' || choice == 'Y') {
                decryptBallot(allBallots, paillierKeys, aes_key);
                cout << "Would you like to decrypt another ballot? (y/N): ";
                cin >> choice; 
            } 
        }
        else {
            cout << "No ballots were generated to decrypt." << endl;
        }


    } catch (const exception& e) {
        cerr << "\nCritical Error in Main: " << e.what() << endl;
        cout << "Simulation aborted." << endl;
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