# CryptoVote: Paillier & DES Secure Voting Simulation

**Authors:** Jonathan Mazurkiewicz, Julia Antunes

## Overview

CryptoVote is a command-line application demonstrating a conceptual secure electronic voting system. It utilizes the Paillier partially homomorphic cryptosystem to allow for the secure tallying of encrypted votes without decrypting individual ballots during the counting process. Additionally, it uses the Data Encryption Standard (DES) to encrypt voter Personally Identifiable Information (PII) associated with each ballot.

The primary execution starts in `main.cpp`, which calls the core simulation logic contained within the `simulateVotes()` function in `src/paillier.cpp`. This function manages the entire workflow:

* Setting up election parameters (candidates, voter numbers).
* Generating Paillier public/private key pairs.
* Handling DES key input for PII encryption.
* Simulating the casting of encrypted votes (Paillier for vote weight, DES for PII).
* Homomorphically tallying the encrypted vote weights.
* Decrypting the final Paillier tally to reveal election results.
* Verifying the decrypted results against the simulated vote counts.
* Optionally decrypting individual ballots (PII and vote weight) upon user request.

## Running the Simulation & User Inputs

Compile the project (ensuring the GMP library is linked). When you execute the compiled program, you will be guided through the following prompts:

1.  **Number of candidates:** Enter the total count of candidates participating (e.g., `3`).
2.  **Maximum expected total voters (k):** Provide the anticipated upper limit on the number of voters. This value (`k`) is crucial for the Base-M encoding (`M = k + 1`) used to represent votes for different candidates within the Paillier encryption (e.g., `1000`).
3.  **Number of votes to simulate:** Specify how many random votes the simulation should generate and process for this test run (e.g., `100`).
4.  **64-bit DES key (hexadecimal):** Input the secret DES key for PII protection. This must be a hexadecimal string (using `0-9`, `a-f`, `A-F`) with a maximum length of 16 characters (representing 64 bits). Example: `133457799BBCDFF1`.
5.  **(Optional) Decrypt specific ballot?:** After tallying, you'll be prompted with `(y/n)` to decide if you want to inspect a specific encrypted ballot.
6.  **(Optional) Ballot index:** If you answered `y`, enter the numerical index (0-based) of the ballot you want to decrypt.

The simulation output will display the final vote counts per candidate, verification status, and, if requested, the decrypted contents (PII and vote weight) of the chosen ballot.