# CryptoVote: Paillier & AES Secure Voting Simulation

## 1. Introduction

* **Authors:** Jonathan Mazurkiewicz, Julia Antunes
* **What it is:** CryptoVote is a C++ command-line application that simulates a secure electronic voting system. It uses the Paillier cryptosystem (with a 1024-bit key size in this simulation) for encrypting vote weights and AES-256 for encrypting voter Personally Identifiable Information (PII).
* **Why it exists:** This project demonstrates how cryptographic techniques like Partially Homomorphic Encryption (PHE) and symmetric encryption can be combined to build a conceptual secure e-voting system, allowing votes to be tallied without decrypting individual ballot choices during the counting process. This specific implementation was created for a school project.

## 2. Building the Project

This project requires a C++ compiler (supporting C++11 or later) and the GMP library.

**Step 1: Install Dependencies**

* **GMP Library:** You need both the GMP library and its development headers. Installation methods vary by operating system (common package names might be `libgmp-dev` or `gmp-devel`).
* **Note:** If you install GMP in a non-standard location, you may need to tell the compiler where to find the headers and library files using `-I/path/to/gmp/include` and `-L/path/to/gmp/lib` flags, respectively.

**Step 2: Compile the Code**

* Navigate to the root directory of the project (`CryptoVote-main`) in your terminal.
* Assuming you have `g++` installed and the necessary source files are in place (`main.cpp`, `src/paillier.cpp`, `src/aes.cpp`, `include/paillier.h`, `include/aes.h`), you can compile the project using a command similar to this:

    ```bash
    g++ main.cpp src/paillier.cpp src/aes.cpp -o cryptovote -Iinclude -lgmp -lgmpxx -std=c++11
    ```

    * **`g++`**: Invokes the GCC C++ compiler. Replace with `clang++` or your compiler if different.
    * **`main.cpp src/paillier.cpp src/aes.cpp`**: Specifies the C++ source files to compile.
    * **`-o cryptovote`**: Sets the name of the output executable file to `cryptovote`.
    * **`-Iinclude`**: Tells the compiler to look for header files (`.h`) in the `include` directory.
    * **`-lgmp -lgmpxx`**: Links the compiled code against the GMP and GMP C++ libraries. The order might matter on some systems.
    * **`-std=c++11`**: Ensures the code is compiled using at least the C++11 standard.

**Step 3: Run the Executable**

* Once compiled successfully, you can run the simulation from the same directory:

    ```bash
    ./cryptovote
    ```

* The program will then prompt you for the necessary inputs.

## 3. Running the Fullstack Web App
###  Project Structure

```
CryptoVote/
├── backend/           # Express server + C++ binary
│   ├── server.js
│   ├── bin/cryptovote (compiled binary)
├── ui/                # React frontend
│   └── src/
```

### Setup Steps

## 1. Build the C++ Binary
cd backend
../main.cpp ../src/paillier.cpp ../src/aes.cpp -o bin/cryptovote -I../include -lgmp -lgmpxx -std=c++11

## 2. Start the Express Backend 
cd backend
node server.js

## 3. Start the React Frontend

cd ui
npm install
npm run dev



## 4. What is PHE and Why Use It for Secure Voting?

* **Partially Homomorphic Encryption (PHE):** PHE is a type of encryption that allows specific mathematical operations (like addition or multiplication) to be performed directly on ciphertexts without needing to decrypt them first. The result of the computation, when decrypted, matches the result of the same operation performed on the original plaintexts.
* **Paillier Cryptosystem:** The Paillier cryptosystem, used in this project, is an example of PHE that is additively homomorphic. This means you can add multiple encrypted values together, and the result is the encryption of the sum of the original values.
* **Why PHE for Secure Voting:** In voting, privacy and integrity are critical. PHE (specifically Paillier here) allows an authority to sum up all the encrypted votes to get an encrypted total. Only this final encrypted total needs to be decrypted to reveal the election results. Individual votes remain encrypted throughout the tallying process, protecting voter privacy. This prevents anyone tallying the votes from knowing individual choices while still ensuring the final count is accurate.

## 5. PII Encryption with AES

While the Paillier cryptosystem secures the *vote weights* for homomorphic tallying, this project adds another layer of security by encrypting the voter's Personally Identifiable Information (PII) separately using the Advanced Encryption Standard (AES). Specifically, it uses AES-256 in CBC mode.

**Why use AES for PII?**

* **Protecting Voter Privacy:** The primary goal is to decouple the voter's identity from their vote during the main tallying process. Encrypting PII with AES means that even someone observing the encrypted ballots cannot directly link a specific voter to their encrypted vote choice without having the separate AES decryption key.
* **Defense in Depth:** Using different cryptographic mechanisms for different data types adds resilience. Paillier handles the specialized task of countable encryption, while AES, a robust and widely trusted symmetric encryption standard, efficiently handles the encryption of the PII string data.
* **Auditability vs. Anonymity:** Although the core tallying process preserves anonymity, real-world systems often need auditability. Encrypting PII with a separate AES key allows for this possibility under controlled circumstances (like a specific audit request) without exposing all PII during the general counting phase. Access to the AES key would be strictly controlled.

In this simulation, each `EncryptedBallot` stores both the Paillier-encrypted vote weight and the AES-encrypted PII. A single, randomly generated AES key is used for all PII encryption within a simulation run.

## 6. Code Workflow (`main.cpp`)

The simulation follows these general steps:

1.  **Setup:** The program prompts the user for the number of candidates, the maximum expected number of voters (k), and the number of votes to simulate.
2.  **Initialization:** Initializes random states for cryptographic operations (GMP and standard C `rand()`).
3.  **Key Generation:**
    * Generates Paillier public/private keys (e.g., 1024 bits).
    * Generates a random 256-bit AES key for PII encryption.
4.  **Weight Calculation:** Calculates base-M encoding weights (M = k + 1) for Paillier encryption based on the number of candidates and max voters.
5.  **Vote Simulation & Encryption:**
    * Loops for the specified number of votes.
    * For each vote: generates mock PII, encrypts PII using AES, simulates a vote choice, gets the Paillier plaintext weight, encrypts the weight using Paillier, stores the `EncryptedBallot` (encrypted PII + encrypted weight), and tracks actual counts for verification.
6.  **Homomorphic Tallying:** Adds all encrypted Paillier vote weights together using ciphertext multiplication.
7.  **Tally Decryption:** Decrypts the final aggregated Paillier ciphertext using the private key.
8.  **Results & Verification:** Decodes the decrypted tally (using base-M) to get counts per candidate and compares them against the actual counts recorded during simulation.
9.  **Optional Individual Decryption:** Prompts the user if they want to decrypt a specific ballot by index, then decrypts and displays both the AES-encrypted PII and the Paillier-encrypted vote weight for that ballot.

## 7. Input Validations

The code currently takes the following user inputs in `main.cpp`:

* Number of candidates <= 50
* Maximum expected total number of voters (k) <= 25000
* Number of votes to simulate <= k

It is not recommended to use more than 50 candidates or more than 25000 votes unless your computer is very fast in the current iteration, considering Paillier-1024 and AES-256 (4/11/2025).