#include "paillier.h" // Include the Paillier header (adjust path if needed initially, but -Iinclude should handle this after build update)
#include <iostream>       // For cout/cerr
#include <exception>      // For std::exception

int main() {

    try {
        // Run the main simulation logic
        simulateVotes();
    } catch (const exception& e) {
         // Catch any critical errors propagating up
        cerr << "\nCritical Error in Main: " << e.what() << endl;
        return 1;
    }
    return 0;
}