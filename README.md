# Multiplicative-to-Additive Shares Conversion

This project implements the Multiplicative-to-Additive (MtA) protocol using Correlated Oblivious Transfer (COT) for securely converting multiplicative shares of a secret value into additive shares, without revealing either party's input.

## Prerequisites

To build and run this project, you need:

- C compiler (GCC or Clang)
- CMake (version 3.10 or higher)
- Git (for cloning the repository)

## Building the Project

Follow these steps to build the project:

```bash
# Clone the repository
git clone https://github.com/Anonymous5164/Multiplicative_to_Additive.git
cd Multiplicative_to_Additive

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
cmake --build .
```

## Running the Application

After building, run the executable:

```bash
./mta_protocol
```

This will execute the test implementation of the MtA protocol, which:
1. Generates random multiplicative shares for both parties
2. Performs the MtA protocol to convert them to additive shares
3. Verifies that a*b = c+d (mod order)

## Project Structure

```
├── include/           # Header files
│   ├── base_ot.h      # Base Oblivious Transfer protocol
│   ├── cot.h          # Correlated Oblivious Transfer protocol
│   ├── mta.h          # Multiplicative-to-Additive protocol
│   ├── utils.h        # Utility functions
│   └── logger.h       # Logging functionality
├── src/               # Source files
│   ├── base_ot.c      # Base OT implementation
│   ├── cot.c          # COT implementation
│   ├── mta.c          # MtA implementation
│   ├── utils.c        # Utility functions implementation
│   └── logger.c       # Logger implementation
├── external/          # External dependencies
│   └── ...            # Trezor's crypto library files and optimized point operations
├── test/              # Test implementations
│   ├── mta_test.c     # MtA protocol test
│   └── mta_test.h     # Test header file
├── main.c             # Main entry point
└── CMakeLists.txt     # CMake build configuration
```

## Implementation Details

The implementation follows a layered approach:

1. **Base OT Protocol** (`base_ot.h/c`): Implements the fundamental 1-out-of-2 oblivious transfer protocol where:
   - Alice (sender) has two messages m0, m1
   - Bob (receiver) selects one message with a choice bit c
   - Bob receives mc without learning m1-c
   - Alice learns nothing about Bob's choice bit c

2. **Correlated OT Protocol** (`cot.h/c`): Extends base OT with a correlation:
   - Alice only needs to provide a correlation value Δ where m1 = m0 + Δ
   - Enables more efficient protocol execution

3. **MtA Protocol** (`mta.h/c`): Implements the main protocol:
   - Alice has input a
   - Bob has input b
   - After protocol execution, Alice obtains c and Bob obtains d
   - Such that a*b = c+d (mod order)
   - Uses bit-by-bit processing with Correlated OT

## Logging

The implementation includes a logging system that records all protocol steps. The log is written to `build/activity.log` and includes:

- Alice's and Bob's multiplicative shares
- Protocol execution details for each bit
- Keys generated during the protocol
- Messages exchanged
- Final verification results

Sample log output for a single bit:

```
[DEBUG] === MtA Bit 0 (Alice) ===
[DEBUG] Alice's secret a: 6d48b3c5ad9f8a35af8775dc11104bf7a55b1e5fb5cdc5548823db269963e0d4
[DEBUG] Alice's message m0: ca87fe9f3aacf421d149b9619d7972e679209e432a8717a2c641f7ff635a57c4
[DEBUG] Alice's message m1: b5ffeb0db3e64b49fc4ab018b79975de3c1a4a94f11ddc3269601e4b9180f712
[DEBUG] === MtA Bit 0 (Bob) ===
[DEBUG] Bob's secret b: c906ac941376a63612c2fe1ba923d249454e7ef169fa1b43cbf21df7926455fe
[DEBUG] Bob's choice bit: 1
[DEBUG] Bob derived k_c: 848aca7a9bc9b1e1edbd24a9cc1f93c5920fdd967eefb272c63399cac8a54482
[DEBUG] Alice's key for bit 0: 83ed551991988fc9235227c59e336f76498d0bbb396caa1d22b3d75a4ce4eb39
[DEBUG] Alice's key for bit 1: 848aca7a9bc9b1e1edbd24a9cc1f93c5920fdd967eefb272c63399cac8a54482
```

## Notes on Implementation

- The implementation uses the secp256k1 elliptic curve (same as used in Bitcoin) for cryptographic operations.
- Uses SHA-256 for key derivation and XOR for encryption as specified in the requirements.
- All integers are processed within the finite field of the secp256k1 curve order.
- For the elliptic curve point operations, I found that some of the point operations in Trezor's ECDSA library were not giving the desired outputs for this specific application. I've added an external optimized versions of these operations that provide better performance and numerical stability specifically for the MtA protocol. These enhanced operations are included in the `external` directory.
- The test module randomly generates two 256-bit values represented in hexadecimal format as multiplicative shares for Alice and Bob. These values are then processed through the MtA protocol to obtain the corresponding additive shares.

## Verification

The protocol includes a verification step that confirms the mathematical relation a*b = c+d (mod order) holds after protocol execution, proving its correctness.