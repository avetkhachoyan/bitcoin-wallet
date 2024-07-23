# bitcoin-wallet
bitcoin-wallet on python - cli approach

This Bitcoin wallet application provides a command-line interface (CLI) and API to manage Bitcoin addresses, transactions, and private keys. It uses a master key to derive child keys, which are securely stored and encrypted. The application supports generating new Bitcoin addresses, creating and sending transactions, and generating QR codes for addresses.

## Features

- **Generate Bitcoin Wallet**: Create new Bitcoin addresses derived from a master key.
- **Create Transactions**: Generate and send Bitcoin transactions.
- **Secure Storage**: Master key and private keys are encrypted and stored securely.
- **QR Code Generation**: Generate QR codes for Bitcoin addresses.

## Prerequisites

- Python 3.7 or later
- Internet connection (for broadcasting transactions and fetching unspent outputs)

## Installation

1. **Clone the Repository**:

   ```sh
   git clone <repository-url>
   cd <repository-directory>
