# Contents
- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Test it yourself](#test-it-yourself)
- [Quality](#quality)
- [Roadmap](#roadmap)
- [Benchmarks](#benchmarks)
- [Compilation](#benchmarks)

# About
Daedalus Turbo is an open-source project that aims to improve drastically (>=10x) the blockchain synchronization performance of the Daedalus wallet, the primary fully decentralized wallet of the Cardano blockchain. The project has a two-year schedule presented in its [roadmap](#roadmap), and its technical approach is based on two key ideas: reducing the necessary network bandwidth through the use of compression and maximizing the use of parallel computation during the processing of blockchain data. These ideas are further explained in the following research reports:
- [On the Security of Wallet Nodes in the Cardano Blockchain](./doc/2024-sierkov-on-wallet-security.pdf) explains the security approach.
- [Parallelized Ouroboros Praos](./doc/2024-sierkov-parallelized-ouroboros-praos.pdf) explains the approach to parallelized data validation.
- [Highly Parallel Reconstruction of Wallet History in the Cardano Blockchain](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf) explains the approach to wallet history reconstruction.
- [Scalability of Bulk Synchronization in the Cardano Blockchain](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf) explains the network infrastructure requirements, the need for compressing proxies, and how the approach can be scaled to support up to a billion Cardano wallet nodes.

# Features
Currently supported:
- Incremental synchronization of compressed blockchain data over the Internet (the Turbo protocol)
- Incremental synchronization using the normal Cardano Network protocol (no compression)
- Incremental synchronization from a local Cardano Node instance
- Parallelized Ouroboros Praos data validation (full consensus validation)
- Ouroboros Genesis chain selection rule when synchronizing with a Cardano Network peer
- Interactive reconstruction of balances and transaction histories of stake and payment addresses
- Compressed local storage of blockchain data (compression ratio ~4.5x)
- Interactive search for transaction data
- ADA and non-ADA assets
- Blockchain Explorer Desktop User Interface
- Evaluation of Plutus programs

In active development:
- Validation of Plutus script witnesses to enable the full tail validation, as explained in [On the Security of Wallet Nodes in the Cardano Blockchain](./doc/2024-sierkov-on-wallet-security.pdf)
- Support for Cardano Chang hard fork

As the project matures and moves through its [roadmap](#roadmap), the list of supported features will grow.

# Requirements
- a modern CPU with 8+ physical cores (will refuse to work on anything weaker than an Orange Pi 5 Plus)
- 16+GB of RAM (The more cores a CPU has, the more RAM is needed)
- a fast SSD with ~80GB of free space:
  - ~60GB for the compressed blockchain data and search indices
  - ~20GB for temporary use during indexing
- a fast Internet connection (250 Mbps or better)

# Test it yourself

One can test the software using two methods:
- Building the software from the source code using Docker
- Downloading and installing a prebuilt binary

Each is described in more detail below.

## Cardano Chang fork support
On September 1, 2024 Cardano has introduced a number of new features with its Chang hard fork.
The support for them is being actively developed. However, for the time being, the previous builds of DT Explorer likely won't work.
On the other hand, the command line demo described below should work but limit the data to the last epoch of Cardano's Babbage era.

## Command line interface

### Prerequisites
To test the command line interface, you need the following software packages installed:
- [Git](https://git-scm.com/) to get a copy of this repository.
- [Docker](https://www.docker.com/products/docker-desktop/) to launch the software in an isolated environment.

### Commands

Clone this repository and make it your working directory:
```
git clone https://github.com/sierkov/daedalus-turbo.git dt
cd dt
```

Build the test Docker container:
```
docker build -t dt -f Dockerfile.test .
```

Start the test container, with `<cardano-dir>` being the host's directory to store the blockchain data:
```
docker run -it --rm -v <cardano-dir>:/data/cardano dt
```

All the following commands are to be run within the container started by the previous command.

Download, validate, and prepare for querying a copy of the Cardano blockchain from a network of compressing proxies with entry points listed in [etc/mainnet/turbo.json](etc/mainnet/turbo.json):
```
./dt sync-turbo /data/cardano
```

(Optional) Revalidate the data downloaded by sync-turbo for benchmark purposes:
```
./dt revalidate /data/cardano
```

(Optional) Compare the downloaded chain vs a Cardano Network node (`relays-new.cardano-mainnet.iohk.io` by default) and fetch differences if necessary:
```
./dt sync-p2p /data/cardano
```

Reconstruct the latest balance and transaction history of a stake key:
```
./dt stake-history /data/cardano stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg
```

Reconstruct the latest balance and transaction history of a payment key:
```
./dt pay-history /data/cardano addr1q86j2ywajjgswgg6a6j6rvf0kzhhrqlma7ucx0f2w0v7stuau7usgm94re2n6fhe9ee88c2u5ta5znnwwtlxpsulzrdqv6rmuj
```

Show information about a transaction:
```
./dt tx-info /data/cardano 357D47E9916B7FE949265F23120AEED873B35B97FB76B9410C323DDAB5B96D1A
```

Evaluate a Plutus script and show its result and costs:
```
./dt plutus-eval ../data/plutus/conformance/example/factorial/factorial.uplc
```

## Pre-built binaries for Windows and Mac (ARM64)

The latest builds of the DT Explorer application can be found in the Assets section of [the latest GitHub release](https://github.com/sierkov/daedalus-turbo/releases/latest) page.
It shows the new synchronization and history-reconstruction algorithms in a safe and easy-to-test way by working without private keys and directly reconstructing history of any payment and stake address.

### How to install on Windows
- Download and launch the installer from the Assets section of [the latest release](https://github.com/sierkov/daedalus-turbo/releases/latest) page.
- Choose locations for the program files and blockchain data (each will be asked individually). For optimal performance, it's important to select your fastest SSD drive if you have multiple storage devices. 

Windows builds have been tested with Windows 11 (earlier versions may work but have yet to be be tested).

### How to install on Mac
- Download the Mac image from the Assets section of [the latest release](https://github.com/sierkov/daedalus-turbo/releases/latest) page.
- Open the image. This is a development (unsigned) image, so Mac OS will ask you if you trust the developer: [See Apple's explanation and instructions](https://support.apple.com/en-is/guide/mac-help/mh40616/mac).
- Copy dt-explorer app to your Applications folder.
- Both program and blockchain data will be stored in that folder, so when deleted all used space will be recovered.
- Launch the app from the Applications folder. If Mac OS says that the app is damaged, open a terminal and run ```sudo xattr -rc /Applications/dt-explorer.app```.

Mac builds have been tested with Mac OS Sonoma (earlier versions may work but have yet to be be tested).

### How to use
- Synchronization (full or partial) always happens at the app's launch; to catch up, simply restart the app. If you restart before the synchronization is finished, the app will reuse already downloaded data but may reprocess and revalidate some of them.
- History reconstruction happens through a simple search for a transaction, stake, or payment address, either entered explicitly or when clicked as part of blockchain exploration. The easiest starting point for most users would be to search for their own stake address (e.g.: stake1uxw70wgydj63u4faymujuunnu9w2976pfeh89lnqcw03pksulgcrg), as its history will be the most representative of their wallet's history.
- When searching for Cardano addresses starting with "addr1" prefix, the app may ask you if want to explore the payment or stake history. The reason for that is that many cardano addresses contain two keys. If in doubt, select stake history as it will normally discover more transactions. This is necessary so that the app can work without private keys. However, when integrated into Daedalus, the same aglorithms can reconstruct the full wallet history by finding all payment and stake keys generated from a wallet private key.
- Once synchronized, users can turn off their Internet connection and test history reconstruction with new transaction or stake addresses to prove that the app reconstructs all histories interactively and uses only the downloaded blockchain data.

# Spread the word
Many in the Cardano community, including some developers of Daedalus, don't believe that it's possible to make it noticeably faster. This leads to a situation in which the development is not focused on its performance. If you're persuaded by the evidence presented here, share it on social media with those around you. Changing the beliefs of people can be harder than building top-notch technology. So, every single tweet and Facebook post makes a difference. Thank you!

# Supporting network infrastructure
The high-speed delivery of blockchain data depends on a network of compressing proxies (Cardano nodes that can share their local chain with other nodes in a compressed format and which are needed until the support for compressed data transfers becomes part of the regular Cardano network protocol). The current network configuration is sufficient to support up to 100'000 high-speed (with a download speed of 200+ Mbps) full blockchain synchronizations per year and orders of magnitude more incremental ones. The plan how to scale the network capacity
to support a billion clients is presented in the [Scalability of Bulk Synchronization in the Cardano Blockchain](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf) paper.

# Quality
The accuracy of the ledger state reconstruction has been tested by recreating the ledger state from raw blockchain data at the end (the presented method batches updates) of each post-Shelley epoch up to the mainnet's epoch 494, exporting it into the Cardano Node format, and comparing it with the snapshot produced by Cardano Node version 8.9.2. The source code of the tools used for the comparison is located in [lib/dt/cli-test/test-node-state.cpp](lib/dt/cli-test/test-node-state.cpp) and [lib/dt/cli-test/test-export-full.cpp](lib/dt/cli-test/test-export-full.cpp)

The indexing and history-reconstruction code has been tested using a sample of ten thousand randomly-selected stake keys. For 100% of those, the reconstructed ADA balance (excluding rewards) precisely matched the stake recorded in the ledger snapshot produced by Cardano Node. The testing was performed with slot number 106012751 at the tip of the blockchain. The code of the test is located in the [lib/dt/cli-test/test-stake-balances.cpp](lib/dt/cli-test/test-stake-balances.cpp) file.

# Roadmap
The development of the project is organized into the following milestones:
| Milestone | ETA | Status |
| --------- | --- | ------ |
| M1: Show that transaction history can be reconstructed 10x quicker | February 2023 | Ready |
| M2: Analyze the scalability of the Cardano network protocol and prepare requirements for the accelerated one | June 2023 | Ready |
| M3: Full POC of Daedalus Turbo: fast blockchain data delivery and transaction-history reconstruction | April 2024 | In review |
| M4: Integrate the POC with the official Daedalus builds | March 2025 | In Progress |

Due to the experimental nature of the project, the ETAs are tentative.
The development can go both faster and slower than expected.

# Benchmarks
The [experiment](./experiment/) directory contains the source code of benchmarks and experiments discussed in the research reports.

# Compilation
The software is in its proof-of-concept stage, and only the build path with Docker described above is regularly tested.
Nevertheless, compilation in other environments and with other compilers is possible and is tested from time to time.
The below notes may be helpful if you decide to build the software outside of Docker.

## Necessary software packages
- [CMake](https://cmake.org/) >= 3.28, a build system
- [boost](https://www.boost.org/) == 1.83, a collection of C++ libraries
- [fmt](https://github.com/fmtlib/fmt) >= 8.1.1, a string formatting library
- [libsodium](https://github.com/jedisct1/libsodium) >= 1.0.18, a cryptographic library
- [secp256k1](https://github.com/bitcoin-core/secp256k1) >= 0.2.0, a cryptographic library
- [spdlog](https://github.com/gabime/spdlog) >= 1.9.2, a logging library
- [zstd](https://github.com/facebook/zstd) >= 1.4.8, a compression library

Additionally on Windows:
- [mimalloc](https://github.com/microsoft/mimalloc) >= 2.0.5, a memory allocator that works well with multi-threaded workloads

## Tested environments and compilers
- Ubuntu Linux 24.04 with GCC 13.2
- Ubuntu Linux 24.04 with Clang 18
- Mac OS Sonoma 14.2.1 with Clang 17.0.6 installed with ```brew install llvm@17```
- Windows 11 with Visual C++ 19.39.33520.0 that comes with Visual Studio 2022 Community Edition
- Windows 11 with GCC 13.2 that comes with MinGW64

## Build instructions
Verify the presence of the necessary libraries and generate build files in `cmake-build-release` directory for a release build:
```
cmake -B cmake-build-release
```

Build `dt` binary using all available CPU cores (will be available in `cmake-build-release` directory):
```
cmake --build cmake-build-release -j -t dt
```