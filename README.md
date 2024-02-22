# Contents
- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [Test it yourself](#test-it-yourself)
- [Quality](#quality)
- [Roadmap](#roadmap)
- [Benchmarks](#benchmarks)

# About
Daedalus Turbo is an open-source project that aims to improve drastically (>=10x) the blockchain synchronization performance of the Daedalus wallet, the primary fully decentralized wallet of the Cardano blockchain. The project has a two-year schedule presented in its [roadmap](#roadmap), and its technical approach is based on two key ideas: reducing the necessary network bandwidth through the use of compression and maximizing the use of parallel computation during the processing of blockchain data. These ideas are further explained in the following research reports:
1. [Highly Parallel Reconstruction of Wallet History in the Cardano Blockchain](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf);
2. [Scalability of Bulk Synchronization in the Cardano Blockchain](./doc/2023_Sierkov_CardanoBulkSynchronization.pdf).
3. [Parallelized Ouroboros Praos](./doc/2024-sierkov-parallelized-ouroboros-praos.pdf).

# Features
Currently supported:
- Incremental synchronization and indexing of compressed blockchain data over the network;
- Incremental synchronization and indexing from a local Cardano Node instance;
- Reconstruction of balances and transaction histories of stake addresses;
- Reconstruction of balances and transaction histories of payment addresses;
- Quick search for transaction data;
- ADA and non-ADA assets;
- Direct reconstruction from compressed blockchain data;
- Blockchain Explorer Desktop User Interface;
- Parallelized Ouroboros Praos validation of blockchain data.

Currently not supported:
- Validation of Plutus and other scripts.

As the project matures and moves through its [roadmap](#roadmap), the list of supported features will grow.

# Requirements
- 8+-core CPU;
- 16+GB of RAM. The precise amount depends on the number of simultaneous execution threads your CPU can handle. The higher the number, the more RAM is needed;
- a fast SSD with ~60GB of free space;
  - ~50GB for the compressed blockchain data and search indices;
  - ~10GB for temporary use during indexing;
- a fast Internet connection (250 Mbps or better).

# Test it yourself

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
git checkout parallelized-ouroboros-praos
```

Build the test Docker container:
```
docker build -t dt -f Dockerfile.test .
```

Start the test container, with `<cardano-dir>` being the host's directory to store the blockchain data:
```
docker run -it --rm -v <cardano-dir>:/data/cardano dt
```

Download, validate, and prepare for querying a copy of the Cardano blockchain from a demo compressing server, [turbo1.daedalusturbo.org](http://turbo1.daedalusturbo.org/):
```
./dt sync-http /data/cardano
```

(Optional) To revalidate already downloaded data (for benchmark purposes, etc.):
```
./dt revalidate /data/cardano
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

## Blockchain Explorer Desktop User Interface

### Prerequisites
To test the desktop user interface, you need the following packages:
- [Git](https://git-scm.com/) to get a copy of this repository.
- [Docker](https://www.docker.com/products/docker-desktop/) to launch the software in an isolated environment.
- [Node.JS](https://nodejs.org/en/download/current) to start the user interface.

### Build

Clone this repository and make it your working directory:
```
git clone https://github.com/sierkov/daedalus-turbo.git dt
cd dt
git checkout parallelized-ouroboros-praos
```

Build the test Docker container:
```
docker build -t dt -f Dockerfile.test .
```

Install the necessary Node.JS modules:
```
cd ui
npm i
cd ..
```

### Launch

Launch the local API server which will store the downloaded blockchain data into the host's `<cardano-dir>` directory and will be listening at the address 127.0.0.1:55556 of the host machine:
```
docker run -it --rm -v <cardano-dir>:/data/cardano -p 127.0.0.1:55556:55556 dt ./dt http-api /data/cardano --ip=0.0.0.0
```

From a separate terminal window, while the http API is running, start the UI:
```
cd ui
npm start
```

During the first run, the API server will download the complete Cardano blockchain data, which may take a while.
If your test PC fulfills the [hardware requirements](#requirements), the initial synchronization should take less than one hour. The successive runs will sync only the updates since the previous sync.

Once you are done with testing the UI, stop the local API server by using Ctrl-C or closing the terminal in which you started it.

# Spread the word
Many in the Cardano community, including some developers of Daedalus, don't believe that it's possible to make it noticeably faster. This leads to a situation in which the development is not focused on its performance. If you're persuaded by the evidence presented here, share it on social media with those around you. Changing the beliefs of people can be harder than building top-notch technology. So, every single tweet and Facebook post makes a difference. Thank you!

# Quality
The accuracy of the ledger state reconstruction has been tested by comparing the reconstructed components
of the ledger state with those prepared by Cardano Node at the end of each Shelley+ epoch on the Cardano's mainnet up to 465.
The code of the test is located in the [test/validate-state.cpp](test/validate-state.cpp) file.

The indexing and history-reconstruction code has been tested using a sample of ten thousand randomly-selected stake keys. For 100% of those, the reconstructed ADA balance (excluding rewards) precisely matched the stake recorded in the ledger snapshot produced by Cardano Node. The testing was performed with slot number 106012751 at the tip of the blockchain. The code of the test is located in the [test/validate-balance.cpp](test/validate-balance.cpp) file.

# Roadmap
The development of the project is organized into the following milestones:
| Milestone | ETA | Status |
| --------- | --- | ------ |
| M1: Show that transaction history can be reconstructed 10x quicker | February 2023 | Ready |
| M2: Analyze the scalability of the Cardano network protocol and prepare requirements for the accelerated one | June 2023 | Ready |
| M3: Full POC of Daedalus Turbo: fast blockchain data delivery and transaction-history reconstruction | March 2024 | In review |
| M4: Integrate the POC into the official Daedalus builds | February 2025 | Planned |

Due to the experimental nature of the project, the ETAs are tentative.
The development can go both faster and slower than expected.

# Benchmarks
The [experiment](./experiment/) directory contains the source code of benchmarks and experiments discussed in the research reports.
