const fs = require('fs');

function testPublisherState(dataDir) {
    const state = JSON.parse(fs.readFileSync(`${dataDir}/chain.json`));
    let ok = 0;
    let err = 0;
    let epoch = 0;
    for (const epochMeta of state.epochs) {
        const epochData = JSON.parse(fs.readFileSync(`${dataDir}/epoch-${epoch}-${epochMeta.lastBlockHash}.json`));
        for (const chunk of epochData.chunks) {
            const chunkPath = `${dataDir}/compressed/chunk/${chunk.hash}.zstd`;
            if (!fs.existsSync(chunkPath)) {
                console.error('Missing chunk:', chunkPath);
                ++err;
            } else {
                ++ok;
            }
        }
        ++epoch;
    }
    console.log(`Analyzed epochs: ${epoch} chunks present: ${ok} missing: ${err}`);
}

function testOlderMetadata(dataDir) {
    let ok = 0;
    let err = 0;
    let numFiles = 0;
    for (const file of fs.readdirSync(dataDir)) {
        if (!file.startsWith('epoch-') || !file.endsWith('.json') )
            continue;
        ++numFiles;
        const epoch = JSON.parse(fs.readFileSync(`${dataDir}/${file}`));
        for (const chunk of epoch.chunks) {
            const chunkPath = `${dataDir}/compressed/chunk/${chunk.hash}.zstd`;
            if (!fs.existsSync(chunkPath)) {
                console.error('Missing chunk:', chunkPath);
                ++err;
            } else {
                ++ok;
            }
        }
    }
    console.log(`Analyzed old metadata files: ${numFiles} chunks present: ${ok} missing: ${err}`);
}

if (process.argv.length < 3) {
    console.error('Usage: node test-chunks.js <data-dir>');
    process.exit(1);
}
const dataDir = process.argv[2];
testOlderMetadata(dataDir);
testPublisherState(dataDir);
