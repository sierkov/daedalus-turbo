
const fs = require('fs');
const { spawn } = require('child_process');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function shellCmd(cmd, args, handler=undefined) {
    return new Promise((resolve, reject) => {
        let stdout = '', stderr = '';
        const child = spawn(cmd, args);
        child.stdin.setEncoding('utf8');
        child.stdout.setEncoding('utf8');
        child.stdout.on('data', (data) => {
            stdout += data;
            if (handler?.stdout) handler.stdout(child, data);
        });
        child.stderr.setEncoding('utf8');
        child.stderr.on('data', (data) => {
            stderr += data;
            if (handler?.stderr) handler.stderr(child, data);
        });
        child.on('error', err => {
            reject(`command ${cmd} ${args} failed with error: ${err}`);
        });
        child.on('close', code => {
            if (handler?.code) {
                handler.code(child, code);
            } else {
                if (code !== 0) throw Error(`command ${cmd} ${args} terminated with a non-zero status: ${code} stdout: ${stdout}, stderr: ${stderr}`);
            }
            resolve({
                status: code,
                stdout,
                stderr
            });
        });
        
    });
}

async function createWallet(keyphrase) {
    let actIdx = 0;
    let stderrLine = '';
    const res = await shellCmd(
        'docker-compose',
        ['exec', '-T', 'cardano-wallet', 'cardano-wallet', 'wallet', 'create', 'from-recovery-phrase', 'test'],
        {
            'stderr': (child, data) => {
                const promptSep = ': ';
                for (;;) {
                    const promptIdx = data.indexOf(promptSep);
                    if (promptIdx === -1) {
                        stderrLine += data;
                        return;
                    }
                    const line = stderrLine + data.slice(0, promptIdx);
                    stderrLine = '';
                    data = data.slice(promptIdx + promptSep.length);
                    switch (actIdx++) {
                        case 0:
                            child.stdin.write(`${keyphrase}\n`);
                            break;
                        case 1:
                            child.stdin.write(`\n`);
                            break;
                        case 2:
                        case 3:
                            child.stdin.write(`donotaskme\n`);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    );
}

async function syncStatus() {
    const res = await shellCmd('docker-compose', ['exec', '-T', 'cardano-node', 'cardano-cli', 'query', 'tip', '--mainnet', '--socket-path', '/ipc/node.socket']);
    return JSON.parse(res.stdout.toString());
}

const main = async () => {
    const startTime = Date.now();
    let status;
    for (;;) {
        status = await syncStatus();
        console.log('timestamp:', new Date().toISOString(), JSON.stringify(status), 'waiting:', (Date.now() - startTime) / 1000, 'secs');
        if (status.slot >= 115948800) break;
        await sleep(1000);
    }
    const endTime = Date.now();
    console.log('timestamp:', new Date().toISOString(), status);
    console.log('cardano node synced in:', (endTime - startTime) / 1000, 'secs');
};

(async () => {
    await main();
})();
