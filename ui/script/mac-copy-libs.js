const fs = require('fs/promises');
const path = require('node:path');
const { spawn } = require('child_process');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function shellCmd(cmd, args) {
    return new Promise((resolve, reject) => {
        let stdout = '', stderr = '';
        console.log(cmd, args.join(' '));
        const child = spawn(cmd, args);
        child.stdin.setEncoding('utf8');
        child.stdout.setEncoding('utf8');
        child.stdout.on('data', (data) => {
            stdout += data;
        });
        child.stderr.setEncoding('utf8');
        child.stderr.on('data', (data) => {
            stderr += data;
        });
        child.on('error', err => {
            reject(`command ${cmd} ${args} failed with error: ${err}`);
        });
        child.on('close', code => {
            if (code !== 0)
                reject(`command ${cmd} ${args} terminated with a non-zero status: ${code} stdout: ${stdout}, stderr: ${stderr}`);
            else
                resolve({
                    status: code,
                    stdout,
                    stderr
                });
        });
    });
}

const extractDeps = async (binPath) => {
    const res = await shellCmd('otool', [ '-L', binPath ]);
    const lines = res.stdout.split(/\r?\n/).map((l) => {
        if (l.startsWith('\t'))
            l = l.slice(1);
        const spcIdx = l.indexOf(' ');
        if (spcIdx !== -1)
            l = l.slice(0, spcIdx);
        return l;
    }).filter(l => l.length > 0);
    if (lines.length > 0 && lines[0].startsWith(binPath + ':'))
        lines.shift();
    const deps = new Map();
    for (const lib of lines) {
        if (lib.startsWith('@loader_path')) {
            deps.set(lib, path.dirname(binPath) + lib.slice('@loader_path'.length));
        } else if (lib.startsWith('/usr/lib/')) {
            continue;
        } else if (lib[0] === '/') {
            deps.set(lib, lib);
        } else {
            console.error("unexpected reference:", lib);
        }
    }
    return deps;
};

const copyDeps = async (binPath, depMap, dstDir) => {
    for (const [srcPath, deps] of depMap.entries()) {
        const filename = path.basename(srcPath);
        const dstPath = path.join(dstDir, filename);
        console.log('cp', srcPath, dstPath);
        await fs.cp(srcPath, dstPath, { force: true, dereference: true });
        for (const [lib, libPath] of deps.entries())
            await shellCmd('install_name_tool', [ '-change', lib, '@executable_path/' + path.basename(libPath), dstPath ]);
        if (srcPath !== binPath)
            await shellCmd('install_name_tool', [ '-id', '@executable_path/' + filename, dstPath ]);
        await shellCmd('codesign', [ '--force', '-s', '-', dstPath ]);
    }
};

const main = async () => {
    if (process.argv.length !== 4)
        throw Error(`Usage: node mac-copy-libs.js <binary> <dst-dir>`);
    const depMap = new Map();
    const binPath = process.argv[2];
    const dstDir = process.argv[3];
    const binDeps = await extractDeps(binPath);
    depMap.set(binPath, binDeps);
    for (const [lib, libPath] of binDeps.entries()) {
        const libDeps = await extractDeps(libPath);
        depMap.set(libPath, libDeps);
        for (const [depLib, depLibPath] of libDeps.entries()) {
            if (!depMap.has(depLibPath))
                depMap.set(depLibPath, await extractDeps(depLibPath));
        }
    }
    await copyDeps(binPath, depMap, dstDir);
};

(async () => {
    try {
        await main();
    } catch (ex) {
        console.error('MAIN ERROR:', ex);
        process.exit(1);
    }
})();