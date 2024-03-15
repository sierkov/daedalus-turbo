import React from 'react';
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import { bech32 } from 'bech32';
import NavBar from './NavBar.jsx';
import Address from './Address.jsx';
import './Bech32.scss';

function toHex(bytes) {
    return bytes.map(x => x.toString(16).padStart(2, '0')).join('');
}

function extractHash(bytes, startIdx, endIdx) {
    if (bytes?.length < endIdx)
        throw Error(`address too short: expected ${endIdx} bytes but got ${bytes?.length}`);
    return toHex(bytes.slice(startIdx, endIdx));
}

function parseAddress(bytes) {
    const res = { type: (bytes[0] >> 4) & 0xF, bytes };
    switch (res.type) {
        case 0b0000: // base address: keyhash28,keyhash28
            res.payId = { hash: extractHash(bytes, 1, 29) };
            res.stakeId = { hash: extractHash(bytes, 29, 57) };
            break;
        case 0b0001: // base address: scripthash28,keyhash28
            res.payId = { hash: extractHash(bytes, 1, 29), script: true };
            res.stakeId = { hash: extractHash(bytes, 29, 57) };
            break;
        case 0b0010: // base address: keyhash28,scripthash28
            res.payId = { hash: extractHash(bytes, 1, 29) };
            res.stakeId = { hash: extractHash(bytes, 29, 57), script: true };
            break;
        case 0b0011: // base address: scripthash28,scripthash28
            res.payId = { hash: extractHash(bytes, 1, 29), script: true };
            res.stakeId = { hash: extractHash(bytes, 29, 57), script: true };
            break;
        case 0b0100: // pointer key
            res.payId = { hash: extractHash(bytes, 1, 29) };
            // ignore the stake pointer component for now
            break;
        case 0b0101: // pointer script
            res.payId = { hash: extractHash(bytes, 1, 29), script: true };
            // ignore the stake pointer component for now
            break;
        case 0b0110: // enterprise key
            res.payId = { hash: extractHash(bytes, 1, 29) };
            break;
        case 0b0111: // enterprise script
            res.payId = { hash: extractHash(bytes, 1, 29), script: true };
            break;
        case 0b1110: // reward key
            res.stakeId = { hash: extractHash(bytes, 1, 29) };
            break;
        case 0b1111: // reward script
            res.stakeId = { hash: extractHash(bytes, 1, 29), script: true };
            break;
    }
    return res;
}

function parseBech32(bech32Data) {
    const info = bech32.decode(bech32Data, 128);
    const bytes = bech32.fromWords(info?.words);
    if (bytes?.length > 0 && (info?.prefix === "stake" || info?.prefix === "addr"))
        return parseAddress(bytes);
    throw Error(`unsupported BECH32 prefix: ${info?.prefix}! Only 'stake' and 'addr' are currently supported.`);
}

export default function Bech32 () {
    const params = useParams();
    const bech32Data = params.bech32;
    let error, addr;
    try {
        addr = parseBech32(bech32Data);
    } catch (err) {
        error = `Error parsing ${bech32Data}: ${err}`;
    }
    if (addr && !addr.stakeId && !addr.payId)
        error = `The provided address has neither a payment key nor stake key component: ${bech32Data}!`;
    if (error)
        return <div className="content">
            <NavBar style={{marginBottom: '64px' }}  />
            <p style={{marginTop: '64px' }}>{error}</p>
        </div>;
    if (addr.payId && !addr.stakeId)
        return <Navigate to={'/pay/' + toHex(addr.bytes)} replace={true} />;
    if (addr.stakeId && !addr.payId)
        return <Navigate to={'/stake/' + toHex(addr.bytes)} replace={true} />;
    return <div className="content">
        <NavBar />
        <div style={{marginTop: '64px'}}>
            <p style={{color: '#b2b2b2'}}>
                {bech32Data}
                <br/>
                has both payment and stake components. Please, select the one to explore.
            </p>
            <Address data={toHex(addr.bytes)} stakeId={addr.stakeId} payId={addr.payId}/>
        </div>
    </div>;
}