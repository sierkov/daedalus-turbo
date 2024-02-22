import React, { useEffect } from 'react';
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import { bech32 } from 'bech32';
import Button from '@mui/material/Button';
import NavBar from './NavBar.jsx';
import Transition from './Transition.jsx';
import './Bech32.scss';

function hasStakeId(type) {
    switch (type) {
        case 0b1110: // reward key
        case 0b1111: // reward script
        case 0b0000: // base address: keyhash28,keyhash28
        case 0b0001: // base address: scripthash28,keyhash28
        case 0b0010: // base address: keyhash28,scripthash28
        case 0b0011: // base address: scripthash28,scripthash28
            return true;

        default:
            return false;
    }
}

function hasPayId(type) {
    switch (type) {
        case 0b0110: // enterprise key
        case 0b0111: // enterprise script
        case 0b0000: // base address: keyhash28,keyhash28
        case 0b0001: // base address: scripthash28,keyhash28
        case 0b0010: // base address: keyhash28,scripthash28
        case 0b0011: // base address: scripthash28,scripthash28
        case 0b0100: // pointer key
        case 0b0101: // pointer script
            return true;

        default:
            return false;
    }
}

function toHex(bytes) {
    return bytes.map(x => x.toString(16).padStart(2, '0')).join('');
}

export default function Bech32 () {
    const params = useParams();
    const navigate = useNavigate();
    const stakeUrl = (bytes) => '/stake/' + toHex(bytes);
    const payUrl = (bytes) => '/pay/' + toHex(bytes);
    const bech32Data = params.bech32;
    let error, bytes, hasPay, hasStake;
    try {
        const info = bech32.decode(bech32Data, 128);
        bytes = bech32.fromWords(info.words);
        console.log('bech32:', info, 'bytes:', bytes);
        if (info?.prefix === 'stake') {
            if (bytes?.length !== 29) {
                error = 'invalid stake address: ' + bech32Data;
            } else {
                hasStake = true;
            }
        } else if (info?.prefix === 'addr') {
            if (bytes?.length < 29) {
                error = `BECH32 address is too short: ${bech32Data}`;
            } else {
                const type = (bytes[0] >> 4) & 0xF;
                hasPay = hasPayId(type);
                hasStake = hasStakeId(type);
            }
        } else {
            error = `unsupported BECH32 prefix: ${info?.prefix}! Only 'stake' and 'addr' are currently supported.`
        }
    } catch (err) {
        error = 'invalid BECH32 address: ' + bech32Data;
    }
    if (!hasStake && !hasPay)
        error = `The provided address has neither a payment key nor stake key component: ${bech32Data}!`;
    if (error) {
        return <div className="content">
            <NavBar />
            <p>{error}</p>
        </div>
    }
    if (hasPay && !hasStake) {
        return <Navigate to={payUrl(bytes)} replace={true} />;
    }
    if (hasStake && !hasPay) {
        return <Navigate to={stakeUrl(bytes)} replace={true} />;
    }
    return <div className="content">
        <NavBar />
        <p>{bech32Data}</p>
        <p>The provided address has both payment key and stake key components.</p>
        <p>Which one you'd like to explore:</p>
        <div className="buttons">
            <Button className="choice-button"
                    variant="contained" color="primary" size="large"
                    onClick={() => navigate(payUrl(bytes))}>Explore the payment key</Button>
            <Button className="choice-button"
                    variant="contained" color="primary" size="large"
                    onClick={() => navigate(stakeUrl(bytes))}>Explore the stake key</Button>
        </div>
    </div>;
}