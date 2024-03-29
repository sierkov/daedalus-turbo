import React from 'react';
import './TxRef.scss';
import TxRelStake from './TxRelStake.jsx';

function shortHash(hash, prefixLen, suffixLen)
{
    if (hash === undefined || !hash?.length)
        return 'undefined';
    if (hash?.length <= prefixLen + suffixLen + 2)
        return hash;
    return (hash.slice(0, prefixLen) + '\u2026' + hash.slice(hash.length - suffixLen, hash.length)).toLowerCase();
}

export function shortAssetChange(change)
{
    if (!change || !change?.length)
        return 'undefined';
    const policyIdx = change.lastIndexOf(' ');
    if (policyIdx === -1)
        return change;
    return change.slice(0, policyIdx) + ' ' + shortHash(change.slice(policyIdx + 1, change.length), 6, 4);
}

export default function TxRef(info) {
    let balanceChanges = info?.balanceChange.split('; ').filter(b => b?.length > 0).map(b => <p title={b}>{shortAssetChange(b)}</p>)
    return <div className="tx-ref">
        <div className="txo" title={info?.hash}><a href={'#/tx/' + info?.hash}>{shortHash(info?.hash, 10, 10)}</a></div>
        <div className="timestamp">{info?.slot?.timestamp}</div>
        <div className="rel-stake"><TxRelStake relStake={info?.relativeStake} /></div>
        <div className="balance">{balanceChanges}</div>
    </div>;
}