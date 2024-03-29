import React from 'react';
import bs58 from 'bs58';
import CBOR from 'cbor-sync';
import { Crc32 } from '@aws-crypto/crc32';
import './Address.scss';

function hexOrThrow(hex) {
    if (!(hex?.length > 0)) throw Error(`hex string cannot be empty: ${hex}`);
    if (hex.length % 2 !== 0) throw Error(`hex string must have an even number of characters but has ${hex.length}: ${hex}`);
    const isHex = !!hex?.match(/^[A-F0-9]+$/i);
    if (!isHex) throw Error(`hex string must contain only A-F or 0-9 characters but has: ${hex}`);
}

function hexToBytes(hex) {
    hexOrThrow(hex);
    var bytes = new Uint8Array(hex.length / 2);
    for (var c = 0; c < hex.length; c += 2) {
      bytes[c / 2] = parseInt(hex.substr(c, 2), 16);
    }
    return bytes;
}

export default function Address(addr) {
    let stakeLink, payLink, byronLink, pointerLink;
    if (addr.stakeId) {
        const stakeSuffix = addr.stakeId?.script ? '/script' : '';
        stakeLink = <div>stake key: <a href={'#/stake/' + addr.data}>{addr.stakeId?.hash}{stakeSuffix}</a></div>;
    }
    if (addr.payId) {
        let paySuffix = '';
        if (addr.payId.type === "shelley-script") paySuffix = '/script';
        else if (addr.payId.type === "byron") paySuffix = '/byron';
        payLink = <div>payment key: <a href={'#/pay/' + addr.data}>{addr.payId?.hash}{paySuffix}</a></div>;
    }
    if (addr.stakePointer) {
        pointerLink = <div>stake pointer: (slot: {addr.stakePointer?.slot} tx #: {addr.stakePointer?.txIdx} cert #: {addr.stakePointer?.certIdx})</div>;
    }
    if (addr.type === 'byron') {
        const binData = hexToBytes(addr.data);
        let base58;
        if (binData.length < 256) {
            const crc = (new Crc32).update(binData).digest();
            let packed = '82D81858' + binData.length.toString(16) + addr.data + CBOR.encode(crc, 'hex');
            base58 = bs58.encode(hexToBytes(packed));
        } else {
            base58 = 'unsupported byron address - too long';
        }
        byronLink = <div title={base58}>{base58}</div>;
    }
    return <div className="address">
        {payLink}
        {stakeLink}
        {pointerLink}
        {byronLink}
    </div>;
}