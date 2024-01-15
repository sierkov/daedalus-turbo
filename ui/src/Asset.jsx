import React from 'react';
import './Asset.scss';

export default function Asset({ id, amount }) {
    return <div className="asset">
        <div className="amount">{amount}</div>
        <div className="id" title={id}>{id}</div>
    </div>;
}