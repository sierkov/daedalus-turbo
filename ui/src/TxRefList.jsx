import React from 'react';
import Button from '@mui/material/Button';
import TxRef from './TxRef.jsx';
import './TxRefList.scss';
import './TxRef.scss';

export default function TxRefList({ transactions, count, offset, limit, changeOffset }) {
    const txRefItems = transactions?.map(tx => <TxRef key={tx.hash} {...tx} />);
    return <div className="tx-ref-list">
        <h3>Transactions: {offset + 1} ... {offset + transactions.length}</h3>
        <div className="tx-ref">
            <div className="txo header">Transaction hash</div>
            <div className="timestamp">Timestamp</div>
            <div className="rel-stake">Confirming stake</div>
            <div className="balance">Balance change</div>
        </div>
        {txRefItems}
        <Button sx={{marginRight: '8px' }} variant="contained" color="primary" onClick={() => changeOffset(Math.max(offset - limit, 0))} disabled={offset === 0}>Prev {limit}</Button>
        <Button variant="contained" color="primary" onClick={() => changeOffset(offset + limit)} disabled={offset + limit >= count}>Next {limit}</Button>
    </div>;
}