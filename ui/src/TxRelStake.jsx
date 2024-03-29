import React from "react";
import './TxRelStake.scss';

export default function TxRelStake({relStake}) {
    if (relStake === undefined)
        relStake = 0.0;
    if (relStake < 0.10)
        return <div className="tx-rel-stake risk" title={Math.round(10000 * relStake) / 100 + '%'}>
            &lt;10%
        </div>;
    if (relStake > 0.50)
        return <div className="tx-rel-stake good">
            &gt;50%
        </div>;
    return <div className="tx-rel-stake fair" title={Math.round(10000 * relStake) / 100 + '%'}>
        {Math.floor(relStake * 100)}%
    </div>;
}