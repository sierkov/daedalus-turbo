import React, { useState, useEffect } from 'react';
import Progress from '../Progress.jsx';
import SyncPaperLink from './PaperLink.jsx';
import './ScreenProgress.scss';

function addWeight(weights, item_name, item_weight)
{
    let sum = 0.0;
    weights[item_name] = item_weight
    for (let [k, v] of Object.entries(weights)) {
        sum += v;
    }
    const correction = 1.0 / sum;
    for (let [k, v] of Object.entries(weights)) {
        weights[k] = v * correction;
    }
}

function computeETA(progress, weights, duration, prevETA) {
    let wsum = 0.0;
    for (let [k, w] of Object.entries(weights)) {
        if (progress[k])
            wsum += w * parseFloat(progress[k].substring(0, progress[k].length - 1)) / 100;
    }
    let newETA;
    if (duration >= 1.0 && wsum >= 0.01)
        newETA = Math.round(duration / wsum * (1.0 - wsum) * 10) / 10;
    // Smooth drastic changes in the predicted ETA
    if (prevETA !== undefined && newETA !== undefined)
        return Math.round((prevETA * 0.9 + newETA * 0.1) * 10) / 10;
    return newETA;
}

export default function SyncScreenProgress({ status }) {
    const [prevETA, setPrevETA] = useState(undefined);
    const [syncETA, setSyncETA] = useState(undefined);
    useEffect(() => {
        const prev = prevETA;
        setPrevETA(syncETA);
        setSyncETA(computeETA(status?.progress, weights, status?.syncDuration, prev));
    }, [status]);
    let slotRange;
    if (status?.syncStartSlot && status?.syncTargetSlot)
        slotRange = {start: status?.syncStartSlot, target: status?.syncTargetSlot};
    let weights = { download: 0.20, parse: 0.35, merge: 0.05, validate: 0.40};
    if (status?.syncType === "p2p")
        weights = { download: 0.30, parse: 0.30, merge: 0.05, validate: 0.35 }
    if (status?.validationMode === "turbo")
        addWeight(weights, "txwit", 0.05);
    else
        addWeight(weights, "txwit", 1.00);
    return <div className="sync screen">
        <div className="col">
            <div className="row">
                <div>
                    <img className="logo-large" src="static/logo.svg"/>
                </div>
            </div>
            <h1>Synchronizing with a {status?.syncType} node</h1>
            <Progress progress={status?.progress} names={['download', 'parse', 'merge', 'validate', 'txwit']}
                  weights={weights}
                  titles={{
                      'download': 'download',
                      'parse': 'parse',
                      'merge': 'merge',
                      'validate': 'consensus',
                      'txwit': 'witnesses: ' + status?.validationMode
                  }}
                  hardware={status?.hardware}
                  duration={status?.syncDuration}
                  eta={syncETA}
                  slotRange={slotRange}
            />
            <SyncPaperLink />
        </div>
    </div>
}
