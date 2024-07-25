import React from 'react';
import Progress from './Progress.jsx';
import './Sync.scss';

export default function Sync({ progress, hardware, duration, eta, slotRange }) {
    return <div className="sync">
        <div>
            <img className="logo-large" src="static/logo.svg" />
        </div>
        <h1>Synchronization progress</h1>
        <Progress progress={progress} names={[ 'download', 'parse', 'merge', 'validate', 'verify' ]}
            weights={ { 'download': 0.2, 'parse': 0.35, 'merge': 0.05, 'validate': 0.35, 'verify': 0.05 } }
            titles={ { 'download': 'download', 'parse': 'parse', 'merge': 'merge', 'validate': 'validate', 'verify': 'P2P verify' } }
            hardware={hardware}  duration={duration} eta={eta} slotRange={slotRange} />
    </div>;
}