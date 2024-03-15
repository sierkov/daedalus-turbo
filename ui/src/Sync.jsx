import React from 'react';
import Progress from './Progress.jsx';
import './Sync.scss';

export default function Sync({ progress, hardware, duration, eta }) {
    return <div className="sync">
        <div>
            <img className="logo-large" src="static/logo.svg" />
        </div>
        <h1>Synchronization progress</h1>
        <Progress progress={progress} names={[ 'download', 'parse', 'merge', 'validate' ]}
            hardware={hardware}  duration={duration} eta={eta} />
    </div>;
}