import React, { useState, useEffect } from 'react';
import CircularProgress from '@mui/material/CircularProgress';
import Progress from './Progress.jsx';
import TransitionSimple from './TransitionSimple.jsx';
import './Transition.scss';

export default function Transition({ message, progressWeights }) {
    const [progress, setProgress] = useState({});
    let updateInterval, cachedNow;
    const updateStatus = async (now) => {
        if (cachedNow !== now) {
            cachedNow = now;
            try {
                const s = await appAPI.status(now);
                const p = s?.progress ?? {};
                setProgress(p);
            } catch (err) {
                console.error('API error:', err);
                setProgress({});
            }
        }
    };
    useEffect(() => {
        updateInterval = setInterval(() => updateStatus(Date.now()), 100);
        return () => {
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = undefined;
            }
        }
    }, []);
    if (Object.keys(progress).length > 0) {
        return <div className="transition">
            <h1>Operation in progress</h1>
            <Progress progress={progress} names={Object.keys(progress)} weights={progressWeights} />
        </div>;
    }
    return <TransitionSimple message={message} />;
}