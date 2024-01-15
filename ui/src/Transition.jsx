import React, { useState, useEffect } from 'react';
import CircularProgress from '@mui/material/CircularProgress';
import Progress from './Progress.jsx';
import './Transition.scss';

export default function Transition({ message }) {
    if (!message)
        message = 'Please wait, processing the data ...';
    const [progress, setProgress] = useState({});
    let updateInterval, cachedNow;
    const updateStatus = async (now) => {
        if (cachedNow !== now) {
            cachedNow = now;
            try {
                const s = await appAPI.status(now);
                const p = s?.progress ?? {};
                if (Object.keys(p).length === 0) {
                    clearInterval(updateInterval);
                    updateInterval = undefined;
                }
                setProgress(p);
            } catch (err) {
                console.error('API error:', err);
                clearInterval(updateInterval);
                updateInterval = undefined;
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
            <Progress progress={progress} names={Object.keys(progress)} />
        </div>;
    } else {
        return <div className="transition">
            <div>
                <CircularProgress />
            </div>
            <p className="explain">
                {message}
            </p>
        </div>;
    }   
}