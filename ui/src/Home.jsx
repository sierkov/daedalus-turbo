import React, { useEffect, useState } from 'react';
import Dashboard from './Dashboard.jsx';
import Error from './Error.jsx';
import SyncScreen from './Sync/Screen.jsx';
import Transition from './Transition.jsx';

export default function Home({ confirmed }) {
    const [statusInfo, setStatusInfo] = useState({ ready: false, progress: {} });
    const [trackStatus, setTrackStatus] = useState(true);
    let updateInterval, cachedNow;
    const updateStatus = async (now) => {
        if (cachedNow !== now) {
            cachedNow = now;
            try {
                const s = await appAPI.status(now);
                setStatusInfo(s);
                if (s.ready)
                    setTrackStatus(false);
            } catch (err) {
                console.error('API error:', err);
                clearInterval(updateInterval);
                updateInterval = undefined;
                setStatusInfo({
                    apiError: 'The internal API server is not accessible. Please, start it first!'
                });
            }
        }
    };
    useEffect(() => {
        console.log('trackStatus:', trackStatus, 'updateInterval:', updateInterval);
        if (trackStatus && !updateInterval) {
            updateInterval = setInterval(() => updateStatus(Date.now()), 200);
        }
        return () => {
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = undefined;
            }
        }
    }, [trackStatus]);
    const [readyConfirmed, setReadyConfirmed] = useState(confirmed);
    let homeComponent;
    if (statusInfo?.apiError?.length > 0) {
        const issues = [
            { description: statusInfo.apiError, canProceed: false }
        ];
        homeComponent = <Error issues={issues} />;
    } else if (statusInfo?.requirements?.issues?.length > 0) {
        homeComponent = <Error issues={statusInfo?.requirements?.issues} />;
    } else if (statusInfo?.error?.length > 0) {
        const issues = [
            { description: `We are sorry, but the synchronization has failed: ${statusInfo.error}.`, canProceed: false }
        ];
        homeComponent = <Error issues={issues} />;
    } else if (statusInfo?.ready && readyConfirmed) {
        homeComponent = <Dashboard />;
    } else if (statusInfo?.ready !== undefined) {
        homeComponent = <SyncScreen
            status={statusInfo}
            confirmReady={() => setReadyConfirmed(true)}
            trackStatus={() => setTrackStatus(true) }
        />;
    } else {
        return <Transition message="Fetching the updated status, this should be done in a second ..." />;
    }
    return homeComponent;
}