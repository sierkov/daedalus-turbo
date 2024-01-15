import React, { useEffect, useState } from 'react';
import Dashboard from './Dashboard.jsx';
import Error from './Error.jsx';
import Sync from './Sync.jsx';
import Transition from './Transition.jsx';

export default function Home() {
    const [statusInfo, setStatusInfo] = useState({ ready: false, progress: {} });
    let updateInterval, cachedNow;
    const updateStatus = async (now) => {
        if (cachedNow !== now) {
            cachedNow = now;
            try {
                const s = await appAPI.status(now);
                if (s.ready) {
                    clearInterval(updateInterval);
                    updateInterval = undefined;
                }
                setStatusInfo(s);
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
        updateInterval = setInterval(() => updateStatus(Date.now()), 100);
        return () => {
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = undefined;
            }
        }
    }, []);
    let homeComponent, forceContinue;
    if (statusInfo?.apiError?.length > 0) {
        const issues = [
            { description: statusInfo.apiError, canProceed: false }
        ];
        homeComponent = <Error issues={issues} />;
    } else if (statusInfo?.error?.length > 0) {
        const issues = [
            { description: `We are sorry, but the synchronization has failed: ${statusInfo.error}.`, canProceed: false }
        ];
        homeComponent = <Error issues={issues} />;
    } else if (statusInfo?.requirements?.issues?.length > 0 && !forceContinue) {
        homeComponent = <Error issues={statusInfo?.requirements?.issues} />;
    } else if (statusInfo?.ready) {
        homeComponent = <Dashboard />;
    } else if (statusInfo?.progress && Object.keys(statusInfo?.progress).length > 0) {
        homeComponent = <Sync progress={statusInfo.progress} />;
    } else {
        return <Transition message="Fetching the updated status, this should be done in a second ..." />;
    }
    return homeComponent;
}