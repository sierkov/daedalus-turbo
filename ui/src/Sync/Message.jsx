import React from "react";
import './Message.scss';

export default function SyncMessage({ status }) {
    if (status?.syncError) {
        return <div className="row message error-text">
            <div className="col">
                <h4>Synchronization failed: {status?.syncError}</h4>
            </div>
        </div>
    }
    if (status?.syncType !== "none" && status?.syncDataMB && status?.syncDuration) {
        return <div className="row message">
            <div className="col">
                <h4>Synchronized {status?.syncDataMB} MB in {status?.syncDuration} min.</h4>
            </div>
        </div>
    }
    return <></>
}
