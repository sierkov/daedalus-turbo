import React from "react";

export default function SyncTip({ status }) {
    if (status?.lastBlock) {
        return <div className="row">
            <div className="col">
                <h3 className="highlight-text">{status.lastBlock?.timestamp}</h3>
                <p className="note">the generation time of the last synchronized block</p>
            </div>
        </div>
    }
    return <div className="row">
        <div className="col">
            <h3 className="default-text">The local chain is empty</h3>
            <p className="note">please synchronize the local chain</p>
        </div>
    </div>
}
