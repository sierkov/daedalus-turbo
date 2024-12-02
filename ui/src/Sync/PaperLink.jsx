import React from 'react';
import './PaperLink.scss';

export default function SyncPaperLink() {
    return <div className="sync-paper-link">
        <p className="note">An overview of the synchronization method and its configurations is provided in the following paper:
            <br/>
            <span className="link" onClick={() => appAPI.paperLink()}>On the security of wallet nodes in the Cardano blockchain</span>.
        </p>
    </div>
}
