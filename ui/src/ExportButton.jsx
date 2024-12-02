import Button from "@mui/material/Button";
import SaveAltIcon from "@mui/icons-material/SaveAlt";
import React from "react";
import { useNavigate } from "react-router-dom";

export default function ExportButton({ status }) {
    const navigate = useNavigate();
    const doExport = async () => {
        const selectRes = await appAPI.selectDir();
        console.log('selectRes:', selectRes);
        if (!selectRes?.canceled && Array.isArray(selectRes?.filePaths) && selectRes?.filePaths.length)
            navigate('/export/' + encodeURIComponent(selectRes.filePaths[0]));
    };
    return <div className="row secondary">
        <Button className="search-button" startIcon={<SaveAltIcon/>}
                variant="contained" color="secondary" size="large" onClick={doExport}
                disabled={!status?.exportable}>Export State to Daedalus
        </Button>
    </div>;
}
