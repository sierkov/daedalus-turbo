import React from 'react';
import ReactDOM from 'react-dom/client';
import { createHashRouter, RouterProvider } from 'react-router-dom';
import App from './App.jsx';
import Bech32 from './Bech32.jsx';
import Export from './Export.jsx';
import Home from './Home.jsx';
import Pay from './Pay.jsx';
import Stake from './Stake.jsx';
import Tx from './Tx.jsx';

const router = createHashRouter([
    {
        element: <App />,
        children: [
            { path: '/', element: <Home /> },
            { path: '/bech32/:bech32', element: <Bech32 /> },
            { path: '/export/:path', element: <Export /> },
            { path: '/pay/:hash', element: <Pay /> },
            { path: '/stake/:hash', element: <Stake /> },
            { path: '/tx/:hash', element: <Tx /> }
        ]
    },
]);
ReactDOM.createRoot(document.getElementById("root")).render(
    <React.StrictMode>
        <RouterProvider router={router}/>
    </React.StrictMode>
);
