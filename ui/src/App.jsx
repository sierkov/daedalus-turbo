import React from 'react';
import { Outlet } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import './App.scss';

const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: '#F15D2A',
            contrastText: '#fff'
        }
    }
});

export default function App() {
    return <ThemeProvider theme={theme}>
        <div className="background">
            <Outlet />
        </div>
    </ThemeProvider>;
}