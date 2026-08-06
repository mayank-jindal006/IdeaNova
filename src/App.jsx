import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { SystemDataProvider } from './context/SystemDataContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Repositories from './pages/Repositories';
import ScaScan from './pages/ScaScan';
import Compliance from './pages/Compliance';
import Settings from './pages/Settings';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <SystemDataProvider>
          <Routes>
            {/* Public route */}
            <Route path="/login" element={<Login />} />
            
            {/* Protected dashboard routes */}
            <Route path="/" element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="repositories" element={<Repositories />} />
              <Route path="sca" element={<ScaScan />} />
              <Route path="compliance" element={<Compliance />} />
              <Route path="settings" element={<Settings />} />
            </Route>
          </Routes>
        </SystemDataProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
