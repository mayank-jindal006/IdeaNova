import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Repositories from './pages/Repositories';
import RepositoryDetail from './pages/RepositoryDetail';
import ScanProgress from './pages/ScanProgress';
import FindingDetail from './pages/FindingDetail';
import FixReview from './pages/FixReview';
import NotFound from './pages/NotFound';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          
          {/* Repositories */}
          <Route path="repositories" element={<Repositories />} />
          <Route path="repos" element={<Repositories />} />
          <Route path="repositories/:repoId" element={<RepositoryDetail />} />
          <Route path="repos/:repoId" element={<RepositoryDetail />} />
          <Route path="repositories/:repoId/scan" element={<ScanProgress />} />
          <Route path="repos/:repoId/scan" element={<ScanProgress />} />

          {/* Findings & Remediation */}
          <Route path="findings/:findingId" element={<FindingDetail />} />
          <Route path="findings/:findingId/fix" element={<FixReview />} />

          {/* Fallbacks */}
          <Route path="login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
