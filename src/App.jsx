import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { RepoGuardProvider } from './context/RepoGuardContext';
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
      <RepoGuardProvider>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="repositories" element={<Repositories />} />
            <Route path="repositories/:repoId" element={<RepositoryDetail />} />
            <Route path="repositories/:repoId/scan" element={<ScanProgress />} />
            <Route path="findings/:findingId" element={<FindingDetail />} />
            <Route path="findings/:findingId/fix" element={<FixReview />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </RepoGuardProvider>
    </BrowserRouter>
  );
}

export default App;
