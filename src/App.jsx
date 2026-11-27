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
import ActivityLog from './pages/ActivityLog';
import NotFound from './pages/NotFound';
import Commerce from './pages/Commerce';
import Login from './pages/Login';
import { useRepoGuard } from './context/useRepoGuard';

function ProtectedApp() {
  const { user, authLoading } = useRepoGuard();
  if (authLoading) return <div className="page-content-padded">Checking session…</div>;
  if (!user) return <Login />;
  return <Routes>
    <Route path="/" element={<Layout />}>
      <Route index element={<Dashboard />} /><Route path="repositories" element={<Repositories />} /><Route path="repositories/:repoId" element={<RepositoryDetail />} /><Route path="repositories/:repoId/scan" element={<ScanProgress />} /><Route path="findings/:findingId" element={<FindingDetail />} /><Route path="findings/:findingId/fix" element={<FixReview />} /><Route path="activity" element={<ActivityLog />} /><Route path="catalog" element={<Commerce />} /><Route path="*" element={<NotFound />} />
    </Route>
  </Routes>;
}

function App() {
  return (
    <BrowserRouter>
      <RepoGuardProvider>
        <ProtectedApp />
      </RepoGuardProvider>
    </BrowserRouter>
  );
}

export default App;
