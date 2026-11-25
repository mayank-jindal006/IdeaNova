import { useContext } from 'react';
import { RepoGuardContext } from './repoGuardContextValue';

export const useRepoGuard = () => {
  const context = useContext(RepoGuardContext);

  if (!context) {
    throw new Error('useRepoGuard must be used within a RepoGuardProvider');
  }

  return context;
};
