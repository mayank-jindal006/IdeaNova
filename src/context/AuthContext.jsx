import React, { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Load user session on startup
  useEffect(() => {
    const savedUser = localStorage.getItem('ideanova_session');
    if (savedUser) {
      try {
        setUser(JSON.parse(savedUser));
      } catch (e) {
        localStorage.removeItem('ideanova_session');
      }
    }
    setLoading(false);
  }, []);

  const login = (username, password, selectedRole) => {
    // Basic mock authentication: any non-empty username/password is accepted.
    // Roles can be Developer, Security Engineer, CISO
    if (!username.trim() || !password.trim()) {
      return { success: false, message: 'Username and password are required.' };
    }

    const mockUser = {
      username: username.trim(),
      role: selectedRole || 'Developer',
      avatarLetter: username.trim().charAt(0).toUpperCase()
    };

    setUser(mockUser);
    localStorage.setItem('ideanova_session', JSON.stringify(mockUser));
    return { success: true };
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('ideanova_session');
  };

  const switchRole = (newRole) => {
    if (!user) return;
    const updatedUser = { ...user, role: newRole };
    setUser(updatedUser);
    localStorage.setItem('ideanova_session', JSON.stringify(updatedUser));
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, switchRole, loading }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
