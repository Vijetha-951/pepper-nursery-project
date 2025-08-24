import { useEffect, useState } from 'react';
import authService from '../services/authService';

const ProtectedRoute = ({ children, requireAuth = true, redirectTo = '/login' }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkAuth = () => {
      const user = authService.getCurrentUser();
      const token = authService.getToken();
      
      setIsAuthenticated(!!(user && token));
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  if (isLoading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        background: '#f9fafb'
      }}>
        <div style={{
          width: '3rem',
          height: '3rem',
          border: '4px solid #10b981',
          borderTop: '4px solid transparent',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite'
        }}></div>
        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  // If route requires authentication but user is not authenticated
  if (requireAuth && !isAuthenticated) {
    window.location.href = redirectTo;
    return null;
  }

  // If route requires no authentication but user is authenticated (like login/register pages)
  if (!requireAuth && isAuthenticated) {
    window.location.href = '/dashboard';
    return null;
  }

  return children;
};

export default ProtectedRoute;