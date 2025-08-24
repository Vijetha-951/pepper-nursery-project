import { useEffect, useState } from "react";
import { CheckCircle, AlertCircle, Loader } from "lucide-react";
import authService from "../services/authService";

export default function AuthCallback() {
  const [status, setStatus] = useState('processing'); // 'processing', 'success', 'error'
  const [message, setMessage] = useState('Processing your authentication...');

  useEffect(() => {
    const handleAuthCallback = async () => {
      try {
        // Get the authorization code from URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const error = urlParams.get('error');

        if (error) {
          setStatus('error');
          setMessage('Authentication was cancelled or failed. Please try again.');
          setTimeout(() => {
            window.location.href = '/login';
          }, 3000);
          return;
        }

        if (!code) {
          setStatus('error');
          setMessage('No authorization code received. Please try again.');
          setTimeout(() => {
            window.location.href = '/login';
          }, 3000);
          return;
        }

        // Send the code to your backend for processing
        const result = await authService.handleGoogleCallback(code);

        if (result.success) {
          setStatus('success');
          setMessage('Authentication successful! Redirecting...');
          
          // Check if user needs to complete profile
          const user = result.user;
          if (user.isNewUser) {
            setTimeout(() => {
              window.location.href = '/complete-profile';
            }, 2000);
          } else {
            setTimeout(() => {
              window.location.href = '/dashboard';
            }, 2000);
          }
        } else {
          setStatus('error');
          setMessage(result.error || 'Authentication failed. Please try again.');
          setTimeout(() => {
            window.location.href = '/login';
          }, 3000);
        }
      } catch (error) {
        console.error('Auth callback error:', error);
        setStatus('error');
        setMessage('An unexpected error occurred. Please try again.');
        setTimeout(() => {
          window.location.href = '/login';
        }, 3000);
      }
    };

    handleAuthCallback();
  }, []);

  const containerStyle = {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'linear-gradient(135deg, #f0fdf4, #ecfdf5)',
    padding: '2rem'
  };

  const cardStyle = {
    background: 'white',
    borderRadius: '16px',
    padding: '3rem',
    boxShadow: '0 20px 40px rgba(0, 0, 0, 0.1)',
    textAlign: 'center',
    maxWidth: '400px',
    width: '100%'
  };

  const iconContainerStyle = {
    width: '4rem',
    height: '4rem',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 1.5rem',
    boxShadow: '0 8px 20px rgba(0, 0, 0, 0.15)'
  };

  const titleStyle = {
    fontSize: '1.5rem',
    fontWeight: 'bold',
    marginBottom: '1rem',
    color: '#1f2937'
  };

  const messageStyle = {
    color: '#6b7280',
    fontSize: '1rem',
    lineHeight: '1.6',
    marginBottom: '1.5rem'
  };

  const renderIcon = () => {
    switch (status) {
      case 'processing':
        return (
          <div style={{
            ...iconContainerStyle,
            background: 'linear-gradient(135deg, #10b981, #059669)'
          }}>
            <div style={{
              width: '2rem',
              height: '2rem',
              border: '3px solid white',
              borderTop: '3px solid transparent',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite'
            }}></div>
          </div>
        );
      case 'success':
        return (
          <div style={{
            ...iconContainerStyle,
            background: 'linear-gradient(135deg, #10b981, #059669)'
          }}>
            <CheckCircle color="white" size={32} />
          </div>
        );
      case 'error':
        return (
          <div style={{
            ...iconContainerStyle,
            background: 'linear-gradient(135deg, #ef4444, #dc2626)'
          }}>
            <AlertCircle color="white" size={32} />
          </div>
        );
      default:
        return null;
    }
  };

  const getTitle = () => {
    switch (status) {
      case 'processing':
        return 'Authenticating...';
      case 'success':
        return 'Success!';
      case 'error':
        return 'Authentication Failed';
      default:
        return 'Processing...';
    }
  };

  const getProgressBar = () => {
    if (status !== 'processing') return null;

    return (
      <div style={{
        width: '100%',
        height: '4px',
        background: '#e5e7eb',
        borderRadius: '2px',
        overflow: 'hidden',
        marginBottom: '1rem'
      }}>
        <div style={{
          width: '100%',
          height: '100%',
          background: 'linear-gradient(90deg, #10b981, #059669)',
          borderRadius: '2px',
          animation: 'progress 2s ease-in-out infinite'
        }}></div>
      </div>
    );
  };

  return (
    <div style={containerStyle}>
      <div style={cardStyle}>
        {renderIcon()}
        <h1 style={titleStyle}>{getTitle()}</h1>
        <p style={messageStyle}>{message}</p>
        {getProgressBar()}
        
        {status === 'processing' && (
          <div style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: '0.5rem',
            color: '#10b981',
            fontSize: '0.875rem',
            fontWeight: '500'
          }}>
            <Loader size={16} />
            Please wait...
          </div>
        )}

        {status === 'error' && (
          <div style={{
            background: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '8px',
            padding: '0.75rem',
            color: '#dc2626',
            fontSize: '0.875rem',
            marginTop: '1rem'
          }}>
            You will be redirected to login page shortly.
          </div>
        )}

        {status === 'success' && (
          <div style={{
            background: '#f0fdf4',
            border: '1px solid #bbf7d0',
            borderRadius: '8px',
            padding: '0.75rem',
            color: '#166534',
            fontSize: '0.875rem',
            marginTop: '1rem'
          }}>
            Redirecting to your dashboard...
          </div>
        )}
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        
        @keyframes progress {
          0% { transform: translateX(-100%); }
          50% { transform: translateX(0%); }
          100% { transform: translateX(100%); }
        }
      `}</style>
    </div>
  );
}