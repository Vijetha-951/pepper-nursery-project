import { useState, useEffect } from 'react';
import { CheckCircle, AlertCircle, Settings } from 'lucide-react';
import { hasValidGoogleConfig, GOOGLE_CLIENT_ID } from '../config/googleConfig';

export default function GoogleOAuthStatus() {
  const [status, setStatus] = useState('loading');
  const [isExpanded, setIsExpanded] = useState(false);

  useEffect(() => {
    const checkStatus = () => {
      if (hasValidGoogleConfig()) {
        setStatus('configured');
      } else {
        setStatus('demo');
      }
    };

    // Check initially and after a small delay to allow for initialization
    checkStatus();
    setTimeout(checkStatus, 1000);
  }, []);

  const getStatusInfo = () => {
    switch (status) {
      case 'configured':
        return {
          icon: <CheckCircle size={20} color="#10b981" />,
          title: 'Google OAuth Configured',
          message: 'Real Google authentication is active',
          bgColor: '#f0fdf4',
          borderColor: '#bbf7d0',
          textColor: '#166534'
        };
      case 'demo':
        return {
          icon: <AlertCircle size={20} color="#f59e0b" />,
          title: 'Demo Mode Active',
          message: 'Using mock authentication - follow setup guide for real Google OAuth',
          bgColor: '#fffbeb',
          borderColor: '#fed7aa',
          textColor: '#92400e'
        };
      default:
        return {
          icon: <Settings size={20} color="#6b7280" />,
          title: 'Checking Configuration...',
          message: 'Loading Google OAuth status',
          bgColor: '#f9fafb',
          borderColor: '#d1d5db',
          textColor: '#374151'
        };
    }
  };

  const statusInfo = getStatusInfo();

  return (
    <div style={{
      position: 'fixed',
      bottom: '20px',
      right: '20px',
      zIndex: 1000,
      maxWidth: '300px'
    }}>
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        style={{
          background: statusInfo.bgColor,
          border: `1px solid ${statusInfo.borderColor}`,
          borderRadius: '8px',
          padding: '12px',
          cursor: 'pointer',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
          transition: 'all 0.3s ease'
        }}
      >
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          marginBottom: isExpanded ? '8px' : '0'
        }}>
          {statusInfo.icon}
          <span style={{
            fontSize: '14px',
            fontWeight: '500',
            color: statusInfo.textColor
          }}>
            {statusInfo.title}
          </span>
        </div>
        
        {isExpanded && (
          <div style={{ marginTop: '8px' }}>
            <p style={{
              fontSize: '12px',
              color: statusInfo.textColor,
              opacity: 0.8,
              margin: '0 0 8px 0',
              lineHeight: '1.4'
            }}>
              {statusInfo.message}
            </p>
            
            {status === 'demo' && (
              <div style={{
                background: 'rgba(0, 0, 0, 0.05)',
                borderRadius: '4px',
                padding: '8px',
                fontSize: '11px',
                color: statusInfo.textColor
              }}>
                <strong>To enable real Google OAuth:</strong>
                <ol style={{ margin: '4px 0 0 0', paddingLeft: '16px' }}>
                  <li>Read GOOGLE_OAUTH_SETUP.md</li>
                  <li>Create Google Console project</li>
                  <li>Get Client ID</li>
                  <li>Update .env file</li>
                  <li>Restart app</li>
                </ol>
              </div>
            )}
            
            {status === 'configured' && (
              <div style={{
                background: 'rgba(0, 0, 0, 0.05)',
                borderRadius: '4px',
                padding: '8px',
                fontSize: '11px',
                color: statusInfo.textColor
              }}>
                <strong>Client ID:</strong> {GOOGLE_CLIENT_ID?.substring(0, 20)}...
                <br />
                <strong>Status:</strong> Ready for Google Sign-In
              </div>
            )}
            
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsExpanded(false);
              }}
              style={{
                marginTop: '8px',
                padding: '4px 8px',
                fontSize: '10px',
                background: 'transparent',
                border: `1px solid ${statusInfo.borderColor}`,
                borderRadius: '4px',
                color: statusInfo.textColor,
                cursor: 'pointer'
              }}
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}