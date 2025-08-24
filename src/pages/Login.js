import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Mail, Lock, Eye, EyeOff, ArrowLeft, LogIn } from "lucide-react";
import backgroundImage from "../assets/loginreg.jpeg";
import authService from "../services/authService";

export default function Login() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    email: "",
    password: ""
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [successMessage, setSuccessMessage] = useState("");

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    if (errors[e.target.name]) {
      setErrors({ ...errors, [e.target.name]: "" });
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.email) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Please enter a valid email";
    }
    
    if (!formData.password) {
      newErrors.password = "Password is required";
    } else if (formData.password.length < 6) {
      newErrors.password = "Password must be at least 6 characters";
    }
    
    return newErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = validateForm();
    
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    setIsLoading(true);
    setErrors({});
    setSuccessMessage("");
    
    try {
      const result = await authService.login(formData);
      
      if (result.success) {
        setSuccessMessage("Login successful! Redirecting...");
        setTimeout(() => {
          navigate('/dashboard');
        }, 1000);
      } else {
        setErrors({ general: result.error });
      }
    } catch (error) {
      console.error('Login error:', error);
      setErrors({ general: "An unexpected error occurred. Please try again." });
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setIsGoogleLoading(true);
    setErrors({});
    setSuccessMessage("");
    
    try {
      const result = await authService.googleSignIn();
      
      if (result.success) {
        setSuccessMessage("Google login successful! Redirecting...");
        
        // Check if user needs to complete profile
        if (result.user.isNewUser) {
          setTimeout(() => {
            navigate('/complete-profile');
          }, 1000);
        } else {
          setTimeout(() => {
            navigate('/dashboard');
          }, 1000);
        }
      } else {
        setErrors({ general: result.error });
      }
    } catch (error) {
      console.error('Google login error:', error);
      setErrors({ general: "Google login failed. Please try again." });
    } finally {
      setIsGoogleLoading(false);
    }
  };

  const containerStyle = {
    minHeight: '100vh',
    display: 'flex',
    position: 'relative',
    overflow: 'hidden'
  };

  const leftSideStyle = {
    flex: '1',
    background: `linear-gradient(45deg, rgba(0, 0, 0, 0.3), rgba(16, 185, 129, 0.2)), url(${backgroundImage})`,
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    backgroundRepeat: 'no-repeat',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexDirection: 'column',
    color: 'white',
    position: 'relative',
    padding: '2rem'
  };

  const rightSideStyle = {
    flex: '1',
    background: 'white',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '2rem',
    position: 'relative',
    overflowY: 'auto'
  };

  const overlayStyle = {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0, 0, 0, 0.2)',
    backdropFilter: 'blur(0.5px)'
  };

  const welcomeContentStyle = {
    textAlign: 'center',
    zIndex: 10,
    maxWidth: '400px'
  };

  const formContainerStyle = {
    width: '100%',
    maxWidth: '400px',
    zIndex: 10
  };

  const headerStyle = {
    textAlign: 'center',
    marginBottom: '2rem'
  };

  const iconContainerStyle = {
    width: '3.5rem',
    height: '3.5rem',
    background: 'linear-gradient(135deg, #10b981, #059669)',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 1rem',
    boxShadow: '0 10px 25px rgba(16, 185, 129, 0.3)'
  };

  const titleStyle = {
    fontSize: '2rem',
    fontWeight: 'bold',
    color: '#1f2937',
    marginBottom: '0.5rem'
  };

  const subtitleStyle = {
    color: '#6b7280',
    fontSize: '1rem'
  };

  const backButtonStyle = {
    position: 'absolute',
    top: '2rem',
    left: '2rem',
    padding: '0.75rem',
    background: 'rgba(255, 255, 255, 0.2)',
    backdropFilter: 'blur(16px)',
    borderRadius: '50%',
    color: 'white',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    zIndex: 20,
    boxShadow: '0 8px 25px rgba(0, 0, 0, 0.3)'
  };

  const inputContainerStyle = {
    display: 'flex',
    alignItems: 'center',
    background: '#f8fafc',
    borderRadius: '0.75rem',
    padding: '0.75rem 1rem',
    border: '2px solid #e2e8f0',
    transition: 'all 0.3s ease',
    marginBottom: '0.5rem',
    position: 'relative',
    overflow: 'hidden'
  };

  const inputContainerFocusStyle = {
    borderColor: '#10b981',
    background: '#f0fdf4',
    transform: 'translateY(-2px)',
    boxShadow: '0 10px 25px rgba(16, 185, 129, 0.15)'
  };

  const inputStyle = {
    width: '100%',
    background: 'transparent',
    border: 'none',
    outline: 'none',
    padding: '0.5rem',
    color: '#374151',
    fontSize: '1rem'
  };

  const buttonStyle = {
    width: '100%',
    background: 'linear-gradient(135deg, #10b981, #059669)',
    color: 'white',
    padding: '1rem',
    borderRadius: '0.75rem',
    fontWeight: '600',
    fontSize: '1.125rem',
    border: 'none',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    transform: 'scale(1)',
    boxShadow: '0 4px 15px rgba(16, 185, 129, 0.4)',
    position: 'relative',
    overflow: 'hidden',
    marginBottom: '1rem'
  };

  const buttonHoverStyle = {
    transform: 'scale(1.02) translateY(-2px)',
    boxShadow: '0 8px 25px rgba(16, 185, 129, 0.6)'
  };

  const googleButtonStyle = {
    width: '100%',
    background: 'white',
    color: '#374151',
    padding: '1rem 1.5rem',
    borderRadius: '0.75rem',
    fontWeight: '600',
    fontSize: '1rem',
    border: '2px solid #e5e7eb',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    transform: 'scale(1)',
    boxShadow: '0 4px 15px rgba(0, 0, 0, 0.1)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.75rem',
    marginBottom: '1.5rem'
  };

  const googleButtonHoverStyle = {
    transform: 'scale(1.02) translateY(-2px)',
    boxShadow: '0 8px 25px rgba(0, 0, 0, 0.15)',
    borderColor: '#10b981'
  };

  const errorStyle = {
    color: '#ef4444',
    fontSize: '0.875rem',
    marginTop: '0.25rem',
    marginLeft: '0.25rem',
    animation: 'shake 0.5s ease-in-out'
  };

  // Responsive styles for mobile
  const isMobile = window.innerWidth <= 768;
  
  if (isMobile) {
    containerStyle.flexDirection = 'column';
    leftSideStyle.flex = 'none';
    leftSideStyle.minHeight = '40vh';
    rightSideStyle.flex = 'none';
    rightSideStyle.minHeight = '60vh';
  }

  return (
    <div style={containerStyle}>
      {/* Left Side - Background Image */}
      <div style={leftSideStyle}>
        <div style={overlayStyle}></div>
        
        {/* Back Button */}
        <button 
          style={backButtonStyle}
          onClick={() => navigate(-1)}
          onMouseEnter={(e) => {
            e.target.style.background = 'rgba(255, 255, 255, 0.3)';
            e.target.style.transform = 'scale(1.1)';
          }}
          onMouseLeave={(e) => {
            e.target.style.background = 'rgba(255, 255, 255, 0.2)';
            e.target.style.transform = 'scale(1)';
          }}
        >
          <ArrowLeft size={24} />
        </button>

        <div style={welcomeContentStyle}>
          <div style={{
            ...iconContainerStyle,
            background: 'rgba(255, 255, 255, 0.2)',
            backdropFilter: 'blur(16px)',
            border: '2px solid rgba(255, 255, 255, 0.3)',
            boxShadow: '0 15px 35px rgba(0, 0, 0, 0.2)'
          }}>
            <LogIn size={28} color="white" />
          </div>
          <h1 style={{ 
            fontSize: '2.5rem', 
            fontWeight: 'bold', 
            marginBottom: '1rem',
            textShadow: '2px 2px 4px rgba(0, 0, 0, 0.3)'
          }}>
            Welcome Back!
          </h1>
          <p style={{ 
            fontSize: '1.125rem',
            marginBottom: '1.5rem',
            opacity: 0.9,
            textShadow: '1px 1px 2px rgba(0, 0, 0, 0.2)'
          }}>
            Thekkevayalil Pepper Nursery
          </p>
          <p style={{ 
            fontSize: '1rem',
            opacity: 0.8,
            textShadow: '1px 1px 2px rgba(0, 0, 0, 0.2)',
            lineHeight: '1.6'
          }}>
            Sign in to access your account and explore our premium pepper collection.
          </p>
          

        </div>
      </div>

      {/* Right Side - Login Form */}
      <div style={rightSideStyle}>
        <div style={formContainerStyle}>
          {/* Header */}
          <div style={headerStyle}>
            <div style={iconContainerStyle}>
              <LogIn color="white" size={20} />
            </div>
            <h2 style={titleStyle}>Sign In</h2>
            <p style={subtitleStyle}>Access your account</p>
          </div>

          {/* Error/Success Messages */}
          {errors.general && (
            <div style={{
              background: '#fef2f2',
              border: '1px solid #fecaca',
              color: '#dc2626',
              padding: '0.75rem 1rem',
              borderRadius: '0.5rem',
              fontSize: '0.875rem',
              marginBottom: '1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
              </svg>
              {errors.general}
            </div>
          )}

          {successMessage && (
            <div style={{
              background: '#f0fdf4',
              border: '1px solid #bbf7d0',
              color: '#16a34a',
              padding: '0.75rem 1rem',
              borderRadius: '0.5rem',
              fontSize: '0.875rem',
              marginBottom: '1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22,4 12,14.01 9,11.01"/>
              </svg>
              {successMessage}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {/* Email */}
            <div style={{ marginBottom: '1.5rem' }}>
              <div 
                style={{
                  ...inputContainerStyle,
                  ...(errors.email ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                }}
                onMouseEnter={(e) => {
                  if (!errors.email) Object.assign(e.target.style, inputContainerFocusStyle);
                }}
                onMouseLeave={(e) => {
                  if (!errors.email) {
                    e.target.style.borderColor = '#e2e8f0';
                    e.target.style.background = '#f8fafc';
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = 'none';
                  }
                }}
              >
                <Mail color={errors.email ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                <input
                  type="email"
                  name="email"
                  placeholder="Email Address"
                  value={formData.email}
                  onChange={handleChange}
                  style={inputStyle}
                />
              </div>
              {errors.email && <p style={errorStyle}>{errors.email}</p>}
            </div>

            {/* Password */}
            <div style={{ marginBottom: '1.5rem' }}>
              <div 
                style={{
                  ...inputContainerStyle,
                  ...(errors.password ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                }}
                onMouseEnter={(e) => {
                  if (!errors.password) Object.assign(e.target.style, inputContainerFocusStyle);
                }}
                onMouseLeave={(e) => {
                  if (!errors.password) {
                    e.target.style.borderColor = '#e2e8f0';
                    e.target.style.background = '#f8fafc';
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = 'none';
                  }
                }}
              >
                <Lock color={errors.password ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                <input
                  type={showPassword ? "text" : "password"}
                  name="password"
                  placeholder="Password"
                  value={formData.password}
                  onChange={handleChange}
                  style={inputStyle}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: '#6b7280',
                    padding: '0.25rem',
                    borderRadius: '0.25rem',
                    transition: 'all 0.3s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.target.style.background = '#f3f4f6';
                    e.target.style.color = '#10b981';
                  }}
                  onMouseLeave={(e) => {
                    e.target.style.background = 'none';
                    e.target.style.color = '#6b7280';
                  }}
                >
                  {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
              {errors.password && <p style={errorStyle}>{errors.password}</p>}
            </div>

            {/* Remember Me & Forgot Password */}
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              marginBottom: '2rem',
              fontSize: '0.875rem'
            }}>
              <label style={{ 
                display: 'flex', 
                alignItems: 'center',
                cursor: 'pointer',
                color: '#374151'
              }}>
                <input 
                  type="checkbox" 
                  style={{ 
                    marginRight: '0.5rem',
                    accentColor: '#10b981'
                  }} 
                />
                Remember me
              </label>
              <a 
                href="/forgot-password"
                style={{ 
                  color: '#10b981',
                  textDecoration: 'none',
                  fontWeight: '500',
                  transition: 'all 0.3s ease'
                }}
                onMouseEnter={(e) => {
                  e.target.style.color = '#059669';
                  e.target.style.textDecoration = 'underline';
                }}
                onMouseLeave={(e) => {
                  e.target.style.color = '#10b981';
                  e.target.style.textDecoration = 'none';
                }}
              >
                Forgot password?
              </a>
            </div>

            {/* Sign In Button */}
            <button
              type="submit"
              disabled={isLoading}
              style={{
                ...buttonStyle,
                opacity: isLoading ? 0.8 : 1,
                cursor: isLoading ? 'not-allowed' : 'pointer'
              }}
              onMouseEnter={(e) => !isLoading && Object.assign(e.target.style, buttonHoverStyle)}
              onMouseLeave={(e) => !isLoading && Object.assign(e.target.style, {
                transform: 'scale(1)',
                boxShadow: '0 4px 15px rgba(16, 185, 129, 0.4)'
              })}
            >
              {isLoading ? (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <div style={{
                    width: '1.25rem',
                    height: '1.25rem',
                    border: '2px solid white',
                    borderTop: '2px solid transparent',
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite',
                    marginRight: '0.5rem'
                  }}></div>
                  Signing In...
                </div>
              ) : (
                "Sign In"
              )}
            </button>
          </form>

          {/* Divider */}
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            margin: '1.5rem 0'
          }}>
            <div style={{ flex: 1, height: '1px', background: 'linear-gradient(to right, transparent, #e5e7eb, transparent)' }}></div>
            <span style={{ 
              padding: '0 1rem', 
              color: '#6b7280', 
              fontSize: '0.875rem',
              background: 'white'
            }}>Or continue with</span>
            <div style={{ flex: 1, height: '1px', background: 'linear-gradient(to left, transparent, #e5e7eb, transparent)' }}></div>
          </div>

          {/* Google Sign In Button */}
          <button
            type="button"
            onClick={handleGoogleLogin}
            disabled={isGoogleLoading}
            style={{
              ...googleButtonStyle,
              opacity: isGoogleLoading ? 0.8 : 1,
              cursor: isGoogleLoading ? 'not-allowed' : 'pointer'
            }}
            onMouseEnter={(e) => !isGoogleLoading && Object.assign(e.target.style, googleButtonHoverStyle)}
            onMouseLeave={(e) => !isGoogleLoading && Object.assign(e.target.style, {
              transform: 'scale(1)',
              boxShadow: '0 4px 15px rgba(0, 0, 0, 0.1)',
              borderColor: '#e5e7eb'
            })}
          >
            {isGoogleLoading ? (
              <>
                <div style={{
                  width: '1.25rem',
                  height: '1.25rem',
                  border: '2px solid #10b981',
                  borderTop: '2px solid transparent',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }}></div>
                <span>Signing in...</span>
              </>
            ) : (
              <>
                <svg width="20" height="20" viewBox="0 0 24 24">
                  <path fill="#ea4335" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#4285f4" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                <span>Sign in with Google</span>
              </>
            )}
          </button>

          {/* Sign Up Link */}
          <p style={{ 
            textAlign: 'center', 
            color: '#6b7280',
            fontSize: '0.875rem'
          }}>
            Don't have an account?{" "}
            <a 
              href="/register" 
              style={{ 
                color: '#10b981',
                textDecoration: 'none',
                fontWeight: '600',
                transition: 'all 0.3s ease',
                padding: '0.25rem'
              }}
              onMouseEnter={(e) => {
                e.target.style.color = '#059669';
                e.target.style.textDecoration = 'underline';
              }}
              onMouseLeave={(e) => {
                e.target.style.color = '#10b981';
                e.target.style.textDecoration = 'none';
              }}
            >
              Create Account
            </a>
          </p>
        </div>
      </div>

      <style>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-5px); }
          75% { transform: translateX(5px); }
        }
        
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        
        @keyframes float {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-20px); }
        }

        @media (max-width: 768px) {
          .container {
            flex-direction: column !important;
          }
          .left-side {
            flex: none !important;
            min-height: 40vh !important;
          }
          .right-side {
            flex: none !important;
            min-height: 60vh !important;
          }
        }
      `}</style>
    </div>
  );
}