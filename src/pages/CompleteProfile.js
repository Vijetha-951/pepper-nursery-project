import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { User, Mail, Phone, MapPin, ArrowLeft, CheckCircle } from "lucide-react";
import backgroundImage from "../assets/loginreg.jpeg";
import authService from "../services/authService";

export default function CompleteProfile() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    role: "user",
    place: "",
    district: "",
    pincode: ""
  });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [successMessage, setSuccessMessage] = useState("");

  useEffect(() => {
    const currentUser = authService.getCurrentUser();
    if (!currentUser) {
      navigate('/login');
      return;
    }
    
    // If user profile is already complete, redirect to dashboard
    if (!currentUser.isNewUser && currentUser.phone && currentUser.place && currentUser.district && currentUser.pincode) {
      navigate('/dashboard');
      return;
    }

    setUser(currentUser);
    setFormData({
      firstName: currentUser.firstName || "",
      lastName: currentUser.lastName || "",
      email: currentUser.email || "",
      phone: currentUser.phone || "",
      role: currentUser.role || "user",
      place: currentUser.place || "",
      district: currentUser.district || "",
      pincode: currentUser.pincode || ""
    });
  }, [navigate]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    if (errors[e.target.name]) {
      setErrors({ ...errors, [e.target.name]: "" });
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.firstName) {
      newErrors.firstName = "First name is required";
    } else if (formData.firstName.length < 2 || formData.firstName.length > 50) {
      newErrors.firstName = "First name must be 2–50 characters";
    } else if (!/^[\p{L}]+$/u.test(formData.firstName)) {
      newErrors.firstName = "Only letters allowed";
    }
    
    if (!formData.lastName) {
      newErrors.lastName = "Last name is required";
    } else if (formData.lastName.length < 2 || formData.lastName.length > 50) {
      newErrors.lastName = "Last name must be 2–50 characters";
    } else if (!/^[\p{L}]+$/u.test(formData.lastName)) {
      newErrors.lastName = "Only letters allowed";
    }
    
    if (!formData.email) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Please enter a valid email";
    }
    
    if (!formData.phone) {
      newErrors.phone = "Phone number is required";
    } else if (!/^\d{10}$/.test(formData.phone)) {
      newErrors.phone = "Please enter a valid 10-digit phone number";
    }
    
    if (!formData.place) {
      newErrors.place = "Place is required";
    } else if (formData.place.length < 2 || formData.place.length > 100) {
      newErrors.place = "Place must be 2–100 characters";
    } else if (!/^[\p{L}\s]+$/u.test(formData.place)) {
      newErrors.place = "Only letters and spaces allowed";
    }
    
    if (!formData.district) {
      newErrors.district = "District is required";
    } else if (formData.district.length < 2 || formData.district.length > 50) {
      newErrors.district = "District must be 2–50 characters";
    } else if (!/^[\p{L}]+$/u.test(formData.district)) {
      newErrors.district = "Only letters allowed";
    }
    
    if (!formData.pincode) {
      newErrors.pincode = "Pincode is required";
    } else if (!/^\d{6}$/.test(formData.pincode)) {
      newErrors.pincode = "Please enter a valid 6-digit pincode";
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
      const result = await authService.updateProfile({ 
        ...formData,
        isNewUser: false
      });
      
      if (result.success) {
        setSuccessMessage("Profile completed successfully! Redirecting to dashboard...");
        setTimeout(() => {
          navigate('/dashboard');
        }, 2000);
      } else {
        setErrors({ general: result.error });
      }
    } catch (error) {
      console.error('Profile update error:', error);
      setErrors({ general: "An unexpected error occurred. Please try again." });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSkip = () => {
    if (window.confirm('Are you sure you want to skip profile completion? You can complete it later from your dashboard.')) {
      navigate('/dashboard');
    }
  };

  if (!user) {
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
      </div>
    );
  }

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
    maxWidth: '500px',
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
    marginBottom: '0.5rem'
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

  const selectStyle = {
    width: '100%',
    background: '#f8fafc',
    border: '2px solid #e2e8f0',
    borderRadius: '0.75rem',
    padding: '1rem',
    color: '#374151',
    fontSize: '1rem',
    outline: 'none',
    transition: 'all 0.3s ease',
    appearance: 'none',
    backgroundImage: `url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e")`,
    backgroundPosition: 'right 1rem center',
    backgroundRepeat: 'no-repeat',
    backgroundSize: '1.5em 1.5em'
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
    marginBottom: '1rem'
  };

  const buttonHoverStyle = {
    transform: 'scale(1.02) translateY(-2px)',
    boxShadow: '0 8px 25px rgba(16, 185, 129, 0.6)'
  };

  const skipButtonStyle = {
    width: '100%',
    background: 'white',
    color: '#6b7280',
    padding: '1rem',
    borderRadius: '0.75rem',
    fontWeight: '500',
    fontSize: '1rem',
    border: '2px solid #e5e7eb',
    cursor: 'pointer',
    transition: 'all 0.3s ease'
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
          onClick={() => window.history.back()}
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
            <CheckCircle size={28} color="white" />
          </div>
          <h1 style={{ 
            fontSize: '2.5rem', 
            fontWeight: 'bold', 
            marginBottom: '1rem',
            textShadow: '2px 2px 4px rgba(0, 0, 0, 0.3)'
          }}>
            Almost Done!
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
            Complete your profile to get the best experience from our pepper nursery. 
            We'll use this information to provide personalized recommendations.
          </p>
        </div>
      </div>

      {/* Right Side - Complete Profile Form */}
      <div style={rightSideStyle}>
        <div style={formContainerStyle}>
          {/* Header */}
          <div style={headerStyle}>
            <div style={iconContainerStyle}>
              <User color="white" size={20} />
            </div>
            <h2 style={titleStyle}>Complete Your Profile</h2>
            <p style={subtitleStyle}>Help us serve you better</p>
          </div>

          <form onSubmit={handleSubmit}>
            {/* General Error Message */}
            {errors.general && (
              <div style={{
                background: '#fef2f2',
                border: '1px solid #fecaca',
                borderRadius: '0.5rem',
                padding: '0.75rem',
                marginBottom: '1rem',
                color: '#dc2626',
                fontSize: '0.875rem',
                textAlign: 'center'
              }}>
                {errors.general}
              </div>
            )}

            {/* First Name & Last Name Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <div>
                <div 
                  style={{
                    ...inputContainerStyle,
                    ...(errors.firstName ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                  }}
                  onMouseEnter={(e) => {
                    if (!errors.firstName) Object.assign(e.target.style, inputContainerFocusStyle);
                  }}
                  onMouseLeave={(e) => {
                    if (!errors.firstName) {
                      e.target.style.borderColor = '#e2e8f0';
                      e.target.style.background = '#f8fafc';
                      e.target.style.transform = 'translateY(0)';
                      e.target.style.boxShadow = 'none';
                    }
                  }}
                >
                  <User color={errors.firstName ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                  <input
                    type="text"
                    name="firstName"
                    placeholder="First Name"
                    value={formData.firstName}
                    onChange={handleChange}
                    style={inputStyle}
                  />
                </div>
                {errors.firstName && <p style={errorStyle}>{errors.firstName}</p>}
              </div>
              
              <div>
                <div 
                  style={{
                    ...inputContainerStyle,
                    ...(errors.lastName ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                  }}
                  onMouseEnter={(e) => {
                    if (!errors.lastName) Object.assign(e.target.style, inputContainerFocusStyle);
                  }}
                  onMouseLeave={(e) => {
                    if (!errors.lastName) {
                      e.target.style.borderColor = '#e2e8f0';
                      e.target.style.background = '#f8fafc';
                      e.target.style.transform = 'translateY(0)';
                      e.target.style.boxShadow = 'none';
                    }
                  }}
                >
                  <User color={errors.lastName ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                  <input
                    type="text"
                    name="lastName"
                    placeholder="Last Name"
                    value={formData.lastName}
                    onChange={handleChange}
                    style={inputStyle}
                  />
                </div>
                {errors.lastName && <p style={errorStyle}>{errors.lastName}</p>}
              </div>
            </div>

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
                  readOnly
                />
              </div>
              {errors.email && <p style={errorStyle}>{errors.email}</p>}
            </div>

            {/* Phone & Role Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <div>
                <div 
                  style={{
                    ...inputContainerStyle,
                    ...(errors.phone ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                  }}
                  onMouseEnter={(e) => {
                    if (!errors.phone) Object.assign(e.target.style, inputContainerFocusStyle);
                  }}
                  onMouseLeave={(e) => {
                    if (!errors.phone) {
                      e.target.style.borderColor = '#e2e8f0';
                      e.target.style.background = '#f8fafc';
                      e.target.style.transform = 'translateY(0)';
                      e.target.style.boxShadow = 'none';
                    }
                  }}
                >
                  <Phone color={errors.phone ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                  <input
                    type="tel"
                    name="phone"
                    placeholder="Phone Number"
                    value={formData.phone}
                    onChange={handleChange}
                    style={inputStyle}
                  />
                </div>
                {errors.phone && <p style={errorStyle}>{errors.phone}</p>}
              </div>
              
              <div>
                <select
                  name="role"
                  value={formData.role}
                  onChange={handleChange}
                  style={{
                    ...selectStyle,
                    borderColor: errors.role ? '#ef4444' : '#e2e8f0'
                  }}
                  onMouseEnter={(e) => {
                    e.target.style.borderColor = '#10b981';
                    e.target.style.background = '#f0fdf4';
                  }}
                  onMouseLeave={(e) => {
                    e.target.style.borderColor = '#e2e8f0';
                    e.target.style.background = '#f8fafc';
                  }}
                >
                  <option value="user">User</option>
                  <option value="deliveryboy">Delivery Boy</option>
                </select>
                {errors.role && <p style={errorStyle}>{errors.role}</p>}
              </div>
            </div>

            {/* Address Fields */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <div>
                <div 
                  style={{
                    ...inputContainerStyle,
                    ...(errors.place ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                  }}
                  onMouseEnter={(e) => {
                    if (!errors.place) Object.assign(e.target.style, inputContainerFocusStyle);
                  }}
                  onMouseLeave={(e) => {
                    if (!errors.place) {
                      e.target.style.borderColor = '#e2e8f0';
                      e.target.style.background = '#f8fafc';
                      e.target.style.transform = 'translateY(0)';
                      e.target.style.boxShadow = 'none';
                    }
                  }}
                >
                  <MapPin color={errors.place ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                  <input
                    type="text"
                    name="place"
                    placeholder="Place"
                    value={formData.place}
                    onChange={handleChange}
                    style={inputStyle}
                  />
                </div>
                {errors.place && <p style={errorStyle}>{errors.place}</p>}
              </div>
              
              <div>
                <div 
                  style={{
                    ...inputContainerStyle,
                    ...(errors.district ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                  }}
                  onMouseEnter={(e) => {
                    if (!errors.district) Object.assign(e.target.style, inputContainerFocusStyle);
                  }}
                  onMouseLeave={(e) => {
                    if (!errors.district) {
                      e.target.style.borderColor = '#e2e8f0';
                      e.target.style.background = '#f8fafc';
                      e.target.style.transform = 'translateY(0)';
                      e.target.style.boxShadow = 'none';
                    }
                  }}
                >
                  <MapPin color={errors.district ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                  <input
                    type="text"
                    name="district"
                    placeholder="District"
                    value={formData.district}
                    onChange={handleChange}
                    style={inputStyle}
                  />
                </div>
                {errors.district && <p style={errorStyle}>{errors.district}</p>}
              </div>
            </div>

            {/* Pincode */}
            <div style={{ marginBottom: '2rem' }}>
              <div 
                style={{
                  ...inputContainerStyle,
                  ...(errors.pincode ? { borderColor: '#ef4444', background: '#fef2f2' } : {}),
                }}
                onMouseEnter={(e) => {
                  if (!errors.pincode) Object.assign(e.target.style, inputContainerFocusStyle);
                }}
                onMouseLeave={(e) => {
                  if (!errors.pincode) {
                    e.target.style.borderColor = '#e2e8f0';
                    e.target.style.background = '#f8fafc';
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = 'none';
                  }
                }}
              >
                <MapPin color={errors.pincode ? "#ef4444" : "#10b981"} size={20} style={{ marginRight: '0.75rem' }} />
                <input
                  type="text"
                  name="pincode"
                  placeholder="Pincode"
                  value={formData.pincode}
                  onChange={handleChange}
                  style={inputStyle}
                  maxLength={6}
                />
              </div>
              {errors.pincode && <p style={errorStyle}>{errors.pincode}</p>}
            </div>

            {/* Complete Profile Button */}
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
                  Completing Profile...
                </div>
              ) : (
                "Complete Profile"
              )}
            </button>

            {/* Skip Button */}
            <button
              type="button"
              onClick={handleSkip}
              style={skipButtonStyle}
              onMouseEnter={(e) => {
                e.target.style.background = '#f9fafb';
                e.target.style.borderColor = '#d1d5db';
              }}
              onMouseLeave={(e) => {
                e.target.style.background = 'white';
                e.target.style.borderColor = '#e5e7eb';
              }}
            >
              Skip for Now
            </button>
          </form>
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