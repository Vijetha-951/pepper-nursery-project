import { useState, useEffect } from "react";
import { User, Package, ShoppingCart, Truck, LogOut, Settings, Bell, Search, Plus } from "lucide-react";
import authService from "../services/authService";

export default function Dashboard() {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState({
    totalOrders: 15,
    pendingDeliveries: 3,
    totalProducts: 47,
    newNotifications: 5
  });

  useEffect(() => {
    const currentUser = authService.getCurrentUser();
    if (!currentUser) {
      window.location.href = '/login';
      return;
    }
    setUser(currentUser);
  }, []);

  const handleLogout = () => {
    if (window.confirm('Are you sure you want to logout?')) {
      authService.logout();
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

  const sidebarStyle = {
    width: '280px',
    background: 'linear-gradient(135deg, #10b981, #059669)',
    color: 'white',
    padding: '2rem',
    display: 'flex',
    flexDirection: 'column',
    boxShadow: '4px 0 20px rgba(0, 0, 0, 0.1)',
    position: 'relative',
    overflow: 'hidden'
  };

  const mainContentStyle = {
    flex: 1,
    background: '#f9fafb',
    padding: '2rem',
    overflowY: 'auto'
  };

  const cardStyle = {
    background: 'white',
    borderRadius: '12px',
    padding: '1.5rem',
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.05)',
    border: '1px solid #e5e7eb',
    transition: 'all 0.3s ease'
  };

  const statCardStyle = {
    ...cardStyle,
    textAlign: 'center',
    cursor: 'pointer',
    transition: 'all 0.3s ease'
  };

  const menuItems = [
    { id: 'overview', label: 'Overview', icon: Package },
    { id: 'orders', label: 'My Orders', icon: ShoppingCart },
    { id: 'products', label: 'Products', icon: Package },
    ...(user.role === 'deliveryboy' ? [{ id: 'deliveries', label: 'Deliveries', icon: Truck }] : []),
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  const renderOverview = () => (
    <div>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
        gap: '1.5rem',
        marginBottom: '2rem'
      }}>
        <div 
          style={statCardStyle}
          onMouseEnter={(e) => {
            e.target.style.transform = 'translateY(-4px)';
            e.target.style.boxShadow = '0 8px 30px rgba(0, 0, 0, 0.15)';
          }}
          onMouseLeave={(e) => {
            e.target.style.transform = 'translateY(0)';
            e.target.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.05)';
          }}
        >
          <ShoppingCart size={32} color="#10b981" style={{ marginBottom: '1rem' }} />
          <h3 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '0.5rem' }}>
            {stats.totalOrders}
          </h3>
          <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>Total Orders</p>
        </div>

        <div 
          style={statCardStyle}
          onMouseEnter={(e) => {
            e.target.style.transform = 'translateY(-4px)';
            e.target.style.boxShadow = '0 8px 30px rgba(0, 0, 0, 0.15)';
          }}
          onMouseLeave={(e) => {
            e.target.style.transform = 'translateY(0)';
            e.target.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.05)';
          }}
        >
          <Truck size={32} color="#f59e0b" style={{ marginBottom: '1rem' }} />
          <h3 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '0.5rem' }}>
            {stats.pendingDeliveries}
          </h3>
          <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>Pending Deliveries</p>
        </div>

        <div 
          style={statCardStyle}
          onMouseEnter={(e) => {
            e.target.style.transform = 'translateY(-4px)';
            e.target.style.boxShadow = '0 8px 30px rgba(0, 0, 0, 0.15)';
          }}
          onMouseLeave={(e) => {
            e.target.style.transform = 'translateY(0)';
            e.target.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.05)';
          }}
        >
          <Package size={32} color="#10b981" style={{ marginBottom: '1rem' }} />
          <h3 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '0.5rem' }}>
            {stats.totalProducts}
          </h3>
          <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>Available Products</p>
        </div>

        <div 
          style={statCardStyle}
          onMouseEnter={(e) => {
            e.target.style.transform = 'translateY(-4px)';
            e.target.style.boxShadow = '0 8px 30px rgba(0, 0, 0, 0.15)';
          }}
          onMouseLeave={(e) => {
            e.target.style.transform = 'translateY(0)';
            e.target.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.05)';
          }}
        >
          <Bell size={32} color="#ef4444" style={{ marginBottom: '1rem' }} />
          <h3 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '0.5rem' }}>
            {stats.newNotifications}
          </h3>
          <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>New Notifications</p>
        </div>
      </div>

      <div style={cardStyle}>
        <h3 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>
          Recent Activity
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            padding: '1rem', 
            background: '#f0fdf4', 
            borderRadius: '8px',
            border: '1px solid #bbf7d0'
          }}>
            <Package size={20} color="#10b981" style={{ marginRight: '1rem' }} />
            <div>
              <p style={{ fontWeight: '500', color: '#1f2937' }}>New order placed</p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280' }}>Black Pepper Seedlings - 5 plants</p>
            </div>
          </div>
          
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            padding: '1rem', 
            background: '#fef3c7', 
            borderRadius: '8px',
            border: '1px solid #fde68a'
          }}>
            <Truck size={20} color="#f59e0b" style={{ marginRight: '1rem' }} />
            <div>
              <p style={{ fontWeight: '500', color: '#1f2937' }}>Order shipped</p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280' }}>White Pepper Seeds - Track: #WP2025001</p>
            </div>
          </div>
          
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            padding: '1rem', 
            background: '#ede9fe', 
            borderRadius: '8px',
            border: '1px solid #c4b5fd'
          }}>
            <User size={20} color="#8b5cf6" style={{ marginRight: '1rem' }} />
            <div>
              <p style={{ fontWeight: '500', color: '#1f2937' }}>Profile updated</p>
              <p style={{ fontSize: '0.875rem', color: '#6b7280' }}>Delivery address changed</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return renderOverview();
      case 'orders':
        return (
          <div style={cardStyle}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>
              My Orders
            </h3>
            <p style={{ color: '#6b7280' }}>Your order history and current orders will appear here.</p>
          </div>
        );
      case 'products':
        return (
          <div style={cardStyle}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>
              Our Products
            </h3>
            <p style={{ color: '#6b7280' }}>Browse our premium pepper plants and seeds collection.</p>
          </div>
        );
      case 'deliveries':
        return (
          <div style={cardStyle}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>
              Delivery Management
            </h3>
            <p style={{ color: '#6b7280' }}>Manage your delivery routes and pending deliveries.</p>
          </div>
        );
      case 'profile':
        return (
          <div style={cardStyle}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>
              Profile Information
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', color: '#374151', fontWeight: '500' }}>
                  First Name
                </label>
                <input
                  type="text"
                  value={user.firstName || 'N/A'}
                  readOnly
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '8px',
                    background: '#f9fafb'
                  }}
                />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', color: '#374151', fontWeight: '500' }}>
                  Last Name
                </label>
                <input
                  type="text"
                  value={user.lastName || 'N/A'}
                  readOnly
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '8px',
                    background: '#f9fafb'
                  }}
                />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', color: '#374151', fontWeight: '500' }}>
                  Email
                </label>
                <input
                  type="email"
                  value={user.email || 'N/A'}
                  readOnly
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '8px',
                    background: '#f9fafb'
                  }}
                />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', color: '#374151', fontWeight: '500' }}>
                  Role
                </label>
                <input
                  type="text"
                  value={user.role || 'user'}
                  readOnly
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '8px',
                    background: '#f9fafb',
                    textTransform: 'capitalize'
                  }}
                />
              </div>
            </div>
          </div>
        );
      case 'settings':
        return (
          <div style={cardStyle}>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>
              Settings
            </h3>
            <p style={{ color: '#6b7280' }}>Manage your account settings and preferences.</p>
          </div>
        );
      default:
        return renderOverview();
    }
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      <div style={sidebarStyle}>
        {/* Background decoration */}
        <div style={{
          position: 'absolute',
          top: '-50%',
          right: '-50%',
          width: '200%',
          height: '200%',
          background: 'radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%)',
          pointerEvents: 'none'
        }}></div>

        {/* Logo/Brand */}
        <div style={{ marginBottom: '2rem', textAlign: 'center', position: 'relative', zIndex: 10 }}>
          <div style={{
            width: '60px',
            height: '60px',
            background: 'rgba(255, 255, 255, 0.2)',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1rem',
            backdropFilter: 'blur(16px)'
          }}>
            <Package color="white" size={28} />
          </div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 'bold', margin: 0 }}>Pepper Nursery</h1>
        </div>

        {/* User Info */}
        <div style={{
          padding: '1rem',
          background: 'rgba(255, 255, 255, 0.1)',
          borderRadius: '12px',
          marginBottom: '2rem',
          backdropFilter: 'blur(16px)',
          position: 'relative',
          zIndex: 10
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
            {user.avatar ? (
              <img 
                src={user.avatar} 
                alt="Profile" 
                style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '50%',
                  marginRight: '0.75rem'
                }}
              />
            ) : (
              <div style={{
                width: '40px',
                height: '40px',
                background: 'rgba(255, 255, 255, 0.2)',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '0.75rem'
              }}>
                <User color="white" size={20} />
              </div>
            )}
            <div>
              <p style={{ margin: 0, fontWeight: '600', fontSize: '0.875rem' }}>
                {user.firstName || 'User'} {user.lastName || ''}
              </p>
              <p style={{ margin: 0, fontSize: '0.75rem', opacity: 0.8, textTransform: 'capitalize' }}>
                {user.role || 'user'}
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, position: 'relative', zIndex: 10 }}>
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  padding: '0.75rem 1rem',
                  marginBottom: '0.5rem',
                  background: isActive ? 'rgba(255, 255, 255, 0.2)' : 'transparent',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                  fontSize: '0.875rem',
                  fontWeight: isActive ? '600' : '500',
                  backdropFilter: isActive ? 'blur(16px)' : 'none'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.target.style.background = 'rgba(255, 255, 255, 0.1)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.target.style.background = 'transparent';
                  }
                }}
              >
                <Icon size={18} style={{ marginRight: '0.75rem' }} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Logout Button */}
        <button
          onClick={handleLogout}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            padding: '0.75rem 1rem',
            marginTop: '1rem',
            background: 'rgba(239, 68, 68, 0.2)',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            cursor: 'pointer',
            transition: 'all 0.3s ease',
            fontSize: '0.875rem',
            fontWeight: '500',
            backdropFilter: 'blur(16px)',
            position: 'relative',
            zIndex: 10
          }}
          onMouseEnter={(e) => {
            e.target.style.background = 'rgba(239, 68, 68, 0.3)';
          }}
          onMouseLeave={(e) => {
            e.target.style.background = 'rgba(239, 68, 68, 0.2)';
          }}
        >
          <LogOut size={18} style={{ marginRight: '0.75rem' }} />
          Logout
        </button>
      </div>

      {/* Main Content */}
      <div style={mainContentStyle}>
        {/* Header */}
        <header style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          marginBottom: '2rem'
        }}>
          <div>
            <h1 style={{ 
              fontSize: '2rem', 
              fontWeight: 'bold', 
              color: '#1f2937',
              margin: 0,
              marginBottom: '0.5rem'
            }}>
              Welcome back, {user.firstName || 'User'}! 👋
            </h1>
            <p style={{ color: '#6b7280', margin: 0 }}>
              Here's what's happening with your pepper nursery today.
            </p>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <button style={{
              padding: '0.75rem',
              background: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              cursor: 'pointer',
              transition: 'all 0.3s ease'
            }}>
              <Search size={20} color="#6b7280" />
            </button>
            
            <button style={{
              position: 'relative',
              padding: '0.75rem',
              background: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              cursor: 'pointer',
              transition: 'all 0.3s ease'
            }}>
              <Bell size={20} color="#6b7280" />
              {stats.newNotifications > 0 && (
                <div style={{
                  position: 'absolute',
                  top: '4px',
                  right: '4px',
                  width: '12px',
                  height: '12px',
                  background: '#ef4444',
                  borderRadius: '50%',
                  border: '2px solid white'
                }}></div>
              )}
            </button>
          </div>
        </header>

        {/* Content Area */}
        {renderContent()}
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}