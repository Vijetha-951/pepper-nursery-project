import { useEffect, useState } from "react";
import { Truck, Package, MapPin, CheckCircle, Clock, LogOut, Settings } from "lucide-react";
import authService from "../services/authService";

export default function DeliveryDashboard() {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('deliveries');
  const [stats, setStats] = useState({
    todayDeliveries: 8,
    pending: 3,
    completed: 5
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
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f9fafb' }}>
        <div style={{ width: '3rem', height: '3rem', border: '4px solid #10b981', borderTop: '4px solid transparent', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
      </div>
    );
  }

  const sidebarStyle = {
    width: '280px',
    background: 'linear-gradient(135deg, #0ea5e9, #0284c7)',
    color: 'white',
    padding: '2rem',
    display: 'flex',
    flexDirection: 'column',
    boxShadow: '4px 0 20px rgba(0, 0, 0, 0.1)',
    position: 'relative',
    overflow: 'hidden'
  };

  const mainContentStyle = { flex: 1, background: '#f9fafb', padding: '2rem', overflowY: 'auto' };
  const cardStyle = { background: 'white', borderRadius: '12px', padding: '1.5rem', boxShadow: '0 4px 20px rgba(0, 0, 0, 0.05)', border: '1px solid #e5e7eb' };
  const statCardStyle = { ...cardStyle, textAlign: 'center' };

  const deliveriesList = [
    { id: 'DL-001', item: 'Black Pepper Seedlings', qty: 5, address: 'MG Road, Kochi', status: 'Pending' },
    { id: 'DL-002', item: 'White Pepper Seeds', qty: 2, address: 'Fort, Thrissur', status: 'In Transit' },
    { id: 'DL-003', item: 'Pepper Vines', qty: 3, address: 'Vyttila, Kochi', status: 'Pending' }
  ];

  const menuItems = [
    { id: 'deliveries', label: 'Deliveries', icon: Truck },
    { id: 'routes', label: 'Routes', icon: MapPin },
    { id: 'history', label: 'History', icon: CheckCircle },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  const renderDeliveries = () => (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div style={statCardStyle}>
          <Truck size={28} color="#0ea5e9" style={{ marginBottom: '0.5rem' }} />
          <h3 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>{stats.todayDeliveries}</h3>
          <p style={{ color: '#6b7280', margin: 0 }}>Today</p>
        </div>
        <div style={statCardStyle}>
          <Clock size={28} color="#f59e0b" style={{ marginBottom: '0.5rem' }} />
          <h3 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>{stats.pending}</h3>
          <p style={{ color: '#6b7280', margin: 0 }}>Pending</p>
        </div>
        <div style={statCardStyle}>
          <CheckCircle size={28} color="#10b981" style={{ marginBottom: '0.5rem' }} />
          <h3 style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>{stats.completed}</h3>
          <p style={{ color: '#6b7280', margin: 0 }}>Completed</p>
        </div>
      </div>

      <div style={cardStyle}>
        <h3 style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#1f2937', marginBottom: '1rem' }}>Assigned Deliveries</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {deliveriesList.map((d) => (
            <div key={d.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', border: '1px solid #e5e7eb', borderRadius: '10px', background: '#fff' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Package size={20} color="#0ea5e9" />
                <div>
                  <div style={{ fontWeight: 600, color: '#111827' }}>{d.item} <span style={{ color: '#6b7280' }}>x{d.qty}</span></div>
                  <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>{d.address}</div>
                </div>
              </div>
              <button style={{ padding: '0.5rem 0.75rem', borderRadius: '8px', border: '1px solid #e5e7eb', background: '#f9fafb', cursor: 'pointer' }}>{d.status}</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'deliveries':
        return renderDeliveries();
      case 'routes':
        return <div style={cardStyle}>Route planning coming soon.</div>;
      case 'history':
        return <div style={cardStyle}>History coming soon.</div>;
      case 'settings':
        return <div style={cardStyle}>Settings coming soon.</div>;
      default:
        return renderDeliveries();
    }
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      <div style={sidebarStyle}>
        <div style={{ marginBottom: '2rem', textAlign: 'center', position: 'relative', zIndex: 10 }}>
          <div style={{ width: '60px', height: '60px', background: 'rgba(255, 255, 255, 0.2)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1rem', backdropFilter: 'blur(16px)' }}>
            <Truck color="white" size={28} />
          </div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 'bold', margin: 0 }}>Delivery Dashboard</h1>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', zIndex: 10 }}>
          {menuItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.75rem 1rem',
                borderRadius: '10px',
                border: 'none',
                background: activeTab === item.id ? 'rgba(255, 255, 255, 0.2)' : 'transparent',
                color: 'white',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              <item.icon size={18} /> {item.label}
            </button>
          ))}
        </div>

        <div style={{ marginTop: 'auto', zIndex: 10 }}>
          <button onClick={handleLogout} style={{ width: '100%', padding: '0.75rem 1rem', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.3)', background: 'rgba(255,255,255,0.1)', color: 'white', cursor: 'pointer' }}>
            <LogOut size={16} style={{ marginRight: '0.5rem' }} /> Logout
          </button>
        </div>
      </div>

      {/* Main content */}
      <div style={mainContentStyle}>{renderContent()}</div>
    </div>
  );
}