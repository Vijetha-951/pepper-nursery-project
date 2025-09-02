import { useEffect, useState } from "react";
import authService from "../services/authService";
import Dashboard from "./Dashboard";
import DeliveryDashboard from "./DeliveryDashboard";

export default function RoleBasedDashboard() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const u = authService.getCurrentUser();
    if (!u) {
      window.location.href = '/login';
      return;
    }
    setUser(u);
    setLoading(false);
  }, []);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f9fafb' }}>
        <div style={{ width: '3rem', height: '3rem', border: '4px solid #10b981', borderTop: '4px solid transparent', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
      </div>
    );
  }

  if (!user) return null;

  return user.role === 'deliveryboy' ? <DeliveryDashboard /> : <Dashboard />;
}