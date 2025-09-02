import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Home from "./pages/Home";
import AddProducts from "./pages/AddProducts";
import Login from "./pages/Login";
import Register from "./pages/Register";
import RoleBasedDashboard from "./pages/RoleBasedDashboard";
import CompleteProfile from "./pages/CompleteProfile";
import AuthCallback from "./pages/AuthCallback";

function App() {
  return (
    <Router>
      <Routes>
        {/* Public routes with navbar */}
        <Route path="/" element={
          <>
            <Navbar />
            <Home />
          </>
        } />
        <Route path="/add-products" element={
          <>
            <Navbar />
            <AddProducts />
          </>
        } />
        
        {/* Authentication routes without navbar */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/complete-profile" element={<CompleteProfile />} />
        <Route path="/auth/google/callback" element={<AuthCallback />} />
        
        {/* Protected routes without navbar */}
        <Route path="/dashboard" element={<RoleBasedDashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
