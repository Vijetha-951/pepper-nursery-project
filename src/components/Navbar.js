import { Link } from "react-router-dom";
import "./Navbar.css";

export default function Navbar() {
  return (
    <nav className="navbar">
      <h2 className="logo">Pepper Nursery</h2>
      <ul>
        <li><Link to="/">Home</Link></li>
        <li><Link to="/add-products">Add Products</Link></li>
        <li><Link to="/login">Login</Link></li>
        <li><Link to="/register">Register</Link></li>
      </ul>
    </nav>
  );
}
