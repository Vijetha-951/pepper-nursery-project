import React from "react";
import "./Home.css";

// Import images from assets
import logo from "../assets/logo.png";
import pepper1 from "../assets/pepper1.jpg";
import pepper2 from "../assets/pepper2.jpg";
import pepper3 from "../assets/pepper3.jpg";
import pepper4 from "../assets/pepper4.jpg";

export default function Home() {
  return (
    <div className="home-container">
      {/* Hero Section */}
      <section
        className="hero"
        style={{ backgroundImage: `url(${pepper1})` }}
      >
        <div className="overlay">
          <img src={logo} alt="Pepper Logo" className="logo" />
          <h1>Welcome to Pepper Nursery</h1>
          <p>Fresh seedlings delivered to your doorstep</p>
          <a href="/shop" className="cta-btn">Shop Now</a>
        </div>
      </section>

      {/* Gallery Section */}
      <section className="gallery">
        <h2>Our Pepper Varieties</h2>
        <div className="gallery-grid">
          <img src={pepper1} alt="Pepper Variety 1" />
          <img src={pepper2} alt="Pepper Variety 2" />
          <img src={pepper3} alt="Pepper Variety 3" />
          <img src={pepper4} alt="Pepper Variety 4" />
        </div>
      </section>
    </div>
  );
}
