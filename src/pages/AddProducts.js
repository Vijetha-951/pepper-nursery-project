import { useState } from "react";

export default function AddProducts() {
  const [products, setProducts] = useState([]);
  const [name, setName] = useState("");
  const [price, setPrice] = useState("");

  const handleAdd = () => {
    if (name && price) {
      setProducts([...products, { name, price }]);
      setName("");
      setPrice("");
    }
  };

  return (
    <div style={{ padding: "2rem" }}>
      <h1>Add Products</h1>
      <input
        type="text"
        placeholder="Product name"
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <input
        type="number"
        placeholder="Price"
        value={price}
        onChange={(e) => setPrice(e.target.value)}
      />
      <button onClick={handleAdd}>Add</button>

      <h2>Product List</h2>
      <ul>
        {products.map((p, index) => (
          <li key={index}>{p.name} - ₹{p.price}</li>
        ))}
      </ul>
    </div>
  );
}
