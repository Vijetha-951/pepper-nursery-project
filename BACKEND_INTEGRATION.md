# Backend Integration Guide (Optional)

This guide shows how to integrate your Firebase frontend with a custom backend API if needed. **Note: This is optional since Firebase handles authentication and database operations directly.**

## Why You Might Need a Backend

- Complex business logic
- Integration with third-party services
- Advanced data processing
- Custom API endpoints
- Server-side validation
- Payment processing
- Email notifications

## Backend Setup Example (Node.js + Express)

### 1. Install Dependencies

```bash
npm init -y
npm install express firebase-admin cors dotenv
npm install -D nodemon
```

### 2. Firebase Admin Setup

Create `config/firebase-admin.js`:

```javascript
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
const serviceAccount = require('../path/to/your/service-account-key.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com`
});

const db = admin.firestore();
const auth = admin.auth();

module.exports = { admin, db, auth };
```

### 3. Authentication Middleware

Create `middleware/authMiddleware.js`:

```javascript
const { auth } = require('../config/firebase-admin');

const authenticateToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer token
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decodedToken = await auth.verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

module.exports = { authenticateToken };
```

### 4. User Routes

Create `routes/users.js`:

```javascript
const express = require('express');
const { db } = require('../config/firebase-admin');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: userDoc.data() });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Update user profile
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone, place, district, pincode } = req.body;
    
    const updateData = {
      firstName,
      lastName,
      phone,
      place,
      district,
      pincode,
      updatedAt: new Date()
    };

    await db.collection('users').doc(req.user.uid).update(updateData);
    
    const updatedDoc = await db.collection('users').doc(req.user.uid).get();
    
    res.json({ 
      message: 'Profile updated successfully',
      user: updatedDoc.data()
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Delete user account
router.delete('/account', authenticateToken, async (req, res) => {
  try {
    // Delete user document from Firestore
    await db.collection('users').doc(req.user.uid).delete();
    
    // Delete user from Firebase Auth
    await auth.deleteUser(req.user.uid);
    
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

module.exports = router;
```

### 5. Product Routes

Create `routes/products.js`:

```javascript
const express = require('express');
const { db } = require('../config/firebase-admin');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

// Get all products
router.get('/', async (req, res) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    const products = [];
    
    productsSnapshot.forEach(doc => {
      products.push({ id: doc.id, ...doc.data() });
    });
    
    res.json({ products });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: 'Failed to get products' });
  }
});

// Create product (admin only)
router.post('/', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const productData = {
      ...req.body,
      createdBy: req.user.uid,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const docRef = await db.collection('products').add(productData);
    
    res.status(201).json({ 
      message: 'Product created successfully',
      productId: docRef.id
    });
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

module.exports = router;
```

### 6. Main Server File

Create `server.js`:

```javascript
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const userRoutes = require('./routes/users');
const productRoutes = require('./routes/products');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Routes
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### 7. Environment Variables

Create `.env`:

```env
NODE_ENV=development
PORT=5000
FRONTEND_URL=http://localhost:3000
FIREBASE_PROJECT_ID=your-project-id
```

### 8. Package.json Scripts

```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  }
}
```

## Frontend Integration

Update your `firebaseAuthService.js` to optionally sync with backend:

```javascript
// Add this method to firebaseAuthService.js
async syncWithBackend(idToken) {
  try {
    const response = await fetch(`${process.env.REACT_APP_API_URL}/users/profile`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${idToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const data = await response.json();
      return { success: true, user: data.user };
    } else {
      return { success: false, error: 'Failed to sync with backend' };
    }
  } catch (error) {
    console.error('Backend sync error:', error);
    return { success: false, error: 'Backend sync failed' };
  }
}
```

## API Endpoints

### User Endpoints
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `DELETE /api/users/account` - Delete user account

### Product Endpoints
- `GET /api/products` - Get all products
- `POST /api/products` - Create product (admin only)
- `PUT /api/products/:id` - Update product (admin only)
- `DELETE /api/products/:id` - Delete product (admin only)

### Authentication
All protected endpoints require a Firebase ID token in the Authorization header:
```
Authorization: Bearer <firebase-id-token>
```

## Getting Firebase ID Token

In your React app:

```javascript
import { auth } from '../config/firebase';

const getIdToken = async () => {
  const user = auth.currentUser;
  if (user) {
    return await user.getIdToken();
  }
  return null;
};

// Use in API calls
const idToken = await getIdToken();
const response = await fetch('/api/users/profile', {
  headers: {
    'Authorization': `Bearer ${idToken}`
  }
});
```

## Database Schema Examples

### Users Collection
```javascript
{
  uid: "firebase-user-id",
  email: "user@example.com",
  firstName: "John",
  lastName: "Doe",
  phone: "+1234567890",
  role: "user", // or "admin"
  place: "City",
  district: "District",
  pincode: "123456",
  provider: "google",
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

### Products Collection
```javascript
{
  name: "Black Pepper Plant",
  description: "High quality pepper plant",
  price: 299.99,
  category: "plants",
  inStock: true,
  quantity: 50,
  images: ["url1", "url2"],
  createdBy: "admin-uid",
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

## Deployment

### Backend Deployment (Railway/Heroku):
1. Add service account key securely
2. Set environment variables
3. Deploy with Git

### Environment Variables for Production:
```env
NODE_ENV=production
PORT=5000
FRONTEND_URL=https://your-domain.com
FIREBASE_PROJECT_ID=your-project-id
```

## Security Best Practices

1. **Always verify Firebase tokens** on the backend
2. **Use HTTPS** in production
3. **Implement rate limiting**
4. **Validate input data**
5. **Use environment variables** for sensitive data
6. **Implement proper error handling**
7. **Add request logging**
8. **Use CORS appropriately**

## When to Skip Backend

You can skip the backend if you only need:
- User authentication
- Basic CRUD operations
- Real-time data sync
- File uploads
- Simple user profiles

Firebase handles all of this directly from the frontend!

## Conclusion

The Firebase-only approach is simpler and sufficient for most applications. Only add a backend when you need complex server-side logic or integrations that Firebase cannot handle directly.