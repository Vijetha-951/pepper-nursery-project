# Google OAuth Setup Guide for Thekkevayalil Pepper Nursery

## 📋 Setup Instructions

### 1. Create Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API and Google OAuth2 API
4. Go to "Credentials" in the left sidebar
5. Click "Create Credentials" > "OAuth 2.0 Client IDs"
6. Configure the consent screen if prompted
7. Set Application type to "Web application"
8. Add authorized redirect URIs:
   - `http://localhost:3000/auth/google/callback` (for development)
   - `https://your-domain.com/auth/google/callback` (for production)

### 2. Configure Environment Variables

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your Google OAuth credentials:
   ```
   REACT_APP_GOOGLE_CLIENT_ID=your-actual-google-client-id.apps.googleusercontent.com
   REACT_APP_API_URL=http://localhost:5000/api
   NODE_ENV=development
   ```

### 3. Backend Configuration (Optional - For Production)

For production, you'll need a backend API to handle the OAuth flow:

```javascript
// Example backend route (Node.js/Express)
app.post('/api/auth/google/callback', async (req, res) => {
  const { code } = req.body;
  
  try {
    // Exchange code for access token
    const { data } = await axios.post('https://oauth2.googleapis.com/token', {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    });

    // Get user info
    const { data: profile } = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${data.access_token}` },
    });

    // Create or update user in your database
    // Generate JWT token
    // Return user data and token
    
    res.json({
      success: true,
      user: profile,
      token: 'your-jwt-token'
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: 'Google authentication failed'
    });
  }
});
```

## 🚀 Current Implementation

The current implementation includes:

### ✅ **Login Page**
- Email/Password authentication
- Google Sign-In integration
- Form validation and error handling
- Responsive design with your botanical background

### ✅ **Registration Page**
- Complete registration form
- Google Sign-Up integration
- Role selection (User, Delivery Boy)
- Address fields for delivery

### ✅ **Dashboard**
- User overview with statistics
- Order management
- Profile management
- Role-specific features (delivery management for delivery boys)
- Sidebar navigation

### ✅ **Complete Profile Page**
- For Google OAuth users who need to complete their profile
- Address and phone number collection
- Role selection

### ✅ **Authentication Service**
- Centralized auth management
- Token storage
- User session handling
- Google OAuth integration

## 🔧 Features

### **Authentication Flow:**

1. **Login Options:**
   - Email/Password
   - Google Sign-In

2. **Registration Options:**
   - Full form registration
   - Google Sign-Up (with profile completion)

3. **User Roles:**
   - User (regular customers)
   - Delivery Boy (delivery personnel)

4. **Post-Authentication:**
   - Dashboard with personalized content
   - Profile management
   - Order tracking
   - Role-specific features

### **Security Features:**
- JWT token management
- Protected routes
- Session persistence
- Secure logout

## 📱 Pages Overview

### **Public Pages:**
- `/` - Home page with navbar
- `/add-products` - Product management
- `/login` - Sign in page
- `/register` - Registration page

### **Authentication Pages:**
- `/auth/google/callback` - OAuth callback handler
- `/complete-profile` - Profile completion for Google users

### **Protected Pages:**
- `/dashboard` - User dashboard

## 🎨 Design Features

- **Beautiful botanical background** from your assets
- **Split-screen layout** for auth pages
- **Responsive design** for all devices
- **Modern UI components** with hover effects
- **Loading states** and error handling
- **Professional pepper nursery branding**

## 🔄 Current Status

The application is currently set up with **mock authentication** for demonstration purposes. The Google OAuth buttons will:

1. Simulate the OAuth flow
2. Create mock user data
3. Redirect to appropriate pages
4. Store session data

To enable **real Google OAuth**, update the `authService.js` file to use actual Google OAuth URLs and handle real authentication responses.

## 📞 Support

For any issues with the Google OAuth setup, please check:
1. Google Cloud Console configuration
2. Environment variables
3. Redirect URI configuration
4. API enablement status

Your **Thekkevayalil Pepper Nursery** is now ready for Google OAuth integration! 🌱