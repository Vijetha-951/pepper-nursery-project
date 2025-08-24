# 🌶️ Pepper Nursery Frontend

A modern React-based web application for **Thekkevayalil Pepper Nursery** featuring Firebase authentication, user management, and product catalog functionality.

## 🚀 Features

### **Authentication System**
- ✅ **Google OAuth 2.0** - Sign in with Google
- ✅ **Email/Password Authentication** - Traditional login system
- ✅ **User Profile Management** - Complete profile system
- ✅ **Role-Based Access Control** - User roles and permissions
- ✅ **Auto Profile Completion** - Smart user onboarding

### **Core Features**
- 🏠 **Landing Page** - Elegant homepage with nursery information
- 📱 **Responsive Design** - Mobile-first responsive UI
- 🔐 **Protected Routes** - Secure navigation system
- 📊 **Dashboard** - User-specific dashboard
- 🛡️ **Error Handling** - Comprehensive error management
- ⚡ **Real-time Updates** - Firebase real-time data sync

## 🛠️ Technology Stack

- **Frontend**: React 18, React Router v6
- **Authentication**: Firebase Auth
- **Database**: Cloud Firestore
- **Styling**: CSS3, Inline Styles
- **Icons**: Lucide React
- **Deployment**: Firebase Hosting Ready

## 📋 Prerequisites

- **Node.js** (v14 or higher)
- **npm** or **yarn**
- **Firebase Project** (with Auth & Firestore enabled)
- **Google Cloud Console** (OAuth configured)

## ⚙️ Installation & Setup

### **1. Clone Repository**
```bash
git clone https://github.com/Vijetha-951/pepper-nursery-project.git
cd pepper-nursery-project
```

### **2. Install Dependencies**
```bash
npm install
```

### **3. Environment Configuration**
1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Update `.env` with your Firebase configuration:
   ```env
   # Firebase Configuration
   REACT_APP_FIREBASE_API_KEY=your-firebase-api-key
   REACT_APP_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
   REACT_APP_FIREBASE_PROJECT_ID=your-project-id
   REACT_APP_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
   REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
   REACT_APP_FIREBASE_APP_ID=your-app-id
   REACT_APP_FIREBASE_MEASUREMENT_ID=your-measurement-id
   
   # Google OAuth
   REACT_APP_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
   
   # API Configuration
   REACT_APP_API_URL=http://localhost:5000/api
   ```

### **4. Firebase Setup**
1. **Create Firebase Project**: https://console.firebase.google.com/
2. **Enable Authentication**:
   - Go to Authentication → Sign-in method
   - Enable Google & Email/Password providers
3. **Create Firestore Database**:
   - Go to Firestore Database → Create database
   - Start in test mode
4. **Register Web App**:
   - Project settings → Your apps → Add web app
   - Copy configuration to `.env`

### **5. Google OAuth Setup**
1. **Google Cloud Console**: https://console.cloud.google.com/
2. **Create OAuth Client**:
   - APIs & Services → Credentials
   - Create OAuth 2.0 Client ID
   - Add authorized origins: `http://localhost:3000`
   - Add redirect URIs: `http://localhost:3000`

### **6. Start Development Server**
```bash
npm start
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

## 📁 Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── Navbar.js       # Navigation component
│   ├── ProtectedRoute.js # Route protection
│   └── GoogleOAuthStatus.js # OAuth status
├── pages/              # Application pages
│   ├── Home.js         # Landing page
│   ├── Login.js        # Login page
│   ├── Register.js     # Registration page
│   ├── Dashboard.js    # User dashboard
│   ├── CompleteProfile.js # Profile completion
│   └── AddProducts.js  # Product management
├── services/           # External services
│   ├── authService.js  # Authentication wrapper
│   └── firebaseAuthService.js # Firebase auth
├── config/             # Configuration files
│   ├── firebase.js     # Firebase config
│   └── googleConfig.js # Google OAuth config
├── assets/             # Static assets
└── App.js              # Main application component
```

## 🔐 Authentication Flow

### **New User Registration**
```
Register Page → Fill Form/Google → Profile Complete → Dashboard
```

### **Existing User Login**
```
Login Page → Credentials/Google → Dashboard
```

### **Google OAuth Flow**
```
Click Google → Popup → Authentication → Profile/Dashboard
```

## 🧪 Available Scripts

### **Development**
```bash
npm start          # Start development server
npm test           # Run tests
npm run build      # Create production build
```

### **Deployment**
```bash
npm run build      # Build for production
# Upload build/ folder to your hosting service
```

## 🔧 Firebase Configuration

### **Firestore Security Rules**
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can read/write their own profile
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Products - public read, authenticated write
    match /products/{document=**} {
      allow read: if true;
      allow write: if request.auth != null;
    }
  }
}
```

### **Authentication Providers**
- ✅ **Google** - OAuth 2.0 integration
- ✅ **Email/Password** - Traditional authentication

## 🌐 Deployment

### **Firebase Hosting** (Recommended)
```bash
npm install -g firebase-tools
firebase login
firebase init hosting
npm run build
firebase deploy
```

### **Other Hosting Options**
- Vercel, Netlify, GitHub Pages
- Upload `build/` folder contents

## 🐛 Troubleshooting

### **Common Issues**

#### **"Popup blocked" Error**
- **Solution**: Allow popups for localhost/your domain
- **Alternative**: Use redirect authentication method

#### **"This app isn't verified" Warning**
- **Solution**: Normal in development - click "Advanced" → "Go to app"
- **Production**: Submit for Google verification

#### **Firebase Config Errors**
- **Check**: All environment variables are set correctly
- **Fix**: Restart development server after `.env` changes

#### **Authentication Fails**
- **Verify**: Google OAuth origins and redirect URIs
- **Check**: Firebase Authentication providers are enabled

## 📊 User Data Structure

### **User Profile (Firestore)**
```javascript
{
  uid: "firebase-user-id",
  email: "user@example.com",
  firstName: "John",
  lastName: "Doe", 
  phone: "+1234567890",
  role: "user",
  place: "City",
  district: "District",
  pincode: "123456",
  provider: "google" | "email",
  displayName: "John Doe",
  photoURL: "https://...",
  emailVerified: true,
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/new-feature`
3. **Commit changes**: `git commit -m 'Add new feature'`
4. **Push to branch**: `git push origin feature/new-feature`
5. **Create Pull Request**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team

- **Frontend Development**: React, Firebase Integration
- **Authentication**: Google OAuth, Firebase Auth  
- **Database**: Cloud Firestore
- **UI/UX**: Responsive Design, Modern Interface

## 📞 Support

For support and questions:
- **Issues**: Create GitHub issue
- **Email**: Contact repository maintainer
- **Documentation**: Check setup guides in `/docs`

## 🎯 Roadmap

- [ ] Product catalog implementation
- [ ] Shopping cart functionality  
- [ ] Order management system
- [ ] Admin dashboard
- [ ] Payment integration
- [ ] Mobile app development

---

**Built with ❤️ for Thekkevayalil Pepper Nursery**