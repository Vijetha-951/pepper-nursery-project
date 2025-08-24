# Firebase Google Authentication Setup Guide

This guide will help you set up Firebase authentication with Google Sign-In for your React application.

## Prerequisites

- Google Cloud Console account
- Firebase project
- React application

## Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project"
3. Enter project name (e.g., "pepper-nursery")
4. Enable Google Analytics (optional)
5. Click "Create project"

## Step 2: Enable Authentication

1. In your Firebase project console, click "Authentication"
2. Go to "Sign-in method" tab
3. Click "Google" from the list of providers
4. Toggle "Enable" on
5. Set your project support email
6. Click "Save"

## Step 3: Create Web App

1. In the Firebase console, click the gear icon (⚙️) next to "Project Overview"
2. Click "Project settings"
3. Scroll down to "Your apps" section
4. Click the web icon `</>`
5. Enter app nickname (e.g., "pepper-frontend")
6. Check "Also set up Firebase Hosting" (optional)
7. Click "Register app"
8. Copy the Firebase configuration object

## Step 4: Configure Environment Variables

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Update `.env` with your Firebase configuration:
   ```env
   # Firebase Configuration
   REACT_APP_FIREBASE_API_KEY=your-api-key-here
   REACT_APP_FIREBASE_AUTH_DOMAIN=your-project-id.firebaseapp.com
   REACT_APP_FIREBASE_PROJECT_ID=your-project-id
   REACT_APP_FIREBASE_STORAGE_BUCKET=your-project-id.appspot.com
   REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
   REACT_APP_FIREBASE_APP_ID=your-app-id
   REACT_APP_FIREBASE_MEASUREMENT_ID=your-measurement-id
   ```

## Step 5: Set Up Firestore Database

1. In Firebase console, go to "Firestore Database"
2. Click "Create database"
3. Choose "Start in test mode" (for development)
4. Select your preferred location
5. Click "Done"

### Firestore Security Rules (for development):
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Allow users to read/write their own user document
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Allow authenticated users to read/write products
    match /products/{document=**} {
      allow read: if true;  // Public read
      allow write: if request.auth != null;  // Authenticated write
    }
  }
}
```

## Step 6: Configure Google Cloud Console

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your Firebase project
3. Go to "APIs & Services" > "Credentials"
4. Find your OAuth 2.0 client ID (created by Firebase)
5. Click edit (pencil icon)
6. Add authorized JavaScript origins:
   - `http://localhost:3000` (for development)
   - `https://yourdomain.com` (for production)
7. Add authorized redirect URIs:
   - `http://localhost:3000` (for development)
   - `https://yourdomain.com` (for production)
8. Click "Save"

## Step 7: Test the Integration

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm start
   ```

3. Navigate to the register page
4. Click "Sign up with Google"
5. Complete the authentication flow

## Features Included

### 🔐 Authentication Features
- ✅ Google Sign-Up with popup
- ✅ Email/Password registration
- ✅ Email/Password login
- ✅ User profile management
- ✅ Auth state persistence
- ✅ Protected routes

### 📊 Firestore Integration
- ✅ User profiles stored in Firestore
- ✅ Automatic profile creation on Google sign-up
- ✅ Profile completion flow for new Google users
- ✅ Real-time data synchronization

### 🎨 UI/UX Features
- ✅ Loading states for Google authentication
- ✅ Error handling and user feedback
- ✅ Success messages
- ✅ Responsive design
- ✅ Form validation

## File Structure

```
src/
├── config/
│   ├── firebase.js          # Firebase configuration
│   └── googleConfig.js      # Legacy Google config
├── services/
│   ├── firebaseAuthService.js # Firebase auth service
│   └── authService.js        # Main auth service (wrapper)
├── pages/
│   ├── Register.js          # Registration page with Google signup
│   ├── Login.js             # Login page
│   ├── CompleteProfile.js   # Profile completion for new users
│   └── Dashboard.js         # Protected dashboard
└── components/
    └── ProtectedRoute.js    # Route protection component
```

## User Flow

### New Google User:
1. Click "Sign up with Google" → Google popup opens
2. Complete Google authentication → Profile partially created
3. Redirect to CompleteProfile page → Fill additional details
4. Submit profile → Redirect to Dashboard

### Existing Google User:
1. Click "Sign in with Google" → Google popup opens
2. Complete Google authentication → Existing profile loaded
3. Redirect to Dashboard

### Email/Password User:
1. Fill registration form → Submit
2. Account created with all details → Redirect to Dashboard

## Firestore Data Structure

### Users Collection (`/users/{uid}`)
```javascript
{
  uid: "firebase-user-id",
  email: "user@example.com",
  firstName: "John",
  lastName: "Doe",
  phone: "+1234567890",
  role: "user",
  place: "City Name",
  district: "District Name",
  pincode: "123456",
  provider: "google" | "email",
  displayName: "John Doe",
  photoURL: "https://...",
  emailVerified: true,
  isNewUser: false,
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lastLogin: Timestamp
}
```

## Security Considerations

### For Production:
1. Update Firestore security rules to be more restrictive
2. Enable App Check for additional security
3. Set up proper CORS policies
4. Use environment-specific Firebase projects
5. Enable Firebase Security Rules testing

### Firestore Production Rules:
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only access their own data
    match /users/{userId} {
      allow read, write: if request.auth != null 
        && request.auth.uid == userId
        && request.auth.token.email_verified == true;
    }
    
    // Products: authenticated read, admin write
    match /products/{productId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null 
        && get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }
  }
}
```

## Troubleshooting

### Common Issues:

1. **"Auth domain not configured"**
   - Check `REACT_APP_FIREBASE_AUTH_DOMAIN` in `.env`
   - Ensure domain is added in Firebase Authentication settings

2. **"Popup blocked by browser"**
   - Allow popups for localhost/your domain
   - Consider using redirect method instead of popup

3. **"Invalid redirect URI"**
   - Check Google Cloud Console OAuth settings
   - Ensure redirect URIs match your application URLs

4. **"User not found in Firestore"**
   - Check Firestore security rules
   - Ensure user document creation is working

5. **"Firebase not initialized"**
   - Check all environment variables are set
   - Verify Firebase configuration object

### Debug Tips:
- Check browser console for detailed error messages
- Use Firebase Auth emulator for local testing
- Monitor Firestore usage in Firebase console
- Test with different Google accounts

## Next Steps

1. **Add more authentication providers** (Facebook, Twitter, etc.)
2. **Implement email verification** for email/password users
3. **Add password reset functionality**
4. **Set up Firebase Cloud Functions** for server-side logic
5. **Implement role-based access control**
6. **Add user profile image upload** with Firebase Storage
7. **Set up Firebase Analytics** for user insights

## Support

If you encounter any issues:
1. Check the [Firebase Documentation](https://firebase.google.com/docs)
2. Review the [React Firebase Hooks](https://github.com/CSFrequency/react-firebase-hooks)
3. Check the browser console for error messages
4. Verify all environment variables are properly set