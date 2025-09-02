import firebaseAuthService from './firebaseAuthService';

class AuthService {
  constructor() {
    this.firebaseAuth = firebaseAuthService;
    this.user = this.firebaseAuth.getStoredUserData();
  }

  // Regular email/password login
  async login(formData) {
    try {
      // Support both object (formData) and separate parameters (email, password)
      const email = formData.email || formData;
      const password = formData.password || arguments[1];
      
      const result = await this.firebaseAuth.signInWithEmailAndPassword(email, password);
      if (result.success) {
        this.user = result.user;
      }
      return result;
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: 'Network error. Please try again.' };
    }
  }

  // Regular email/password registration (Hybrid: Firebase first, then backend)
  async register(userData) {
    try {
      // 1) Create user in Firebase (Auth + Firestore)
      const firebaseResult = await this.firebaseAuth.registerWithEmailAndPassword(userData);
      if (!firebaseResult.success) {
        return firebaseResult; // return Firebase validation/auth errors to UI
      }

      // 2) Create backend session + user record using Firebase ID token
      const firebaseUser = this.firebaseAuth.getCurrentUser();
      const idToken = firebaseUser ? await firebaseUser.getIdToken(true) : null;

      if (idToken) {
        const resp = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            idToken,
            role: userData.role,
            phone: userData.phone,
            place: userData.place,
            district: userData.district,
            pincode: userData.pincode
          })
        });

        // If backend responds but not ok, log and continue (Firebase already succeeded)
        if (!resp.ok) {
          let data = null;
          try { data = await resp.json(); } catch (_) {}
          console.warn('Backend registration non-OK:', data);
        }

        // Optional: read backend data if needed
        // const data = await resp.json();
      }

      // 3) Persist minimal user context (already set by firebaseAuth service)
      this.user = firebaseResult.user;
      return firebaseResult;
    } catch (error) {
      console.error('Registration error:', error);
      return { success: false, error: 'Network error. Please try again.' };
    }
  }

  // Google OAuth Sign In
  async googleSignIn() {
    try {
      const result = await this.firebaseAuth.signInWithGoogle();
      if (result.success) {
        this.user = result.user;
      }
      return result;
    } catch (error) {
      console.error('Google Sign In error:', error);
      return { success: false, error: 'Google Sign In failed. Please try again.' };
    }
  }

  // Google OAuth Sign Up
  async googleSignUp() {
    try {
      const result = await this.firebaseAuth.signUpWithGoogle();
      if (result.success) {
        this.user = result.user;
      }
      return result;
    } catch (error) {
      console.error('Google Sign Up error:', error);
      return { success: false, error: 'Google Sign Up failed. Please try again.' };
    }
  }

  // Logout
  async logout() {
    try {
      const result = await this.firebaseAuth.signOut();
      if (result.success) {
        this.user = null;
      }
      return result;
    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: 'Logout failed. Please try again.' };
    }
  }

  // Check if user is authenticated
  isAuthenticated() {
    return this.firebaseAuth.isAuthenticated() && !!this.user;
  }

  // Get current user
  getCurrentUser() {
    return this.user || this.firebaseAuth.getStoredUserData();
  }

  // Get Firebase user
  getFirebaseUser() {
    return this.firebaseAuth.getCurrentUser();
  }

  // Update user profile
  async updateProfile(updateData) {
    try {
      const result = await this.firebaseAuth.updateUserProfile(updateData);
      if (result.success) {
        this.user = result.user;
      }
      return result;
    } catch (error) {
      console.error('Profile update error:', error);
      return { success: false, error: 'Network error. Please try again.' };
    }
  }

  // Set auth state change listener
  onAuthStateChange(callback) {
    this.firebaseAuth.onAuthStateChange(callback);
  }
}

export default new AuthService();