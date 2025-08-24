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

  // Regular email/password registration
  async register(userData) {
    try {
      const result = await this.firebaseAuth.registerWithEmailAndPassword(userData);
      if (result.success) {
        this.user = result.user;
      }
      return result;
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