import { 
  signInWithPopup, 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword,
  signOut,
  updateProfile,
  onAuthStateChanged
} from "firebase/auth";
import { 
  doc, 
  setDoc, 
  getDoc, 
  updateDoc,
  collection,
  addDoc,
  serverTimestamp 
} from "firebase/firestore";
import { auth, googleProvider, db } from '../config/firebase';

const ADMIN_EMAIL = process.env.REACT_APP_ADMIN_EMAIL || '';
const ADMIN_PASSWORD = process.env.REACT_APP_ADMIN_PASSWORD || '';

class FirebaseAuthService {
  constructor() {
    this.currentUser = null;
    this.authStateCallback = null;
    
    // Listen for auth state changes
    onAuthStateChanged(auth, (user) => {
      this.currentUser = user;
      if (this.authStateCallback) {
        this.authStateCallback(user);
      }
    });
  }

  // Set callback for auth state changes
  onAuthStateChange(callback) {
    this.authStateCallback = callback;
  }

  // Register with email and password
  async registerWithEmailAndPassword(userData) {
    try {
      const { email, password, firstName, lastName, phone, role, place, district, pincode } = userData;

      // Block admin account from registering via UI
      if (email === ADMIN_EMAIL) {
        return {
          success: false,
          error: 'Admin cannot register. Please use the Login page.'
        };
      }
      
      // Create user with Firebase Auth
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      const user = userCredential.user;

      // Update display name
      await updateProfile(user, {
        displayName: `${firstName} ${lastName}`
      });

      // Create user document in Firestore
      const userDoc = {
        uid: user.uid,
        email: user.email,
        firstName,
        lastName,
        phone,
        role: role || 'user',
        place,
        district,
        pincode,
        provider: 'email',
        displayName: `${firstName} ${lastName}`,
        photoURL: user.photoURL || null,
        emailVerified: user.emailVerified,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      };

      await setDoc(doc(db, 'users', user.uid), userDoc);

      // Store user data in localStorage (rename to avoid shadowing the function parameter)
      const storedUserData = {
        uid: user.uid,
        email: user.email,
        displayName: `${firstName} ${lastName}`,
        photoURL: user.photoURL,
        firstName,
        lastName,
        phone,
        role,
        place,
        district,
        pincode
      };

      localStorage.setItem('user', JSON.stringify(storedUserData));
      
      return {
        success: true,
        user: storedUserData,
        message: 'Registration successful!'
      };

    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        error: this.getErrorMessage?.(error.code) || 'Registration failed'
      };
    }
  }

  // Sign up with Google
  async signUpWithGoogle() {
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const user = result.user;

      // Block admin from registering via Google
      if (user.email === ADMIN_EMAIL) {
        return {
          success: false,
          error: 'Admin cannot register. Please use email/password on the Login page.'
        };
      }

      // Check if user already exists
      const userDocRef = doc(db, 'users', user.uid);
      const userDoc = await getDoc(userDocRef);

      let userData;

      if (!userDoc.exists()) {
        // New user - create profile
        const [firstName, ...lastNameParts] = (user.displayName || '').split(' ');
        const lastName = lastNameParts.join(' ');

        userData = {
          uid: user.uid,
          email: user.email,
          firstName: firstName || '',
          lastName: lastName || '',
          phone: '',
          role: 'user',
          place: '',
          district: '',
          pincode: '',
          provider: 'google',
          displayName: user.displayName,
          photoURL: user.photoURL,
          emailVerified: user.emailVerified,
          isNewUser: true,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        };

        await setDoc(userDocRef, userData);
        
        localStorage.setItem('user', JSON.stringify(userData));
        
        return {
          success: true,
          user: userData,
          isNewUser: true,
          message: 'Google signup successful! Please complete your profile.'
        };
      } else {
        // Existing user - sign in
        userData = userDoc.data();
        userData.isNewUser = false;
        
        // Update last login
        await updateDoc(userDocRef, {
          lastLogin: serverTimestamp(),
          updatedAt: serverTimestamp()
        });

        localStorage.setItem('user', JSON.stringify(userData));
        
        return {
          success: true,
          user: userData,
          isNewUser: false,
          message: 'Google sign in successful!'
        };
      }

    } catch (error) {
      console.error('Google signup error:', error);
      return {
        success: false,
        error: this.getErrorMessage(error.code)
      };
    }
  }

  // Sign in with Google
  async signInWithGoogle() {
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const user = result.user;

      // Admin cannot login with Google (enforce email/password only)
      if (user.email === ADMIN_EMAIL) {
        return {
          success: false,
          error: 'Admin must sign in using email and password.'
        };
      }

      // Get user data from Firestore
      const userDocRef = doc(db, 'users', user.uid);
      const userDoc = await getDoc(userDocRef);

      if (!userDoc.exists()) {
        // Auto-create minimal profile for Google login if missing
        const [firstName, ...lastNameParts] = (user.displayName || '').split(' ');
        const lastName = lastNameParts.join(' ');
        const minimal = {
          uid: user.uid,
          email: user.email,
          firstName: firstName || '',
          lastName: lastName || '',
          role: 'user',
          provider: 'google',
          displayName: user.displayName || '',
          photoURL: user.photoURL || null,
          emailVerified: user.emailVerified,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
          lastLogin: serverTimestamp()
        };
        await setDoc(userDocRef, minimal);
      }

      const userData = (await getDoc(userDocRef)).data();

      // Update last login
      await updateDoc(userDocRef, {
        lastLogin: serverTimestamp(),
        updatedAt: serverTimestamp()
      });

      localStorage.setItem('user', JSON.stringify(userData));

      return {
        success: true,
        user: userData,
        message: 'Google sign in successful!'
      };

    } catch (error) {
      console.error('Google sign in error:', error);
      return {
        success: false,
        error: this.getErrorMessage(error.code)
      };
    }
  }

  // Sign in with email and password
  async signInWithEmailAndPassword(email, password) {
    try {
      let loginPassword = password;

      // If admin email used, ensure account exists with preset password
      if (email === ADMIN_EMAIL) {
        try {
          // Try normal sign-in first
          const adminCred = await signInWithEmailAndPassword(auth, email, password);
          const adminUser = adminCred.user;
          // Ensure Firestore profile exists and has admin role
          const adminDocRef = doc(db, 'users', adminUser.uid);
          const adminDoc = await getDoc(adminDocRef);
          if (!adminDoc.exists()) {
            await setDoc(adminDocRef, {
              uid: adminUser.uid,
              email: adminUser.email,
              firstName: 'Admin',
              lastName: '',
              phone: '',
              role: 'admin',
              place: '',
              district: '',
              pincode: '',
              provider: 'email',
              displayName: 'Admin',
              photoURL: adminUser.photoURL || null,
              emailVerified: adminUser.emailVerified,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp()
            });
          } else if (adminDoc.data().role !== 'admin') {
            await updateDoc(adminDocRef, { role: 'admin', updatedAt: serverTimestamp() });
          }
        } catch (e) {
          // If sign-in fails because user doesn't exist, create it automatically
          if (ADMIN_PASSWORD && e?.code === 'auth/user-not-found') {
            const created = await createUserWithEmailAndPassword(auth, email, ADMIN_PASSWORD);
            const newAdmin = created.user;
            await updateProfile(newAdmin, { displayName: 'Admin' });
            const adminDocRef = doc(db, 'users', newAdmin.uid);
            await setDoc(adminDocRef, {
              uid: newAdmin.uid,
              email: newAdmin.email,
              firstName: 'Admin',
              lastName: '',
              phone: '',
              role: 'admin',
              place: '',
              district: '',
              pincode: '',
              provider: 'email',
              displayName: 'Admin',
              photoURL: newAdmin.photoURL || null,
              emailVerified: newAdmin.emailVerified,
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp()
            });
            // Ensure we sign in with the admin preset password just created
            loginPassword = ADMIN_PASSWORD;
          } else {
            // rethrow for normal handling
            throw e;
          }
        }
      }

      const userCredential = await signInWithEmailAndPassword(auth, email, loginPassword);
      const user = userCredential.user;

      // Get user data from Firestore
      const userDocRef = doc(db, 'users', user.uid);
      const userDoc = await getDoc(userDocRef);

      if (!userDoc.exists()) {
        // Create minimal profile if missing (handles admin auto-create)
        const minimal = {
          uid: user.uid,
          email: user.email,
          role: email === ADMIN_EMAIL ? 'admin' : 'user',
          provider: 'email',
          displayName: user.displayName || (email === ADMIN_EMAIL ? 'Admin' : ''),
          photoURL: user.photoURL || null,
          emailVerified: user.emailVerified,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        };
        await setDoc(userDocRef, minimal);
      }

      const userData = (await getDoc(userDocRef)).data();

      // Ensure admin role if admin email
      if (email === ADMIN_EMAIL && userData.role !== 'admin') {
        await updateDoc(userDocRef, { role: 'admin', updatedAt: serverTimestamp() });
        userData.role = 'admin';
      }
      
      // Update last login
      await updateDoc(userDocRef, {
        lastLogin: serverTimestamp(),
        updatedAt: serverTimestamp()
      });

      // Create backend session cookie
      const idToken = await user.getIdToken(true);
      await fetch('/api/auth/sessionLogin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ idToken })
      });

      localStorage.setItem('user', JSON.stringify(userData));

      return {
        success: true,
        user: userData,
        message: 'Sign in successful!'
      };

    } catch (error) {
      console.error('Sign in error:', error);
      return {
        success: false,
        error: this.getErrorMessage(error.code)
      };
    }
  }

  // Update user profile
  async updateUserProfile(updateData) {
    try {
      if (!this.currentUser) {
        return {
          success: false,
          error: 'User not authenticated'
        };
      }

      const userDocRef = doc(db, 'users', this.currentUser.uid);
      
      // Update Firestore document
      await updateDoc(userDocRef, {
        ...updateData,
        updatedAt: serverTimestamp()
      });

      // Update display name in Auth if name changed
      if (updateData.firstName || updateData.lastName) {
        const displayName = `${updateData.firstName || ''} ${updateData.lastName || ''}`.trim();
        await updateProfile(this.currentUser, { displayName });
      }

      // Update localStorage
      const currentUserData = JSON.parse(localStorage.getItem('user') || '{}');
      const updatedUserData = { ...currentUserData, ...updateData };
      localStorage.setItem('user', JSON.stringify(updatedUserData));

      return {
        success: true,
        user: updatedUserData,
        message: 'Profile updated successfully!'
      };

    } catch (error) {
      console.error('Profile update error:', error);
      return {
        success: false,
        error: 'Failed to update profile. Please try again.'
      };
    }
  }

  // Sign out
  async signOut() {
    try {
      await signOut(auth);
      localStorage.removeItem('user');
      // Clear backend session cookie
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
      return {
        success: true,
        message: 'Signed out successfully!'
      };
    } catch (error) {
      console.error('Sign out error:', error);
      return {
        success: false,
        error: 'Failed to sign out. Please try again.'
      };
    }
  }

  // Get current user
  getCurrentUser() {
    return this.currentUser;
  }

  // Check if user is authenticated
  isAuthenticated() {
    return !!this.currentUser;
  }

  // Get stored user data
  getStoredUserData() {
    try {
      return JSON.parse(localStorage.getItem('user') || 'null');
    } catch {
      return null;
    }
  }

  // Get error message from Firebase error code
  getErrorMessage(errorCode) {
    switch (errorCode) {
      case 'auth/user-disabled':
        return 'Your account has been disabled. Please contact support.';
      case 'auth/user-not-found':
        return 'No account found with this email address.';
      case 'auth/wrong-password':
        return 'Incorrect password. Please try again.';
      case 'auth/email-already-in-use':
        return 'An account with this email already exists.';
      case 'auth/weak-password':
        return 'Password is too weak. Please choose a stronger password.';
      case 'auth/invalid-email':
        return 'Please enter a valid email address.';
      case 'auth/operation-not-allowed':
        return 'This sign-in method is not enabled. Please contact support.';
      case 'auth/account-exists-with-different-credential':
        return 'An account already exists with the same email but different sign-in credentials.';
      case 'auth/auth-domain-config-required':
        return 'Authentication configuration error. Please contact support.';
      case 'auth/credential-already-in-use':
        return 'This credential is already associated with a different user account.';
      case 'auth/operation-not-supported-in-this-environment':
        return 'This operation is not supported in this environment.';
      case 'auth/timeout':
        return 'Operation timed out. Please try again.';
      case 'auth/missing-android-pkg-name':
        return 'An Android Package Name must be provided if the Android App is required to be installed.';
      case 'auth/missing-continue-uri':
        return 'A continue URL must be provided in the request.';
      case 'auth/missing-ios-bundle-id':
        return 'An iOS Bundle ID must be provided if an App Store ID is provided.';
      case 'auth/invalid-continue-uri':
        return 'The continue URL provided in the request is invalid.';
      case 'auth/unauthorized-continue-uri':
        return 'The domain of the continue URL is not whitelisted.';
      case 'auth/invalid-dynamic-link-domain':
        return 'The provided dynamic link domain is not configured or authorized for the current project.';
      case 'auth/argument-error':
        return 'Invalid arguments provided. Please check your input.';
      case 'auth/invalid-persistence-type':
        return 'The specified persistence type is invalid.';
      case 'auth/unsupported-persistence-type':
        return 'The current environment does not support the specified persistence type.';
      case 'auth/invalid-credential':
        return 'The supplied credential is invalid.';
      case 'auth/invalid-verification-code':
        return 'The verification code is invalid.';
      case 'auth/invalid-verification-id':
        return 'The verification ID is invalid.';
      case 'auth/custom-token-mismatch':
        return 'The custom token corresponds to a different audience.';
      case 'auth/invalid-custom-token':
        return 'The custom token format is incorrect.';
      case 'auth/captcha-check-failed':
        return 'The reCAPTCHA response token provided is invalid.';
      case 'auth/invalid-phone-number':
        return 'The format of the phone number provided is incorrect.';
      case 'auth/missing-phone-number':
        return 'To send verification codes, provide a phone number for the recipient.';
      case 'auth/quota-exceeded':
        return 'The project\'s quota for this operation has been exceeded.';
      case 'auth/cancelled-popup-request':
        return 'This operation has been cancelled due to another conflicting popup being opened.';
      case 'auth/popup-blocked':
        return 'Unable to establish a connection with the popup. It may have been blocked by the browser.';
      case 'auth/popup-closed-by-user':
        return 'The popup has been closed by the user before finalizing the operation.';
      case 'auth/unauthorized-domain':
        return 'This domain is not authorized for OAuth operations for your Firebase project.';
      case 'auth/invalid-user-token':
        return 'This user\'s credential isn\'t valid for this project. This can happen if the user\'s token has been tampered with, or if the user isn\'t for the project associated with this API key.';
      case 'auth/user-token-expired':
        return 'The user\'s credential is no longer valid. The user must sign in again.';
      case 'auth/null-user':
        return 'The user is null.';
      case 'auth/app-deleted':
        return 'This instance of FirebaseApp has been deleted.';
      case 'auth/invalid-api-key':
        return 'Your API key is invalid, please check you have copied it correctly.';
      case 'auth/network-request-failed':
        return 'Network error occurred. Please check your internet connection and try again.';
      case 'auth/requires-recent-login':
        return 'This operation is sensitive and requires recent authentication. Log in again before retrying this request.';
      case 'auth/too-many-requests':
        return 'We have blocked all requests from this device due to unusual activity. Try again later.';
      case 'auth/web-storage-unsupported':
        return 'This browser is not supported or 3rd party cookies and data may be disabled.';
      default:
        return 'An error occurred during authentication. Please try again.';
    }
  }
}

export default new FirebaseAuthService();