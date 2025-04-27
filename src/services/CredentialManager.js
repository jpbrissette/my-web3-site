/**
 * CredentialManager.js
 * 
 * A service for securely managing credentials in a web3 application.
 * 
 * Note: This implementation requires the crypto-js library.
 * Install it using: npm install crypto-js --save
 */

import CryptoJS from 'crypto-js';

/**
 * Secret key for encryption/decryption
 * Uses environment variables to keep sensitive data out of the codebase
 * 
 * Set up:
 * 1. Create a .env file in the project root (add it to .gitignore)
 * 2. Add REACT_APP_ENCRYPTION_KEY=your_strong_random_key to the .env file
 * 3. For production, set the environment variable in your hosting platform
 * @type {string}
 */
const SECRET_KEY = process.env.REACT_APP_ENCRYPTION_KEY || 'default-dev-key-replace-in-production';

/**
 * Storage key to use in localStorage
 * @type {string}
 */
const STORAGE_KEY = 'web3_credentials';

/**
 * CredentialManager class for handling secure credential operations
 */
class CredentialManager {
  /**
   * Set credentials in secure storage
   * @param {Object} credentials - The credentials object to store
   * @param {string} [credentials.address] - Wallet address
   * @param {string} [credentials.privateKey] - Private key (sensitive)
   * @param {string} [credentials.token] - Authentication token
   * @returns {boolean} - Success status
   * @throws {Error} - If encryption or storage fails
   */
  static setCredentials(credentials) {
    try {
      if (!credentials || typeof credentials !== 'object') {
        throw new Error('Invalid credentials format');
      }
      
      // Check if encryption key is properly set
      if (SECRET_KEY === 'default-dev-key-replace-in-production' && process.env.NODE_ENV === 'production') {
        console.warn('WARNING: Using default encryption key in production. Set REACT_APP_ENCRYPTION_KEY environment variable.');
      }
      
      // Encrypt the credentials object
      const encryptedCredentials = CryptoJS.AES.encrypt(
        JSON.stringify(credentials),
        SECRET_KEY
      ).toString();
      
      // Store in localStorage
      localStorage.setItem(STORAGE_KEY, encryptedCredentials);
      return true;
    } catch (error) {
      console.error('Failed to set credentials:', error);
      throw new Error('Failed to securely store credentials');
    }
  }

  /**
   * Get credentials from secure storage
   * @returns {Object|null} - The stored credentials or null if none exist
   * @throws {Error} - If decryption fails
   */
  static getCredentials() {
    try {
      const encryptedCredentials = localStorage.getItem(STORAGE_KEY);
      
      if (!encryptedCredentials) {
        return null;
      }
      
      // Decrypt the credentials
      const bytes = CryptoJS.AES.decrypt(encryptedCredentials, SECRET_KEY);
      const decryptedCredentials = bytes.toString(CryptoJS.enc.Utf8);
      
      if (!decryptedCredentials) {
        throw new Error('Decryption failed');
      }
      
      return JSON.parse(decryptedCredentials);
    } catch (error) {
      console.error('Failed to get credentials:', error);
      throw new Error('Failed to retrieve credentials securely');
    }
  }

  /**
   * Check if credentials exist in storage
   * @returns {boolean} - True if credentials exist, false otherwise
   */
  static hasCredentials() {
    try {
      const encryptedCredentials = localStorage.getItem(STORAGE_KEY);
      return !!encryptedCredentials;
    } catch (error) {
      console.error('Failed to check credentials:', error);
      return false;
    }
  }

  /**
   * Remove credentials from storage
   * @returns {boolean} - Success status
   */
  static removeCredentials() {
    try {
      localStorage.removeItem(STORAGE_KEY);
      return true;
    } catch (error) {
      console.error('Failed to remove credentials:', error);
      throw new Error('Failed to remove credentials');
    }
  }

  /**
   * Get a specific credential field
   * @param {string} field - The field name to retrieve
   * @returns {any} - The value of the requested field or null
   * @throws {Error} - If field access fails
   */
  static getCredentialField(field) {
    try {
      const credentials = this.getCredentials();
      
      if (!credentials) {
        return null;
      }
      
      return credentials[field] || null;
    } catch (error) {
      console.error(`Failed to get credential field ${field}:`, error);
      throw new Error(`Failed to retrieve credential field ${field}`);
    }
  }

  /**
   * Update specific fields in the stored credentials
   * @param {Object} fields - Object containing fields to update
   * @returns {boolean} - Success status
   * @throws {Error} - If update fails
   */
  static updateCredentials(fields) {
    try {
      if (!fields || typeof fields !== 'object') {
        throw new Error('Invalid fields format');
      }
      
      const currentCredentials = this.getCredentials() || {};
      const updatedCredentials = { ...currentCredentials, ...fields };
      
      return this.setCredentials(updatedCredentials);
    } catch (error) {
      console.error('Failed to update credentials:', error);
      throw new Error('Failed to update credentials');
    }
  }
}

export default CredentialManager;

