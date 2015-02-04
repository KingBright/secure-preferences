/*
 * Copyright (C) 2013, Daniel Abraham, 2015, Thomas Haertel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.securepreferences;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;

import com.securepreferences.util.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Wrapper class for Android's {@link SharedPreferences} interface, which adds a
 * layer of encryption to the persistent storage and retrieval of sensitive
 * key-value pairs of primitive data types.
 * <p/>
 * This class provides important - but nevertheless imperfect - protection
 * against simple attacks by casual snoopers. It is crucial to remember that
 * even encrypted data may still be susceptible to attacks, especially on rooted
 * or stolen devices!
 * <p/>
 *
 * @see <a href="http://www.codeproject.com/Articles/549119/Encryption-Wrapper-for-Android-SharedPreferences">CodeProject article</a>
 */
public class SecurePreferences implements SharedPreferences {

    private static final String TAG = SecurePreferences.class.getName();

    /**
     * Cipher types that can be used
     * <li>{@link #BC_AES_PBKDF2_SHA1}: Bouncy Castle Provider with AES Key and PBKDF2/HMAC/SHA1 cipher</li>
     * <li>{@link #BC_AES_PBE_TRIPLE_DES}: Bouncy Castle Provider with AES Key and PBE/MD5/DES cipher</li>
     * <li>{@link #SC_AES_GCM}: Spongy Castle Provider with AES/GCM Key, no padding and PBKDF2/HMAC/SHA1 cipher</li>
     * <li>{@link #SC_AES_CBC_PKCS5}: Spongy Castle Provider with AES/CBC Key, PKCS5 padding and PBKDF2/HMAC/SHA1 cipher</li>
     * <p/>
     * All cipher types fallback to Password-Based Encryption and MD5/DES.
     */
    public enum CipherType {
        BC_AES_PBKDF2_SHA1("BC", "AES", "PBKDF2WithHmacSHA1", "PBEWithMD5AndDES"),
        BC_AES_PBE_TRIPLE_DES("BC", "AES", "PBEWithMD5AndTripleDES", "PBEWithMD5AndDES"),
        SC_AES_GCM("SC", "AES/GCM/NoPadding", "PBKDF2WithHmacSHA1", "PBEWithMD5AndDES"),
        SC_AES_CBC_PKCS5("SC", "AES/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1", "PBEWithMD5AndDES");

        public final String provider;
        public final String key_algorithm;
        public final String algorithm;
        public final String backup_algorithm;

        CipherType(String provider, String key_algorithm, String algorithm, String backup_algorithm) {
            this.provider = provider;
            this.key_algorithm = key_algorithm;
            this.algorithm = algorithm;
            this.backup_algorithm = backup_algorithm;
        }
    }

    ;

    private static final String CHARSET = "UTF-8";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 2000;


    public final static SecurePreferences getInstance(Context context, String filename) {
        return getInstance(context, filename, true);
    }

    public final static SecurePreferences getInstance(Context context, String filename, boolean encryptKeys) {
        return new SecurePreferences(context, context.getSharedPreferences(filename, Context.MODE_PRIVATE), encryptKeys);
    }

    public final static SecurePreferences getInstance(Context context, String filename, CipherType cipherType, boolean encryptKeys) {
        return new SecurePreferences(context, context.getSharedPreferences(filename, Context.MODE_PRIVATE), cipherType, encryptKeys);
    }

    private boolean mLoggingEnabled = false;
    private final SharedPreferences mPrefs;
    private final boolean mEncryptKeys;
    private final CipherType mCipherType;
    private byte[] mKey;

    // links user's OnSharedPreferenceChangeListener to secure OnSharedPreferenceChangeListener
    private HashMap<OnSharedPreferenceChangeListener, OnSharedPreferenceChangeListener> mOnSharedPreferenceChangeListeners;

    /**
     * Constructor.
     *
     * @param context the caller's context
     */
    public SecurePreferences(Context context) {
        this(context, PreferenceManager.getDefaultSharedPreferences(context), true);
    }

    /**
     * Constructor.
     *
     * @param context     the caller's context
     * @param encryptKeys set to false, if keys should be stored as plaintext
     */
    public SecurePreferences(Context context, boolean encryptKeys) {
        this(context, PreferenceManager.getDefaultSharedPreferences(context), encryptKeys);
    }

    /**
     * Constructor.
     *
     * @param context     the caller's context
     * @param cipherType  the cipher type to be used for encryption*
     * @param encryptKeys set to false, if keys should be stored as plaintext
     */
    public SecurePreferences(Context context, CipherType cipherType, boolean encryptKeys) {
        this(context, PreferenceManager.getDefaultSharedPreferences(context), cipherType, encryptKeys);
    }

    /**
     * Constructor.
     *
     * @param context the caller's context
     * @param prefs   instance of shared preferences to use internally
     */
    public SecurePreferences(Context context, SharedPreferences prefs) {
        this(context, prefs, true);
    }

    /**
     * Constructor.
     *
     * @param context     the caller's context
     * @param prefs       instance of shared preferences to use internally
     * @param encryptKeys set to false, if keys should be stored as plaintext
     */
    public SecurePreferences(Context context, SharedPreferences prefs, boolean encryptKeys) {
        this(context, prefs, CipherType.BC_AES_PBKDF2_SHA1, encryptKeys);
    }

    /**
     * Constructor.
     *
     * @param context     the caller's context
     * @param prefs       instance of shared preferences to use internally
     * @param cipherType  the cipher type to be used for encryption
     * @param encryptKeys set to false, if keys should be stored as plaintext
     */
    public SecurePreferences(Context context, SharedPreferences prefs, CipherType cipherType, boolean encryptKeys) {
        mPrefs = prefs;
        mCipherType = cipherType;
        mEncryptKeys = encryptKeys;

        init(context);
    }

    private void init(Context context) {
        // Initialize encryption/decryption key
        try {
            final String key = generateAesKeyName(context);
            String value = mPrefs.getString(key, null);

            if (value == null) {
                value = generateAesKeyValue();
                mPrefs.edit().putString(key, value).commit();
            }

            mKey = SecurePreferences.decode(value);
        } catch (Exception e) {
            if (mLoggingEnabled) {
                Log.e(TAG, "Error init:" + e.getMessage());
            }

            throw new IllegalStateException(e);
        }
        // initialize OnSecurePreferencesChangeListener HashMap
        mOnSharedPreferenceChangeListeners = new HashMap<OnSharedPreferenceChangeListener, OnSharedPreferenceChangeListener>(10);
    }

    private static String encode(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static byte[] decode(String input) {
        return Base64.decode(input, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private String generateAesKeyName(Context context)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        final char[] password = context.getPackageName().toCharArray();
        final byte[] salt = getDeviceSerialNumber(context).getBytes();

        SecretKey key = null;

        try {
            // TODO: what if there's an OS upgrade and now supports the primary PBE
            key = generatePBEKey(password, salt, mCipherType.algorithm, ITERATIONS, KEY_SIZE);
        } catch (NoSuchAlgorithmException e) {
            if ("".equals(mCipherType.backup_algorithm)) {
                throw new RuntimeException(e);
            }

            // older devices may not support the implementation try with a weaker algorithm
            key = generatePBEKey(password, salt, mCipherType.backup_algorithm, ITERATIONS, KEY_SIZE);
        }

        return SecurePreferences.encode(key.getEncoded());
    }

    /**
     * Derive a secure key based on the passphraseOrPin
     *
     * @param passphraseOrPin
     * @param salt
     * @param algorithm       - which PBE algorithm to use. some <4.0 devices don;t support
     *                        the prefered PBKDF2WithHmacSHA1
     * @param iterations      - Number of PBKDF2 hardening rounds to use. Larger values
     *                        increase computation time (a good thing), defaults to 1000 if
     *                        not set.
     * @param keyLength
     * @return Derived Secretkey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchProviderException
     */
    private SecretKey generatePBEKey(char[] passphraseOrPin, byte[] salt, String algorithm, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchProviderException {

        if (iterations == 0) {
            iterations = 1000;
        }

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm, mCipherType.provider);
        KeySpec keySpec = new PBEKeySpec(passphraseOrPin, salt, iterations, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

        return secretKey;
    }

    /**
     * Gets the hardware serial number of this device.
     *
     * @return serial number or Settings.Secure.ANDROID_ID if not available.
     */
    private static String getDeviceSerialNumber(Context context) {
        // We're using the Reflection API because Build.SERIAL is only available
        // since API Level 9 (Gingerbread, Android 2.3).
        try {
            String deviceSerial = (String) Build.class.getField("SERIAL").get(null);
            if (TextUtils.isEmpty(deviceSerial)) {
                deviceSerial = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
            }
            return deviceSerial;
        } catch (Exception ignored) {
            // default to Android_ID
            return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        }
    }

    private String generateAesKeyValue() throws NoSuchAlgorithmException {
        // Do *not* seed secureRandom! Automatically seeded from system entropy
        final SecureRandom random = new SecureRandom();

        // Use the largest AES key length which is supported by the OS
        final KeyGenerator generator = KeyGenerator.getInstance(mCipherType.key_algorithm);
        try {
            generator.init(KEY_SIZE, random);
        } catch (Exception e) {
            try {
                generator.init(192, random);
            } catch (Exception e1) {
                generator.init(128, random);
            }
        }
        return SecurePreferences.encode(generator.generateKey().getEncoded());
    }

    private String encrypt(String cleartext) {
        if (cleartext == null || cleartext.length() == 0) {
            return cleartext;
        }
        try {
            final Cipher cipher = Cipher.getInstance(mCipherType.key_algorithm, mCipherType.provider);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(mKey, mCipherType.key_algorithm));

            return SecurePreferences.encode(cipher.doFinal(cleartext.getBytes(CHARSET)));
        } catch (Exception e) {
            if (mLoggingEnabled) {
                Log.w(TAG, "encrypt", e);
            }
            return null;
        }
    }

    private String decrypt(String ciphertext) {
        if (ciphertext == null || ciphertext.length() == 0) {
            return ciphertext;
        }
        try {
            final Cipher cipher = Cipher.getInstance(mCipherType.key_algorithm, mCipherType.provider);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(mKey, mCipherType.key_algorithm));

            return new String(cipher.doFinal(SecurePreferences.decode(ciphertext)), CHARSET);
        } catch (Exception e) {
            if (mLoggingEnabled) {
                Log.w(TAG, "decrypt", e);
            }

            return null;
        }
    }

    @Override
    public Map<String, String> getAll() {
        final Map<String, ?> encryptedMap = mPrefs.getAll();
        final Map<String, String> decryptedMap = new HashMap<String, String>(encryptedMap.size());

        for (Entry<String, ?> entry : encryptedMap.entrySet()) {
            try {
                decryptedMap.put(mEncryptKeys ? decrypt(entry.getKey()) : entry.getKey(), decrypt(entry.getValue().toString()));
            } catch (Exception e) {
                // Ignore unencrypted key/value pairs
            }
        }

        return decryptedMap;
    }

    @Override
    public String getString(String key, String defaultValue) {
        final String encryptedValue = mPrefs.getString(mEncryptKeys ? encrypt(key) : key, null);

        return (encryptedValue != null) ? decrypt(encryptedValue) : defaultValue;
    }

    /**
     * Added to get a values as as it can be useful to store values that are
     * already encrypted and encoded
     *
     * @param key
     * @param defaultValue
     * @return Unencrypted value of the key or the defaultValue if
     */
    public String getStringUnencrypted(String key, String defaultValue) {
        final String nonEncryptedValue = mPrefs.getString(mEncryptKeys ? encrypt(key) : key, null);

        return (nonEncryptedValue != null) ? nonEncryptedValue : defaultValue;
    }

    @Override
    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    public Set<String> getStringSet(String key, Set<String> defaultValues) {
        final Set<String> encryptedSet = mPrefs.getStringSet(mEncryptKeys ? encrypt(key) : key, null);

        if (encryptedSet == null) {
            return defaultValues;
        }

        final Set<String> decryptedSet = new HashSet<String>(encryptedSet.size());

        for (String encryptedValue : encryptedSet) {
            decryptedSet.add(decrypt(encryptedValue));
        }

        return decryptedSet;
    }

    @Override
    public int getInt(String key, int defaultValue) {
        final String encryptedValue = mPrefs.getString(mEncryptKeys ? encrypt(key) : key, null);

        if (encryptedValue == null) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public long getLong(String key, long defaultValue) {
        final String encryptedValue = mPrefs.getString(mEncryptKeys ? encrypt(key) : key, null);

        if (encryptedValue == null) {
            return defaultValue;
        }

        try {
            return Long.parseLong(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public float getFloat(String key, float defaultValue) {
        final String encryptedValue = mPrefs.getString(mEncryptKeys ? encrypt(key) : key, null);

        if (encryptedValue == null) {
            return defaultValue;
        }

        try {
            return Float.parseFloat(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public boolean getBoolean(String key, boolean defaultValue) {
        final String encryptedValue = mPrefs.getString(mEncryptKeys ? encrypt(key) : key, null);

        if (encryptedValue == null) {
            return defaultValue;
        }

        try {
            return Boolean.parseBoolean(decrypt(encryptedValue));
        } catch (NumberFormatException e) {
            throw new ClassCastException(e.getMessage());
        }
    }

    @Override
    public boolean contains(String key) {
        return mPrefs.contains(mEncryptKeys ? encrypt(key) : key);
    }

    public boolean isEncryptKeys() {
        return mEncryptKeys;
    }

    @Override
    public Editor edit() {
        return new Editor(this);
    }

    /**
     * Wrapper for Android's {@link android.content.SharedPreferences.Editor}.
     * <p/>
     * Used for modifying values in a {@link SecurePreferences} object. All
     * changes you make in an editor are batched, and not copied back to the
     * original {@link SecurePreferences} until you call {@link #commit()} or
     * {@link #apply()}.
     */
    public static class Editor implements SharedPreferences.Editor {
        private SharedPreferences.Editor mEditor;
        private SecurePreferences mPrefs;

        /**
         * Constructor.
         */
        private Editor(SecurePreferences prefs) {
            mEditor = mPrefs.edit();
            mPrefs = prefs;
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            mEditor.putString(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, mPrefs.encrypt(value));
            return this;
        }

        /**
         * This is useful for storing values that have be encrypted by something
         * else
         *
         * @param key   - encrypted as usual
         * @param value will not be encrypted
         * @return
         */
        public SharedPreferences.Editor putStringNoEncrypted(String key, String value) {
            mEditor.putString(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, value);
            return this;
        }

        @Override
        @TargetApi(Build.VERSION_CODES.HONEYCOMB)
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            final Set<String> encryptedValues = new HashSet<String>(values.size());

            for (String value : values) {
                encryptedValues.add(mPrefs.encrypt(value));
            }

            mEditor.putStringSet(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, encryptedValues);

            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            mEditor.putString(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, mPrefs.encrypt(Integer.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            mEditor.putString(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, mPrefs.encrypt(Long.toString(value)));

            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            mEditor.putString(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, mPrefs.encrypt(Float.toString(value)));

            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            mEditor.putString(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key, mPrefs.encrypt(Boolean.toString(value)));

            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            mEditor.remove(mPrefs.isEncryptKeys() ? mPrefs.encrypt(key) : key);

            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            mEditor.clear();

            return this;
        }

        @Override
        public boolean commit() {
            return mEditor.commit();
        }

        @Override
        @TargetApi(Build.VERSION_CODES.GINGERBREAD)
        public void apply() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.GINGERBREAD) {
                mEditor.apply();
            } else {
                commit();
            }
        }
    }

    public boolean isLoggingEnabled() {
        return mLoggingEnabled;
    }

    public void setLoggingEnabled(boolean loggingEnabled) {
        mLoggingEnabled = loggingEnabled;
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(final OnSharedPreferenceChangeListener listener) {
        mPrefs.registerOnSharedPreferenceChangeListener(listener);
    }

    /**
     * @param listener    OnSharedPreferenceChangeListener
     * @param decryptKeys Callbacks receive the "key" parameter decrypted
     */
    public void registerOnSharedPreferenceChangeListener(
            final OnSharedPreferenceChangeListener listener, boolean decryptKeys) {

        if (!decryptKeys) {
            registerOnSharedPreferenceChangeListener(listener);
            return;
        }

        // wrap user's OnSharedPreferenceChangeListener with another that decrypts key before
        // calling the onSharedPreferenceChanged callback
        OnSharedPreferenceChangeListener secureListener = new OnSharedPreferenceChangeListener() {
            private OnSharedPreferenceChangeListener mInsecureListener = listener;

            @Override
            public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
                try {
                    final String decryptedKey = isEncryptKeys() ? decrypt(key) : key;
                    if (decryptedKey != null) {
                        mInsecureListener.onSharedPreferenceChanged(sharedPreferences, decryptedKey);
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Unable to decrypt key: " + key);
                }
            }
        };

        mOnSharedPreferenceChangeListeners.put(listener, secureListener);
        mPrefs.registerOnSharedPreferenceChangeListener(secureListener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(
            OnSharedPreferenceChangeListener listener) {
        if (mOnSharedPreferenceChangeListeners.containsKey(listener)) {
            OnSharedPreferenceChangeListener secureListener = mOnSharedPreferenceChangeListeners.remove(listener);
            mPrefs.unregisterOnSharedPreferenceChangeListener(secureListener);
        } else {
            mPrefs.unregisterOnSharedPreferenceChangeListener(listener);
        }
    }
}
