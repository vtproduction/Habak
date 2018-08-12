package com.midsummer.habak;

/**
 * Created by NienLe on 8/12/18,August,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
public class Test {

    private static final String ANDROID_KEY_STORE_NAME = "AndroidKeyStore";
    private static final String AES_MODE_M_OR_GREATER = "AES/GCM/NoPadding";
    private static final String KEY_ALIAS = "YOUR-KeyAliasForEncryption";
    // TODO update these bytes to be random for IV of encryption
    private static final byte[] FIXED_IV = new byte[]{ 55, 54, 53, 52, 51, 50,
            49, 48, 47,
            46, 45, 44 };
    private static final String CHARSET_NAME = "UTF-8";
    private static final String LOG_TAG = Test.class.getName();



    private final static Object s_keyInitLock = new Object();

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void initKeys() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            initValidKeys();
        } else {
            boolean keyValid = false;
            try {
                KeyStore.Entry keyEntry = keyStore.getEntry(KEY_ALIAS, null);
                if (keyEntry instanceof KeyStore.SecretKeyEntry &&
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    keyValid = true;
                }
            } catch (NullPointerException | UnrecoverableKeyException e) {
                // Bad to catch null pointer exception, but looks like Android 4.4.x
                // pin switch to password Keystore bug.
                // https://issuetracker.google.com/issues/36983155
                Log.e(LOG_TAG, "Failed to get key store entry", e);
            }

            if (!keyValid) {
                synchronized (s_keyInitLock) {
                    // System upgrade or something made key invalid
                    removeKeys(keyStore);
                    initValidKeys();
                }
            }

        }

    }

    protected void removeKeys(KeyStore keyStore) throws KeyStoreException {
        keyStore.deleteEntry(KEY_ALIAS);

    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void initValidKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
        synchronized (s_keyInitLock) {
            generateKeysForAPIMOrGreater();
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    protected void generateKeysForAPIMOrGreater() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator;
        keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE_NAME);
        keyGenerator.init(
                new KeyGenParameterSpec.Builder(KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        // NOTE no Random IV. According to above this is less secure but acceptably so.
                        .setRandomizedEncryptionRequired(false)
                        .build());
        // Note according to [docs](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html)
        // this generation will also add it to the keystore.
        keyGenerator.generateKey();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String encryptData(String stringDataToEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException {

        initKeys();

        if (stringDataToEncrypt == null) {
            throw new IllegalArgumentException("Data to be decrypted must be non null");
        }

        Cipher cipher;
        cipher = Cipher.getInstance(AES_MODE_M_OR_GREATER);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeyAPIMorGreater(),
                new GCMParameterSpec(128, FIXED_IV));

        byte[] encodedBytes = cipher.doFinal(stringDataToEncrypt.getBytes(CHARSET_NAME));
        String encryptedBase64Encoded = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
        return encryptedBase64Encoded;

    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String decryptData(String encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException {

        initKeys();

        if (encryptedData == null) {
            throw new IllegalArgumentException("Data to be decrypted must be non null");
        }

        byte[] encryptedDecodedData = Base64.decode(encryptedData, Base64.DEFAULT);

        Cipher c;

        try {
            c = Cipher.getInstance(AES_MODE_M_OR_GREATER);
            c.init(Cipher.DECRYPT_MODE, getSecretKeyAPIMorGreater(), new GCMParameterSpec(128, FIXED_IV));
        } catch (InvalidKeyException | IOException e) {
            // Since the keys can become bad (perhaps because of lock screen change)
            // drop keys in this case.
            removeKeys();
            throw e;
        }

        byte[] decodedBytes = c.doFinal(encryptedDecodedData);
        return new String(decodedBytes, CHARSET_NAME);

    }

    private Key getSecretKeyAPIMorGreater() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);
        return keyStore.getKey(KEY_ALIAS, null);

    }



    public void removeKeys() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        synchronized (s_keyInitLock) {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
            keyStore.load(null);
            removeKeys(keyStore);
        }
    }
}