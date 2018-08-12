package com.midsummer.habakkeystore.cryptography.oldVersion

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import com.midsummer.habakkeystore.Constant
import com.midsummer.habakkeystore.EncryptedModel
import com.midsummer.habakkeystore.cryptography.Habak

import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.util.*
import javax.security.auth.x500.X500Principal
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import com.midsummer.habakkeystore.Constant.ENCRYPTED_KEY_NAME
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import kotlin.collections.ArrayList


/**
 * Created by NienLe on 8/11/18,August,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */
class Habak19Cipher(var alias : String, var context: Context) : Habak {

    private lateinit var keyStore: KeyStore




    private fun rsaEncrypt(secret: ByteArray) : ByteArray {
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val inputCipher = Cipher.getInstance(Constant.RSA_MODE, Constant.OPENSSL)
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)
        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(secret)
        cipherOutputStream.close()
        return outputStream.toByteArray()
    }



    private fun rsaDecrypt(encrypted: ByteArray): ByteArray {
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val output = Cipher.getInstance(Constant.RSA_MODE, Constant.OPENSSL)
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)
        val cipherInputStream = CipherInputStream(
                ByteArrayInputStream(encrypted), output)
        val values : ArrayList<Byte> = ArrayList()
        var nextByte = cipherInputStream.read()

        while (nextByte !== -1) {
            values.add(nextByte.toByte())
            nextByte = cipherInputStream.read()
        }

        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }
        return bytes
    }


    private fun saveSecretKey() {
        val pref = context.getSharedPreferences(Constant.SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE)
        val encryptedKeyB64 = pref.getString(ENCRYPTED_KEY_NAME, null)
        if (encryptedKeyB64 == null) {
            val key = ByteArray(16)
            val secureRandom = SecureRandom()
            secureRandom.nextBytes(key)
            val encryptedKey = rsaEncrypt(key)
            val newKey = Base64.encodeToString(encryptedKey, Base64.DEFAULT)
            val edit = pref.edit()
            edit.putString(ENCRYPTED_KEY_NAME, newKey).apply()
        }
    }


    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private fun generateSecretKey() {
        if (!keyStore.containsAlias(alias)){
            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 1)
            val spec = KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(X500Principal("CN=$alias"))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()
            val kpg = KeyPairGenerator.getInstance(Constant.RSA, Constant.ANDROID_KEY_STORE)
            kpg.initialize(spec)
            kpg.generateKeyPair()
            saveSecretKey()
        }

    }




    private fun getSecretKey(): Key {
        val pref = context.getSharedPreferences(Constant.SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE)
        val encryptedKeyB64 = pref.getString(ENCRYPTED_KEY_NAME, null)

        val encryptedKey = Base64.decode(encryptedKeyB64, Base64.DEFAULT)
        val key = rsaDecrypt(encryptedKey)
        return SecretKeySpec(key, Constant.AES)
    }


    /**
     * Init the Keystore system with default params.
     * Check if the key with alias 'alias' is already existed, generate if need
     */
    override fun initialize() {
        keyStore = KeyStore.getInstance(Constant.ANDROID_KEY_STORE)
        keyStore.load(null)
        if (!keyStore.containsAlias(alias))
            generateSecretKey()


    }
    override fun encrypt(plainText: String): EncryptedModel {
        val c = Cipher.getInstance(Constant.AES_MODE_LESS_THAN_M, "BC")
        c.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val encodedBytes = c.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val now = Calendar.getInstance().timeInMillis
        val iv = ByteArray(0)
        return EncryptedModel(encodedBytes, iv, now)
    }

    override fun decrypt(data: EncryptedModel): String {
        val c = Cipher.getInstance(Constant.AES_MODE_LESS_THAN_M, "BC")
        c.init(Cipher.DECRYPT_MODE, getSecretKey())
        return String(c.doFinal(data.data), Charsets.UTF_8)
    }
}