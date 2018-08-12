package com.midsummer.habak

import android.os.Build
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import com.midsummer.habakkeystore.HabakFactory
import com.midsummer.habak.R
import com.midsummer.habakkeystore.EncryptedModel
import android.content.Intent
import android.app.KeyguardManager



class MainActivity : AppCompatActivity() {

    val TAG = "MainActivity"
    val INTENT_AUTHENTICATE = 1102
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            val km = getSystemService(KEYGUARD_SERVICE) as KeyguardManager

            if (km.isKeyguardSecure) {
                val authIntent = km.createConfirmDeviceCredentialIntent("title", "message")
                startActivityForResult(authIntent, INTENT_AUTHENTICATE)
            }
        }


    }


    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == INTENT_AUTHENTICATE) {
            if (resultCode == RESULT_OK) {
                //do something you want when pass the security
                bla()
            }
        }
    }


    fun bla(){
        val password = "Nien2012"
        Log.d(TAG,password + ": "  + Base64.encodeToString(password.toByteArray(), Base64.DEFAULT) + " - "+  password.toByteArray().size)


        val password1 = ""
        Log.d(TAG,password1 + ": " + Base64.encodeToString(password1.toByteArray(), Base64.DEFAULT) + " - " +  password1.toByteArray().size)

        val password2 = "Nien20121972"
        Log.d(TAG,password2 + ": " + Base64.encodeToString(password2.toByteArray(), Base64.DEFAULT) + " - " +  password2.toByteArray().size)


        val password3 = "0401@"
        Log.d(TAG,password3 + ": " + Base64.encodeToString(password3.toByteArray(), Base64.DEFAULT) + " - " +  password3.toByteArray().size)
        val habak = HabakFactory()
                .withAlias("new-alias-5")
                .withContext(this)
                .withPassword(password3)
                .build()
        val plainText = "this should be encrypted"



        val data = byteArrayOf(10, -60, -59, 0, 84, 27, -26, -36, 25, -72, -87, -51, -84, 101, -21, 27, -111, 55, 15, -59, 106, 68, -59, -2, 105, -83, 28, 30, 90, 60, -44, -74, 95, 91, 73, -2, 95, -91, 47, -26)
        val iv = byteArrayOf(78, 105, 101, 110, 50, 48, 49, 50, 49, 57, 55, 50)
        val lastUpdate= 1534054076579
        val x = EncryptedModel(data, iv, lastUpdate)


        val encrypted = habak.encrypt(plainText)
        Log.d(TAG, encrypted.toByteArrayString())

        val decrypted = habak.decrypt(encrypted)
        Log.d(TAG, decrypted)
    }
}
