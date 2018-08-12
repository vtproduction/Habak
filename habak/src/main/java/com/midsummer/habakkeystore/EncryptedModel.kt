package com.midsummer.habakkeystore

import android.util.Base64

/**
 * Created by NienLe on 8/11/18,August,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */
class EncryptedModel(var data: ByteArray, var iv: ByteArray, var lastUpdate: Long) {


    override fun toString(): String {
        return "EncryptedModel(data='${Base64.encodeToString(data, Base64.DEFAULT)}', iv='${Base64.encodeToString(iv, Base64.DEFAULT)}', lastUpdate=$lastUpdate)"
    }

    fun toByteArrayString(): String {
        return "EncryptedModel(data='${data.contentToString()}', iv='${iv.contentToString()}', lastUpdate=$lastUpdate)"
    }
}