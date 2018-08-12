package com.midsummer.habakkeystore.cryptography

import com.midsummer.habakkeystore.EncryptedModel

/**
 * Created by NienLe on 8/11/18,August,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */
interface Habak{

    fun initialize()
    fun encrypt(plainText: String) : EncryptedModel
    fun decrypt(data: EncryptedModel) : String
}