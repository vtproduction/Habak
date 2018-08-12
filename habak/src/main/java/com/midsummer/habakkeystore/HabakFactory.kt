package com.midsummer.habakkeystore

import android.content.Context
import android.os.Build
import com.midsummer.habakkeystore.cryptography.Habak
import com.midsummer.habakkeystore.cryptography.newVersion.Habak23Cipher
import com.midsummer.habakkeystore.cryptography.newVersion.Habak23WithPasswordCipher
import com.midsummer.habakkeystore.cryptography.oldVersion.Habak19Cipher

/**
 * Created by NienLe on 8/11/18,August,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */
class HabakFactory {
    lateinit var alias : String
    lateinit var context : Context
    var password : String = ""



    fun withAlias(alias : String) : HabakFactory {
        this.alias = alias
        return this
    }


    fun withContext(context : Context) : HabakFactory {
        this.context = context
        return this
    }

    fun withPassword(password : String) : HabakFactory {
        this.password = password
        return this
    }



    fun build() : Habak {

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){

            val h23 = if (password.isBlank()) {
                Habak23Cipher(alias)
            } else {
                Habak23WithPasswordCipher(alias, password)
            }
            h23.initialize()
            h23
        }
        else{
            val h19 = Habak19Cipher(alias, context)
            h19.initialize()
            h19
        }

    }



}