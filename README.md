# HABAK

**Habak** is implementation of Android **Ha**rdware-**Ba**ck **K**eystore security. The information of Hardware-Backed Keystore can be found [here](https://source.android.com/security/keystore/)


## Why Hardware-Backed Keystore?

As seen in the source above, in effort of making data more secure, Google introduce the concept of Keystore. The idea of keystore is simple: seperate the encrypt/decrypt key out of the world

> Keystore is the mechanism that generate and hold the private key that use to encrypt and decrypt data inside the OS level. The key is randomly generate, and can only access at specific application runtime.

> AndroidKeystore is the Android Framework API and component used by apps to access Keystore functionality. It is implemented as an extension to the standard Java Cryptography Architecture APIs, and consists of Java code that runs in the app's own process space. AndroidKeystore fulfills app requests for Keystore behavior by forwarding them to the keystore daemon. (From Google)



![Hardware-Backed Keystore](https://i.imgur.com/d0f0ykw.png?1)

## Encrypt/Decrypt Mechanism

Since the Keystore is only store the key, we need to decide which mechanism of encrypt/decrypt that Keystore System will use. At Habak, we decide to choose **AES/GCM/NoPadding** mechanism.


### AES
AES stands for Advanced Encryption Standard. This algorithm is very popular (More information of AES can be found [Here](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), and currently use worldwide. AES use 128, 192 or 256 bit key to encrypt data, and it almost unbreakable at present, since the complexity to break the algorithm using [brute-force attack](https://en.wikipedia.org/wiki/Brute-force_attack) is 2^128, 2^192 or 2^256, according to the key length. In Habak, I will use default AES method provided by Java, which use 128 bit key length.

### GCM/Nopadding
GCM stands for [Galois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode), which is a mode of operation for symmetric key cryptographic block ciphers that has been widely adopted because of its efficiency and performance. GCM offen comes with [Nopadding](https://en.wikipedia.org/wiki/Padding_%28cryptography%29) options. The combination of AES and GCM/Nopadding mode strengthen the security level of cipher. The implementation of AES/GCM/Nopadding is already available in JVM-8 and highly recommend to use at Android Keystore.

Within AES/GCM/Nopadding, the cipher not only use **secret key** to encrypt the data, but also using **Initial Vector (IV)**. IV is a 12 bytes array that randomly created using java **secureRandom** operation, and come together with the encrypted data. The IV for each encrypt is different and unpredictable. In order to decrypt the data, you have to provide both **secret key** and **IV**. Since IV is 12 bytes array, which equal to 96 bit data, it will make the cipher more security and take more time/effort to break. However, the inconvenience of this strategy is you have to store both data and coordinate IV.

## Habak

With all the theory of Android Hardware-backed Keystore and AES/GCM/Nopaddding mode, now it's time to implement some code to make the encryption and decryption.

First, we initialize the Keystore operation, using neccessary configs:

```
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
    
    /**
     * generate a keystore secret key that use to encrypt/decrypt data
     * This key is store in hardware layer and only can access within app at runtime
     * Specify the key by alias
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun generateSecretKey() : SecretKey {
        val keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, Constant.ANDROID_KEY_STORE)

        keyGenerator.init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build())
        return keyGenerator.generateKey()
    }
    
```

Breakdown the code above, there is ` alias ` field. This is a string that indicate which "block" of keystore that we want to use. Because the keystore system generate and hold many of secret key, then we will use the ` alias ` to tell the system the correct key to load.

Then, we initialze the key mechanism, with those configs:

* The cipher method is ` KeyProperties.KEY_ALGORITHM_AES `, which use AES as algorithm
* The AES will come together with block mode ` KeyProperties.BLOCK_MODE_GCM `, and do not padding the data (` KeyProperties.ENCRYPTION_PADDING_NONE `)
* The key generated is only used to encrypt or decrypt data, so we provide ` KeyProperties.PURPOSE_ENCRYPT ` and ` KeyProperties.PURPOSE_DECRYPT `. With that configs, any key with purpose of encrypt and decrypt is accepted, other purpose (like signing, verify signature..) will be reject.

The encrypt and decrypt functions are very straight-forward:

```
	/**
     * Encrypt the plain text
     * @param plainText
     * @return EncryptedModel object contain the encrypted data, the IV
     * and the current timeStamp
     */
    override fun encrypt(plainText: String): EncryptedModel {
        val cipher = Cipher.getInstance(Constant.AES_MODE_FROM_M)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plainText.toByteArray(charset(Constant.UTF8)))
        val now = Calendar.getInstance().timeInMillis
        return EncryptedModel(encrypted, iv, now)
    }

    /**
     * Decrypt data
     * @param data the EncryptedModel object to decrypt
     * @return decrypted plain string
     * and the current timeStamp
     */
    override fun decrypt(data: EncryptedModel): String {
        val cipher = Cipher.getInstance(Constant.AES_MODE_FROM_M)
        val spec = GCMParameterSpec(128, data.iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)
        return String(cipher.doFinal(data.data), Charsets.UTF_8)
    }

```

Because the decrypt function need the encrypted data and IV, so we need to wrap them up, using ` EncryptedModel ` object:

```
class EncryptedModel(var data: ByteArray, var iv: ByteArray, var lastUpdate: Long)

```

Since both ` data ` and ` iv ` is presented using ` ByteArray `, which very complext to store at device presitence storage, we will make 2 methods to write instance of ` EncryptedModel ` into ` string `, and read them back, too. In particular, I use ` Gson ` to serriallize the object into ` json string `, then encode it into ` Base64 String ` to shorten the content and make them easy to read and store:

```

	fun writeToString() : String{
        val s = Gson().toJson(this)
        val data = s.toByteArray(Charset.defaultCharset())
        return Base64.encodeToString(data, Base64.DEFAULT)
    }

    companion object {
        fun readFromString(src : String) : EncryptedModel {
            val data = Base64.decode(src, Base64.DEFAULT)
            val s = String(data, Charset.defaultCharset())
            return Gson().fromJson(s, EncryptedModel::class.java)
        }
    }
    
```

The flow of encryption and decryption can be demonstrated by this chart:

![](https://i.imgur.com/jAVgvnh.png)
![](https://imgur.com/uHA6c4e.png)


## IV and user provided password

There is a problem with algorithm above: We need to remember the IV in order to decrypt the data. With the structure above, the IV is come along with the encrypted data, so, at this context, the IV protection is useless, because if the attacker retrive the Base64 string from device, he can easily obtain the corresponding IV and data. 

To deal with this problem, I decide to extend the Habak module that has the ability to create IV from **user provided password** instead of randomly generate over secureRandom, then the IV will never be store with the encrypted data. When the data is decrypted, it require the user password, which only known by the data's author - the user. With this approach, the data is protected by both device - the Keystore system, and user authentication - the password. However, the user provided password still has limitation. Since the built in GCM of JVM only accept the IV with 12 bytes length, it means the password that use to create IV **must has extract 12 characters**. It's inconsequently since user may want to use password that ether more or less than 12 characters. So, my temporary way to solve this is, despite of how long the password is, the IV still has 12 chars, by append more if the user-password is short, and cutted-off when it's too long:

```
	/**
     * Since the accepted IV for cipher must has the length of 12 char, so the user password
     * must be cut-off if too long, or append some characters if too short
     * @return formatted password
     */
    private fun formatPasswordLength() : String{
        val ACCEPT_LENGTH = 12

        if (password.length > ACCEPT_LENGTH){
            return password.substring(0, 12)
        }
        if (password.length < ACCEPT_LENGTH){
            var tmp = password
            while(tmp.length < ACCEPT_LENGTH){
                tmp += '0'
            }
            return tmp
        }
        return password
    }

```

## For decprecated API

One limitation of Hardware-Backed Keystore is that it only support Android 6 (API 23) and higher, while there are many of devices currently using Android less than 6. To partily support the older devices, I create seperated class call ` Habak19Cipher `, which shared the same interface with ` Habak23Cipher `, but has some different implementation. 

First, since older API of Android does not provide the AES/GCM/Nopadding mode, the algorithm to use it **AES/ECB/PKCS7Padding** , the diffrent between ECB and GCM can be found [here](https://crypto.stackexchange.com/questions/2310/what-is-the-difference-between-cbc-and-gcm-mode), and the PKCS7Padding is very common padding mode, it works with large block cipher size. The mode is retrived by [Bouncy Castle](https://www.bouncycastle.org/) provider.

Second, AES/ECB only use only secret key to encrypt/decrypt data, but without the protection of Hardware-Backed system, we need to protect the key ourself. So, in this situation, I use **RSA** mechanism to encrypt the secret key. **RSA** ([wiki](https://vi.wikipedia.org/wiki/RSA_(m%C3%A3_h%C3%B3a))) is a **public cryptography algorithm**, which ensure the secure if the key is long enough. This is not secure at all, but still take time to break and retrieve the secret key, because the RSA key is randomly created with the length of 16 bytes. 


## Put it all together

To make everything work as single interface, I created ` HabakFactory ` as a builder, deciding which version of Habak implementation. To use Habak, simply call

```
	val habak = HabakFactory()
		.withContext(context)
		.withAlias("alias name")
		.withPassword("password") //optional
		.build()

```

Then the builder will choose the correct implementation

```
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

```
