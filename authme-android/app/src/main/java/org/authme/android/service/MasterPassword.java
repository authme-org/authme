/*
 * Copyright 2011 Berin Lautenbach
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package org.authme.android.service;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;
import android.widget.EditText;

import org.authme.android.core.AuthListFragment;
import org.authme.android.gcm.GCMService;
import org.authme.android.gcm.GCMUtils;
import org.authme.android.util.KCV;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 31/07/11
 * Time: 4:37 PM
 *
 * Handler for dealing with the password entered by user.  Also deals with encryption keys.
 */

public class MasterPassword {

    // For logging
    public static final String TAG = "MasterPassword";

    // Static strings
    public static final String RSA_PUBLIC_KEY_FILE = "rsa.pub";
    public static final String RSA_PRIVATE_KEY_FILE = "rsa.priv";
    public static final String MASTER_KEY_FILE = "master_key.prefs";
    public static final String PREFS_CHECK_VALUE = "check_value";
    public static final String PREFS_ENCRYPTED_STORE_KEY = "store_key";
    public static final String PREFS_DEVICE_ID = "device_id";
    //public static final String PREFS_C2DM_TOKEN = "c2dm_token";
    public static final String PREFS_GCM_TOKEN = "gcm_token";

    byte masterPasswordSalt[] = {0x56, 0x14, 0x4f, 0x01, 0x5b, 0x3d, 0x44, 0x23};
    byte configCheckArray[] = {0x6a, 0x6a, 0x6a};

    private String deviceUniqueId;

    private String deviceId;            // Service Identifier for the device
    private String gcmToken;

    private static MasterPassword ourInstance = new MasterPassword();
    //private boolean initDone = false;
    Context mainTabContext = null;
    Context applicationContext = null;
    EditText input = null;

    // For the RSA key
    byte encryptedRSAPrivateKey[];
    byte encodedRSAPublicKey[];
    KeyPair deviceKeyPair = null;

    // For the service RSA Key
    KeyPair serviceKeyPair = null;
    KCV privateKCV;

    // For the MasterPassword key
    SharedPreferences masterKeyPrefs = null;
    SecretKeySpec storeKey = null;
    String encryptedCheckValue = null;
    String encryptedStoreKey = null;

    // For the ServiceKey
    SecretKeySpec serviceKey = null;
    byte[] rawServiceKey = null;
    KCV kcv = null;
    String serviceKeyId = null;

    // When blocking everything
    AlertDialog blockingDialog = null;

    // State handling
    boolean initialising = false;
    String passwordFirst = null;

    /* Signalling to other threads */
    Boolean loaded = false;         /* This is false until we know everything is loaded OK */

    /* So other classes can signal an auth list reload */
    AuthListFragment authListFragment = null;

    public static MasterPassword getInstance() {
        return ourInstance;
    }

    private MasterPassword() {
    }

    /**
     * Initialise the master password - loads configuration and asks for the initial password
     * NOTE: This is not threadsafe.  It should only ever be called from the UI thread
     *
     * @param ctx Context of current activity
     * @param applicationContext Context of application
     * @return true if successful, false otherwise
     */

    public boolean init(Context ctx, Context applicationContext) {

        mainTabContext = ctx;
        this.applicationContext = applicationContext;

        /* Have we already loaded?  If so we go straight to service init post config change */
        if (loaded) {
            AuthMeServiceInitialiser amsi = AuthMeServiceInitialiser.getInstance();
            amsi.doInit(this.applicationContext);

            return true;
        }

        /* Load basic prefs so we can check them */
        masterKeyPrefs = ctx.getSharedPreferences(MASTER_KEY_FILE, 0);

        /* Device ID is a  bit different to everything else.  WE create it immediately if we have to */
        deviceId = "";
        deviceUniqueId = masterKeyPrefs.getString(PREFS_DEVICE_ID, "");
        if (deviceUniqueId.equals("")) {
            /* Create a new Unique Device ID */
            deviceUniqueId = UUID.randomUUID().toString();
            Log.i(TAG, "This device has no UUID - created and saving ID: " + deviceUniqueId);
            SharedPreferences.Editor editor = masterKeyPrefs.edit();
            editor.putString(PREFS_DEVICE_ID, deviceUniqueId);
            if (!editor.commit())
                Log.w(TAG, "Error committing device unique ID to preference file");
        }
        else
            Log.i(TAG, "Device ID = " + deviceUniqueId);

        /* Check for our C2DM Token */
        gcmToken = masterKeyPrefs.getString(PREFS_GCM_TOKEN, "");

        /* Open the master key data */
        encryptedCheckValue = masterKeyPrefs.getString(PREFS_CHECK_VALUE, "");
        encryptedStoreKey = masterKeyPrefs.getString(PREFS_ENCRYPTED_STORE_KEY, "");
        if (encryptedCheckValue.equals("") || encryptedStoreKey.equals("")) {
            encryptedCheckValue = null;
            encryptedStoreKey = null;
            return createStore();
        }

        /*
        if (encryptedCheckValue != null)
           return createStore();
        */

        /* Open the RSA files */
        File keyFile = new File(mainTabContext.getFilesDir() + "/" + RSA_PRIVATE_KEY_FILE);
        BufferedInputStream bis;
        try {
            bis = new BufferedInputStream(new FileInputStream(keyFile));
        } catch(FileNotFoundException e) {
            Log.w(TAG, "Loaded pref_service but private key not found");
            return createStore();
        }

        if (keyFile.length() < 17) {
            Log.e(TAG, "Private key file too short");
            return createStore();
        }

        encryptedRSAPrivateKey = new byte[(int)keyFile.length()];
        try {
            //noinspection ResultOfMethodCallIgnored
            bis.read(encryptedRSAPrivateKey);
            bis.close();
        }
        catch (IOException ex) {
            Log.w(TAG, "Error reading RSA Private Key");
            return createStore();
        }

        /* Now the public key */
        keyFile = new File(mainTabContext.getFilesDir() + "/" + RSA_PUBLIC_KEY_FILE);
        try {
            bis = new BufferedInputStream(new FileInputStream(keyFile));
        } catch(FileNotFoundException e) {
            Log.w(TAG, "Loaded pref_service but public key not found");
            return createStore();
        }

        encodedRSAPublicKey = new byte[(int)keyFile.length()];
        try {
            //noinspection ResultOfMethodCallIgnored
            bis.read(encodedRSAPublicKey);
            bis.close();
        }
        catch (IOException ex) {
            Log.w(TAG, "Error reading RSA Public Key");
            return createStore();
        }

        Log.v(TAG, "Loaded RSA Key files OK");

        /* Now start the prompt process */
        promptUserForPassword("Enter Password");

        return true;
    }

    /**
     * Prompt user for an alert
     */

    public class MyOnClickListener implements DialogInterface.OnClickListener {

        public void onClick(DialogInterface dialog, int whichButton) {

            String value = input.getText().toString();

            /* OK - what is our state? */
            if (initialising) {
                if (passwordFirst == null) {
                    passwordFirst = value;
                    promptUserForPassword("Initialise - Repeat Password");
                    return;
                }
                else {
                    if (!passwordFirst.equals(value)) {
                        passwordFirst = null;
                        promptUserForPassword("Initialise Mismatch - Enter Password");
                        return;
                    }

                    /* Got a good password! */
                    initaliseStore();
                    return;
                }
            }

            if (value.equals("RESET!")) {
                createStore();
                return;
            }

            /* OK this is an OK password - validate */
            checkStore(value);
        }
    }

    void promptUserForPassword(String msg) {

        /* Build our alert dialog */
        AlertDialog.Builder alert = new AlertDialog.Builder(mainTabContext);
        alert.setTitle("Master Password");
        alert.setMessage(msg);

        input = new EditText(mainTabContext);

        alert.setView(input);
        alert.setPositiveButton("OK", new MyOnClickListener());

        alert.show();

    }

    private class GenerateRSATask extends AsyncTask<Void, Void, KeyPair> {

        protected KeyPair doInBackground(Void... input) {

            try {
                Log.v(TAG, "Starting background generation of RSA Key");

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);

                KeyPair kp = keyPairGenerator.generateKeyPair();
                Log.v(TAG, "Background generation of RSA key completed");

                return kp;
            }
            catch (Exception ex) {
                Log.e(TAG, "ERROR GENERATING RSA KEY PAIR");
            }

            return null;
        }

        protected void onPostExecute(KeyPair kp) {
            deviceKeyPair = kp;

            try {
                /* Write the public key */
                byte[] publicKeyBytes = deviceKeyPair.getPublic().getEncoded();
                FileOutputStream fos = mainTabContext.openFileOutput(RSA_PUBLIC_KEY_FILE, Context.MODE_PRIVATE);
                fos.write(publicKeyBytes);
                fos.close();

                /* Write the private key */

                byte[] privateKeyBytes = deviceKeyPair.getPrivate().getEncoded();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, storeKey);
                AlgorithmParameters params = cipher.getParameters();
                byte[] encryptedPrivateKeyIV = params.getParameterSpec(IvParameterSpec.class).getIV();
                byte[] encryptedPrivateKeyBytes = cipher.doFinal(privateKeyBytes);

                fos = mainTabContext.openFileOutput(RSA_PRIVATE_KEY_FILE, Context.MODE_PRIVATE);
                fos.write(encryptedPrivateKeyIV);
                fos.write(encryptedPrivateKeyBytes);
                fos.close();
            }
            catch (Exception ex) {
                Log.e(TAG, "Error storing key files");
            }

            if (blockingDialog != null)
                blockingDialog.cancel();

            initContinue();

        }
    }

    public void initRSA() {


        AlertDialog.Builder alert = new AlertDialog.Builder(mainTabContext);
        alert.setTitle("Generating Key");
        alert.setMessage("Please wait while I generate a new RSA key");

        blockingDialog = alert.show();

        /* Now do the generate */
        GenerateRSATask generateRSATask = new GenerateRSATask();
        //noinspection unchecked
        generateRSATask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);

    }

    /**
     * createStore - Creates the KEY store and all data associated with keys
     * @return true if success
     */

    public boolean createStore() {

        initialising = true;
        passwordFirst = null;

        promptUserForPassword("Initialise - Enter Password");

        return true;
    }

    @SuppressWarnings({"ConstantConditions"})
    public void initaliseStore() {

        /* Got a good password - now we need to initialise the store
        *
        *  Start by creating a key spec from our master password
        */

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC");
            //SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordFirst.toCharArray(), masterPasswordSalt, 100, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            AlgorithmParameters params = cipher.getParameters();
            byte[] encryptedStoreKeyIV = params.getParameterSpec(IvParameterSpec.class).getIV();


            /* Now that we have a cipher for the MasterPassword we generate the storeKey */
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(256);

            // Generate the secret key specs.
            SecretKey skey = kgen.generateKey();
            byte[] raw = skey.getEncoded();

            // Encrypt the store key using the master password key
            byte[] encryptedStoreKeyRaw = cipher.doFinal(raw);

            // Now encrypt the check value using the store key
            storeKey = new SecretKeySpec(raw, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, storeKey);
            params = cipher.getParameters();
            byte[] encryptedCheckValueIV = params.getParameterSpec(IvParameterSpec.class).getIV();

            byte[] encryptedCheckValueRaw = cipher.doFinal(configCheckArray);

            /* Build final strings to store */
            byte[] encryptedCheckValueRawAndIV = new byte[encryptedCheckValueRaw.length +
                                                          encryptedCheckValueIV.length];
            System.arraycopy(encryptedCheckValueIV, 0, encryptedCheckValueRawAndIV, 0,
                    encryptedCheckValueIV.length);
            System.arraycopy(encryptedCheckValueRaw, 0, encryptedCheckValueRawAndIV,
                    encryptedCheckValueIV.length, encryptedCheckValueRaw.length);

            byte[] encryptedStoreKeyRawAndIV = new byte[encryptedStoreKeyRaw.length +
                                                        encryptedStoreKeyIV.length];
            System.arraycopy(encryptedStoreKeyIV, 0, encryptedStoreKeyRawAndIV, 0,
                    encryptedStoreKeyIV.length);
            System.arraycopy(encryptedStoreKeyRaw, 0, encryptedStoreKeyRawAndIV,
                    encryptedStoreKeyIV.length, encryptedStoreKeyRaw.length);

            // And finally we store....
            SharedPreferences.Editor editor = masterKeyPrefs.edit();
            editor.putString(PREFS_CHECK_VALUE,
                    new String(Base64.encode(encryptedCheckValueRawAndIV, Base64.NO_WRAP)));
            editor.putString(PREFS_ENCRYPTED_STORE_KEY,
                    new String(Base64.encode(encryptedStoreKeyRawAndIV, Base64.NO_WRAP)));
            editor.apply();
        }
        catch (Exception ex) {
            Log.e(TAG, "Error encrypting initial data", ex);
            return;
        }

        /* OK - Now we have a master password - let's create and store the RSA key */
        initRSA();
    }

    /**
     * Check the password that was provided to see if it decodes the check value.
     * If it does, load the RSA key and release resources
     *
     * If not - restart the password process
     *
     * @param password Password to validate
     */

    @SuppressWarnings({"ConstantConditions"})
    private void checkStore(String password) {

        /* Things we want to erase in anger */

        byte[] rawRSAPrivateKey = null;
        try {

            /* Turn the pasword into a key */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), masterPasswordSalt, 100, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            /* ooooo - this is good!
             * Now we decrypt the storeKey
             */

            byte[] encryptedStoreKeyRawAndIV = Base64.decode(encryptedStoreKey, 0);
            if (encryptedStoreKeyRawAndIV.length <= 17) {
                Log.v(TAG, "Encrypted store key too short");
                promptUserForPassword("Password Error - Enter Password");
                return;
            }
            byte[] encryptedStoreKeyIV = new byte[16];
            byte[] encryptedStoreKeyRaw = new byte[encryptedStoreKeyRawAndIV.length - 16];
            System.arraycopy(encryptedStoreKeyRawAndIV, 0, encryptedStoreKeyIV, 0, 16);
            System.arraycopy(encryptedStoreKeyRawAndIV, 16, encryptedStoreKeyRaw, 0, encryptedStoreKeyRaw.length);

            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(encryptedStoreKeyIV));
            byte[] storeKeyRaw = cipher.doFinal(encryptedStoreKeyRaw);

            /* If that worked we are nearly done! */
            storeKey = new SecretKeySpec(storeKeyRaw, "AES");

            /* WOOT */
            for (int i = 0; i < storeKeyRaw.length; ++ i)
                storeKeyRaw[i] = 0;

            /* Try to decrypt the check value */
            byte[] encryptedCheckValueRawAndIV = Base64.decode(encryptedCheckValue, 0);
            if (encryptedCheckValueRawAndIV.length <= 17) {
                Log.v(TAG, "Encrypted check value too short");
                promptUserForPassword("Password Error - Enter Password");
                return;
            }
            byte[] encryptedCheckValueIV = new byte[16];
            byte[] encryptedCheckValueRaw = new byte[encryptedCheckValueRawAndIV.length - 16];
            System.arraycopy(encryptedCheckValueRawAndIV, 0, encryptedCheckValueIV, 0, 16);
            System.arraycopy(encryptedCheckValueRawAndIV, 16, encryptedCheckValueRaw, 0, encryptedCheckValueRaw.length);

            cipher.init(Cipher.DECRYPT_MODE, storeKey, new IvParameterSpec(encryptedCheckValueIV));
            byte[] decryptedCheckValue = cipher.doFinal(encryptedCheckValueRaw);

            /* Compare the check value */
            for (int i = 0; i < decryptedCheckValue.length; ++i) {
                if (i >= configCheckArray.length || configCheckArray[i] != decryptedCheckValue[i]) {
                    Log.v(TAG, "Mismatch on check array");
                    promptUserForPassword("Password Incorrect - Enter Password");
                    return;
                }
            }

            /* WOOHOO!!! */
            Log.v(TAG, "Check Decrypt all good - now decrypting RSA key");
            rawRSAPrivateKey = masterPasswordDecrypt(encryptedRSAPrivateKey);
            if (rawRSAPrivateKey == null) {
                Log.e(TAG, "Error decrypting RSA private key");
                return;
            }

            /* Create the rsa key */
            KeyFactory fact = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedRSAPublicKey);
            PublicKey publicKey = fact.generatePublic(keySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(rawRSAPrivateKey);
            PrivateKey privateKey = fact.generatePrivate(privateKeySpec);

            deviceKeyPair = new KeyPair(publicKey, privateKey);

            /* All done */
            Log.i(TAG, "All key information loaded successfully");

            /* Now we start up the service stuff */
            initContinue();
            
        }
        catch (Exception ex) {
            Log.e(TAG, "Error decrypting RSA key data", ex);
            promptUserForPassword("Password Error - Enter Password");
        }
        finally{
            /* Erase the RSA key data */
            if (rawRSAPrivateKey != null)
                for (int i = 0; i < rawRSAPrivateKey.length; ++i)
                    rawRSAPrivateKey[i] = 0;
        }

    }


    /**
     * Once encryption keys are done we continue the init process by starting up the authme service
     */

    private synchronized void initContinue() {


         /* Prepare for GCM */
        GCMUtils.gcmCheckPlayServices((Activity) mainTabContext);

        /* Now we signal all threads that the Master Password is now fair game */
        loaded = Boolean.TRUE;
        notifyAll();

        /* Start the gcm messaging service */
        if (GCMUtils.gcmCheckPlayServices((Activity) mainTabContext)) {
            GCMService gcmService = new GCMService(GCMUtils.getGCMSenderId(), getGCMRegistrationId());
            gcmService.start(mainTabContext);
        }

        /* Now we continue our initialisation but move into the service */

        AuthMeServiceInitialiser authmeInit = AuthMeServiceInitialiser.getInstance();
        authmeInit.doInit(applicationContext);
        
    }

    /**
     * Use the device RSA key to encrypt something

     * @param plainBytes plain data in byte[] form
     * @return decrypted data
     */

    public String deviceRSAEncrypt(byte[] plainBytes) {

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, deviceKeyPair.getPublic());

            // Do the encrypt
            byte[] ciperText = cipher.doFinal(plainBytes);

            // Encode it
            return Base64.encodeToString(ciperText, Base64.NO_WRAP);

        }
        catch (Exception ex) {
            Log.e(TAG, "Error encrypting using master password RSA key" + ex.getMessage());
        }

        return null;
    }
    /**
     * Using the master password decrypt some data
     *
     * @param cipherBytes encrypted data in byte[] forme
     * @return decrypted data
     */

    public byte[] masterPasswordDecrypt(byte[] cipherBytes) {

        byte ret[];

        /* First split of the IV */
        if (cipherBytes.length < 17)
            return null;

        byte[] iv = new byte[16];
        byte[] c = new byte[cipherBytes.length - 16];

        System.arraycopy(cipherBytes, 0, iv, 0, 16);
        System.arraycopy(cipherBytes, 16, c, 0, c.length);

        /* Now create the cipher */
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, storeKey, new IvParameterSpec(iv));
            ret = cipher.doFinal(c);
        }
        catch (Exception ex) {
            Log.w(TAG, "Error decrypting data");
            return null;
        }

        return ret;
    }

    public byte[] masterPasswordDecrypt(String cipherString) {

        /* All strings are base 64 */
        try {
            byte cipherRaw[] = Base64.decode(cipherString.getBytes(), 0);
            if (cipherRaw != null && cipherRaw.length > 0)
                return masterPasswordDecrypt(cipherRaw);
        }
        catch (Exception ex) {
            Log.i(TAG, "Error decoding and decrypting item with masterPassword");
            return null;
        }
        return null;

    }

    public String masterPasswordDecryptToString(String cipherString) {

        /* Decrypt what we are currently holding */
        byte decryptedBytes[] = null;

        if (cipherString != null)
            decryptedBytes = masterPasswordDecrypt(cipherString);

        /* If it didn't work, just zero the string */
        if (decryptedBytes == null || decryptedBytes.length == 0)
            return "";

        return new String(decryptedBytes);

    }

    /**
     * Encrypt some data and return as a Base64 string
     * @param plain data to encrypt
     * @return Base64 encoded cipher text
     */

    public String masterPasswordEncryptBase64(byte[] plain) {

        if (plain == null || plain.length == 0)
            return null;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, storeKey);
            AlgorithmParameters params = cipher.getParameters();
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            // Encrypt using the master password key
            byte[] cipherRaw = cipher.doFinal(plain);

            /* Build data string  */
            byte[] cipherRawAndIV = new byte[cipherRaw.length + iv.length];
            System.arraycopy(iv, 0, cipherRawAndIV, 0,
                    iv.length);
            System.arraycopy(cipherRaw, 0, cipherRawAndIV,
                    iv.length, cipherRaw.length);

            /* Finally we return */
            return Base64.encodeToString(cipherRawAndIV, Base64.NO_WRAP);
        }
        catch (Exception ex) {
            Log.e(TAG, "Error encrypting data with Master Password");
            return null;
        }
    }

    /**
     * Unwrap a secret
     *
     * @return Base64 encoded unwrapped secret
     */

    public String masterPasswordUnwrapSecret(String wrappedSecret) {

        if (wrappedSecret == null || "".equals(wrappedSecret))
            return null;

        try {

            // First base64 decode
            byte[] rawSecret = Base64.decode(wrappedSecret, Base64.NO_WRAP);

            // Get the length of the data we are working with for the wrapped key
            int wrapBufLen = 0;
            for (int i = 0; i < 4; ++i) {
                wrapBufLen = wrapBufLen << 8;
                wrapBufLen = wrapBufLen | rawSecret[i];
            }

            /* Get the encrypted AES key */
            byte[] wrapBuf = Arrays.copyOfRange(rawSecret, 4, wrapBufLen + 4);

            // Now decrypt using the main service key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serviceKeyPair.getPrivate());

            // Do the decrypt
            byte[] AESBytes = cipher.doFinal(wrapBuf);

            // Sanity check
            if (AESBytes.length != 32) {
                Log.e(TAG, "AES Key decrypted but wrong length in unwrapSecret");
                return null;
            }

            // Create an AESKey to work with
            SecretKey secret = new SecretKeySpec(AESBytes, "AES256");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] iv = Arrays.copyOfRange(rawSecret, 4 + wrapBufLen, 4 + wrapBufLen + 16);
            byte[] c = Arrays.copyOfRange(rawSecret, 4 + wrapBufLen + 16, rawSecret.length);

            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            byte[] unwrappedSecret = cipher.doFinal(c);

            // Encode it
            return Base64.encodeToString(unwrappedSecret, Base64.NO_WRAP);


        }
        catch (Exception ex) {
            Log.e(TAG, "Error decrypting wrapped secret");
            return null;
        }

    }

    /**
     * Get the RSA key for this installation
     *
     * @return Base64 encoded RSA public key
     */

    public String getPublicKeyBase64() {

        if (deviceKeyPair == null) {
            return null;
        }

        return Base64.encodeToString(deviceKeyPair.getPublic().getEncoded(), Base64.NO_WRAP);

    }

    /**
     * For classes that need to get the application context
     *
     * @return the application context
     */

    public Context getApplicationContext() {
        return applicationContext;
    }

    /**
     * Get the unique ID we use for this device
     * @return Unique ID for this device.
     */

    public String getDeviceUniqueId() {
        return deviceUniqueId;
    }

    public String getGCMRegistrationId() {
        return gcmToken;
    }

    public void setGCMRegistrationId(String registrationId) {

        /* Get the pref_service object so we can save for next time */
        masterKeyPrefs = applicationContext.getSharedPreferences(MASTER_KEY_FILE, 0);

        SharedPreferences.Editor editor = masterKeyPrefs.edit();
        editor.putString(PREFS_GCM_TOKEN, registrationId);
        if (!editor.commit())
            Log.w(TAG, "Error committing device GCM registration ID to preference file");

        /* So others can use it */
        this.gcmToken = registrationId;

    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {

        /* Naughty - need to thread safe this */

        this.deviceId = deviceId;
    }

    public void setServiceKey(byte[] serviceKey) {

        rawServiceKey = serviceKey.clone();
        try {
            this.serviceKey = new SecretKeySpec(rawServiceKey, "AES");
        }
        catch (Exception ex) {
            Log.v(TAG, "Error loading service key into secretKeySpec");
            this.serviceKey = null;
        }
    }

    public KeyPair getDeviceKeyPair() {
        return deviceKeyPair;
    }

    public byte[] getRawServiceKey() {
        return rawServiceKey;
    }

    public KCV getKcv() {
        return kcv;
    }

    public void setKcv(KCV kcv) {
        this.kcv = kcv;
    }

    public void setServiceKeyId(String serviceKeyId) {
        this.serviceKeyId = serviceKeyId;
    }

    public KeyPair getServiceKeyPair() {
        return serviceKeyPair;
    }

    public void setServiceKeyPair(KeyPair serviceKeyPair) {
        this.serviceKeyPair = serviceKeyPair;
    }

    public SecretKeySpec getServiceKey() {
        return serviceKey;
    }

    public KCV getPrivateKcv() {
        return privateKCV;
    }

    public void setPrivateKcv(KCV privateKCV) {
        this.privateKCV = privateKCV;
    }


    /**
     * For syncrhronisation - we need to know the MasterPassword is ready
     * This class will hold a thread until the master password has been loaded
     */

    public synchronized void waitOnLoad() {

        while (!loaded) {
            try {
                Log.v(TAG, "Thread going into wait");
                wait();
            } catch (InterruptedException ignored) {
            }
            Log.v(TAG, "Thread exiting wait");
        }
    }

    public void setAuthListFragment(AuthListFragment alf) {
        authListFragment = alf;
    }

    public AuthListFragment getAuthListFragment() {
        return authListFragment;
    }


}
