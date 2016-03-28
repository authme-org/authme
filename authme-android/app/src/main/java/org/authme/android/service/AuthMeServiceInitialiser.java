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

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import org.authme.android.util.KCV;
import org.authme.event.DeviceAddedEvent;
import org.authme.event.DeviceDetailsEvent;
import org.authme.event.ResponseEvent;
import org.authme.event.ServiceKeyDetailsEvent;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import timber.log.Timber;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 4/08/11
 * Time: 8:42 PM
 *
 * This class is started by MasterPassword after passwords are entered.  It is used to "connect" to the service
 * if we have enough information
 */
public class AuthMeServiceInitialiser implements AuthMeService.Callbacks, AuthMeSign.SigningCallbacks {

    // For logging
    public static final String TAG = "AuthMeServiceInit";

    static private AuthMeService authme = null;
    @SuppressWarnings({"FieldCanBeLocal"})
    static private boolean initialised = false;
    MasterPassword _masterPassword;

    /* For new service key setup */
    String encryptedServiceKey = "";
    KCV kcv = null;
    String base64PrivateKey = "";
    KCV privateKCV = null;
    String base64PublicKey = "";

    /* For checking encryption capabilities of service */
    String nonce = "";

    private static AuthMeServiceInitialiser ourInstance = new AuthMeServiceInitialiser();

    public static synchronized AuthMeServiceInitialiser getInstance() {
        return ourInstance;
    }

    private AuthMeServiceInitialiser() {
    }

    /* Add device */

    private void addDevice() {

        String device = Build.DEVICE;

        if (device.equals("generic"))
            device = "Simulator";

        /**
         * NOTE: we have a race condition here.  If GCM registration hasn't finished then this will register
         * the first time with an empty RegistrationID.  However future cases will work.
         */

        authme.addDevice(_masterPassword.getDeviceUniqueId(), "Berin's Android", "Android " + device,
                MasterPassword.getInstance().getPublicKeyBase64(), _masterPassword.getGCMRegistrationId(), this);

    }

    /* AsyncTasks calling the service */

    /* AsyncTasks calling the service */

    private class SetNewServiceKeyTask extends AsyncTask<Void, Void, Boolean> {

        AuthMeServiceInitialiser initialiser = null;

        protected Boolean doInBackground(Void... input) {

            Log.v(TAG, "Backgrounded set of new service key");

            // Generate a new service key
            KeyGenerator kgen;
            try {
                kgen = KeyGenerator.getInstance("AES");
            }
            catch (NoSuchAlgorithmException ex) {
                Log.e(TAG, "Error generating AES key: " + ex.getMessage());
                return Boolean.FALSE;
            }
            kgen.init(256);

            // Generate the secret key specs.
            SecretKey skey = kgen.generateKey();
            byte[] raw = skey.getEncoded();

            // Generate KCV
            kcv = new KCV(raw);

            // Save to Master Password
            _masterPassword.setServiceKey(raw);
            _masterPassword.setKcv(kcv);

            // Encrypt using our public key
            encryptedServiceKey = _masterPassword.deviceRSAEncrypt(raw);

            // Generate the service RSA key
            KeyPair kp;
            try {
                Log.v(TAG, "Starting background generation of Service RSA Key");

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);

                kp = keyPairGenerator.generateKeyPair();
                Log.v(TAG, "Background generation of Service RSA key completed");

            }
            catch (Exception ex) {
                Log.e(TAG, "ERROR GENERATING SERVICE RSA KEY PAIR");
                return Boolean.FALSE;
            }

            // Pull the private key so we can encrypt and send to service
            byte[] privateKeyBytes = kp.getPrivate().getEncoded();
            byte[] encryptedPrivateKeyIV;
            byte[] encryptedPrivateKeyBytes;

            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, _masterPassword.getServiceKey());
                AlgorithmParameters params = cipher.getParameters();
                encryptedPrivateKeyIV = params.getParameterSpec(IvParameterSpec.class).getIV();
                encryptedPrivateKeyBytes = cipher.doFinal(privateKeyBytes);
            }
            catch (Exception ex) {
                Log.e(TAG, "Error encrypting service RSA Private key - " + ex.getMessage());
                return Boolean.FALSE;
            }

            byte[] encryptedPrivateKey = new byte[encryptedPrivateKeyIV.length + encryptedPrivateKeyBytes.length];
            System.arraycopy(encryptedPrivateKeyIV, 0, encryptedPrivateKey, 0, encryptedPrivateKeyIV.length);
            System.arraycopy(encryptedPrivateKeyBytes, 0,
                    encryptedPrivateKey, encryptedPrivateKeyIV.length,
                    encryptedPrivateKeyBytes.length);

            // Base 64 encode it as it's going to the service
            base64PrivateKey = Base64.encodeToString(encryptedPrivateKey, Base64.NO_WRAP);

            // Generate privateKCV
            privateKCV = new KCV(privateKeyBytes);

            // Get public key
            byte[] publicKeyBytes = kp.getPublic().getEncoded();
            base64PublicKey = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP);

            // Sign it

            /* First we sign the relevant data */
            AuthMeSign signer = new AuthMeSign();
            if (!signer.doSign(_masterPassword.getDeviceId() + _masterPassword.getKcv().getKCVBase64() + encryptedServiceKey,
                    _masterPassword.getDeviceKeyPair(), initialiser))
                Log.e(TAG, "Error signing new service key");

            return Boolean.TRUE;

        }

        protected void onPostExecute(Boolean done) {

            if (done)
                Log.v(TAG, "SetServiceKey initialiser returned successfully");
            else
                Log.e(TAG, "SetServiceKey failed");

        }
    }

    /**
     * Start the initialisation process for the service
     * @param context application context
     */

    public synchronized void doInit(Context context) {

        /* This should never be needed... */
        if (initialised)
            return;

        Log.v(TAG, "Starting initialisation of authme service");

        _masterPassword = MasterPassword.getInstance();

        /* Create a service object */
        authme = new AuthMeService(context);

        /* Kick off the initialisation sequence */
        addDevice();

    }

    private void checkDevice(DeviceDetailsEvent event) {

        Log.v(TAG, "CheckDevice - got a response - validating");

        /* Get the response values */

        String encryptedData = event.getEncryptedData();
        _masterPassword.setDeviceId(event.getDeviceUniqueId());

        Log.v(TAG, "Got return encrypted data from service: " + encryptedData);

        /* Try to decrypt back to our nonce */
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, _masterPassword.getDeviceKeyPair().getPrivate());

            byte decryptRaw[] = cipher.doFinal(Base64.decode(encryptedData, 0));

                        /* Did it work? */
            if (nonce.equals(new String(decryptRaw))) {
                Log.v(TAG, "Decrypt of check nonce OK");

                /* Now we chain through to getting the service key */
                authme.getServiceKey(_masterPassword.getDeviceId(), this);

            } else
                Log.v(TAG, "Decrypt of check nonce failed");

        } catch (Exception ex) {
            Log.i(TAG, "Decrypt of check device nonce failed");
        }
    }

    private void checkServiceKey(ServiceKeyDetailsEvent event) {

        String keyStatus = event.getKeyStatus();
        Log.v(TAG, "Key Status = " + keyStatus);

        if ("Available".equals(keyStatus)) {
            Log.v(TAG, "Have Service Key");
            String encryptedKeyValue = event.getEncryptedKeyValue();
            String keyId = event.getKeyId();
            String keyKCV = event.getKeyKCV();

            _masterPassword.setKcv(new KCV(keyKCV));

            /* Now we decrypt the service key */
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, _masterPassword.getDeviceKeyPair().getPrivate());

                byte decryptRaw[] = cipher.doFinal(Base64.decode(encryptedKeyValue, 0));

                if (decryptRaw != null) {
                    if (_masterPassword.getKcv().checkKCV(decryptRaw)) {
                        Log.v(TAG, "KCV for service key checked out");
                        _masterPassword.setServiceKey(decryptRaw);
                        _masterPassword.setServiceKeyId(keyId);
                    } else {
                        Log.v(TAG, "KCV for service key failed");
                        return;
                    }
                }
            } catch (Exception ex) {
                Log.i(TAG, "Decrypt of service key failed");
                return;
            }

            /* Now we load the service RSA Key Pair */
            String encryptedPrivateKey = event.getEncryptedPrivateKey();
            String publicKey = event.getPublicKey();
            String privateKCV = event.getPrivateKCV();

            _masterPassword.setPrivateKcv(new KCV(privateKCV));

            byte[] publicKeyBytes = Base64.decode(publicKey, 0);
            byte[] encryptedPrivateKeyBytes = Base64.decode(encryptedPrivateKey, 0);

            byte[] iv = new byte[16];
            byte[] c = new byte[encryptedPrivateKeyBytes.length - 16];

            System.arraycopy(encryptedPrivateKeyBytes, 0, iv, 0, 16);
            System.arraycopy(encryptedPrivateKeyBytes, 16, c, 0, c.length);

                             /* Now decrypt the private key */
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, _masterPassword.getServiceKey(), new IvParameterSpec(iv));
                byte[] rawPrivateKey = cipher.doFinal(c);

                // Check the KCV of the private key
                if (!_masterPassword.getPrivateKcv().checkKCV(rawPrivateKey)) {
                    Log.e(TAG, "KCV Mismatch for service private key");
                    return;
                }

                // Looking good....  Transform into a public key
                KeyFactory fact = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                PublicKey servicePublicKey = fact.generatePublic(keySpec);

                PKCS8EncodedKeySpec servicePrivateKeySpec = new PKCS8EncodedKeySpec(rawPrivateKey);
                PrivateKey privateKey = fact.generatePrivate(servicePrivateKeySpec);

                KeyPair keyPair = new KeyPair(servicePublicKey, privateKey);
                _masterPassword.setServiceKeyPair(keyPair);

                Log.v(TAG, "Service RSA key loaded and set successfully");

            } catch (Exception ex) {
                Log.w(TAG, "Error decrypting private key data and creating RSA Key pair for service");
                return;
            }

        } else if ("None".equals(keyStatus)) {
            Log.w(TAG, "No service key on service for this device - need to create and register");

            SetNewServiceKeyTask task = new SetNewServiceKeyTask();
            task.initialiser = this;
            task.execute();
        }

        Log.v(TAG, "Testing");
    }

    /*
     * Service Callbacks interface - effectively a state machine for moving through service
     * initialisation
     */

    public void onAuthMeServiceReturn(ResponseEvent responseEvent) {

        Timber.d("Received response event");

        if (responseEvent == null || !responseEvent.getSuccess()) {
            Timber.d("Error in AuthMe response");
            return;
        }

        if (responseEvent instanceof DeviceAddedEvent) {

            /* Use todays date as a nonce */
            Date dateNow = new Date();
            @SuppressLint("SimpleDateFormat")
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS");
            nonce = dateFormat.format(dateNow);
            String uniqueId = _masterPassword.getDeviceUniqueId();

            Log.v(TAG, "Check of device RSA key using nonce: " + nonce);

            authme.getDevice(uniqueId, nonce, this);

            return;
        }

        if (responseEvent instanceof DeviceDetailsEvent) {

            DeviceDetailsEvent event = (DeviceDetailsEvent) responseEvent;
            if (event.getSuccess()) {
                checkDevice(event);
            }
        }

        if (responseEvent instanceof ServiceKeyDetailsEvent) {

            ServiceKeyDetailsEvent event = (ServiceKeyDetailsEvent) responseEvent;
            if (event.getSuccess()) {
                checkServiceKey(event);
            }
        }
    }

    public void onSignatureReturn(AuthMeSign signer) {

        // Now send it!
        authme.setServiceKey(
                _masterPassword.getDeviceId(),
                encryptedServiceKey,
                kcv.getKCVBase64(),
                base64PrivateKey,
                privateKCV.getKCVBase64(),
                base64PublicKey,
                signer, this);

    }
}
