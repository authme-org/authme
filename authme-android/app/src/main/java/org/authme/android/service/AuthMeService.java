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

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

import org.authme.android.BuildConfig;
import org.authme.android.R;
import org.authme.event.ResponseEvent;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 3/08/11
 * Time: 7:56 PM
 *
 * Manages connections to the AuthMeService.
 *
 * NOTE: This is not thread safe.  So each "thread" (Activity) should have it's own instance
 * of AuthMeService and then ensure that it is only being called one connection at a time.
 *
 */

public class AuthMeService {

    // For logging
    public static final String TAG = "AuthMeService";

    // For talking to the Android API
    Context context;

    // Thread handling
    AuthMeServiceManager authMeServiceManager = null;

    // Service URL base
    String BaseUrl = "";

    public AuthMeService(Context context) {

        this.context = context;
        authMeServiceManager = AuthMeServiceManager.getInstance();
        if (BuildConfig.DEBUG) {
            BaseUrl = context.getString(R.string.BaseURLDebug);
        }
        else {
            BaseUrl = context.getString(R.string.BaseURL);
        }
    }


    /**
     * Register a device with the service.  If already registered we will get an appropriate response
     *
     * @param deviceUniqueId Unique identifier for this device
     * @param name Whatever the device thinks it's called - generally the user's name for it
     * @param deviceType Most likely to be Android....
     * @param publicKey Base64 encoded version of the key to register
     * @param callbacks Function to call when we complete
     * @return TRUE if OK
     */

    public boolean addDevice(String deviceUniqueId,
                             String name,
                             String deviceType,
                             String publicKey,
                             String c2dmToken,
                             Callbacks callbacks) {

        /* First we create the JSON structure */
        JSONObject json = new JSONObject();

        try{
            json.put("deviceUniqueId", deviceUniqueId);
            json.put("type", deviceType);
            json.put("publicKey", publicKey);
            json.put("name", name);
            json.put("c2dmToken", c2dmToken);
        }
        catch (JSONException ex) {
            Log.e(TAG, "Error encoding JSON object");
            return false;
        }

        /* Build the URL */
        MasterPassword _masterPassword = MasterPassword.getInstance();
        Context ctx = _masterPassword.getApplicationContext();

        /* Build the request */

        String URL = getBaseURL() + ctx.getString(R.string.AddDevice);
        Log.v(TAG, "Full URL for service call = " + URL);

        AuthMeServiceTask request = new AuthMeServiceTask(URL);
        request.setPostData(json.toString());

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callbacks);
        request.setOperation(AuthMeServiceTask.Operation.AddDevice);

        /* Do the call */

        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;
    }

    /**
     * Get details about the nominated device.  Will also do an encrypt to test the correct
     * public key is registered for this device with the service
     *
     * @param deviceUniqueId ID for this device
     * @param nonce Data to have encrypted by server
     * @param callbacks Function to call when we complete
     * @return true if succeeds
     */

    public boolean getDevice(String deviceUniqueId, String nonce, Callbacks callbacks) {

        /* We talk to the service purely using the URL */
        MasterPassword _masterPassword = MasterPassword.getInstance();
        Context context = _masterPassword.getApplicationContext();

        String URL = getBaseURL() + context.getString(R.string.GetDevice) +
                "?deviceUniqueId=" + deviceUniqueId +
                "&nonce=" + nonce;

        AuthMeServiceTask request = new AuthMeServiceTask(URL);

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callbacks);
        request.setOperation(AuthMeServiceTask.Operation.GetDevice);

        /* Do the call */

        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;
    }

    /**
     * Get the list of devices for this user
     *
     * @return true if it went well
     */

    public boolean getDevices(Callbacks callback) {

        Context context = MasterPassword.getInstance().getApplicationContext();
        String URL = getBaseURL() + context.getString(R.string.GetDevices);

        AuthMeServiceTask request = new AuthMeServiceTask(URL);

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callback);
        request.setOperation(AuthMeServiceTask.Operation.GetDevices);

        /* Do the call */
        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;

    }

    /**
     * Get Service key for this device
     *
     * @param deviceId ID for this device
     * @param callbacks Function to call when we complete
     * @return true if succeeds
     */

    public boolean getServiceKey(String deviceId, Callbacks callbacks) {

        /* We talk to the service URL with deviceId as a parameter*/

        MasterPassword _masterPassword = MasterPassword.getInstance();
        Context context = _masterPassword.getApplicationContext();
        String URL = getBaseURL() + context.getString(R.string.GetServiceKey) +
                "?deviceId=" + deviceId;

        AuthMeServiceTask request = new AuthMeServiceTask(URL);

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callbacks);
        request.setOperation(AuthMeServiceTask.Operation.GetServiceKey);

        /* Do the call */
        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;
    }

    /**
     * Set Service key for a device
     *
     * @param deviceId ID to set
     * @param encryptedKeyValue service key encrypted under appropriate public key
     * @param keyKCV service key KCV
     * @param signature signature to get service to agree to this update
     * @param callback Function to call when we complete
     * @return true if succeeds
     */

    public boolean setServiceKey(String deviceId,
                                 String encryptedKeyValue,
                                 String keyKCV,
                                 String encryptedPrivateKeyValue,
                                 String privateKCV,
                                 String publicKeyValue,
                                 AuthMeSign signature,
                                 Callbacks callback) {

        /* We talk to the service URL with deviceId as a parameter*/

        MasterPassword _masterPassword = MasterPassword.getInstance();
        Context context = _masterPassword.getApplicationContext();

        /* First we create the JSON structure */

        JSONObject json = new JSONObject();
        JSONObject jsonSig = new JSONObject();

        try{
            // First the signature
            jsonSig.put("sigId", signature.sigId);
            jsonSig.put("dateTime", signature.dateTime);
            jsonSig.put("value", signature.signature);

            // Now the main object
            json.put("deviceId", deviceId);
            json.put("encryptedKeyValue", encryptedKeyValue);
            json.put("keyKCV", keyKCV);
            json.put("encryptedPrivateKey", encryptedPrivateKeyValue);
            json.put("privateKCV", privateKCV);
            json.put("publicKey", publicKeyValue);
            json.put("signature", jsonSig);
        }
        catch (JSONException ex) {
            Log.e(TAG, "Error encoding JSON object");
            return false;
        }

        /* Build the URL */
        String URL = getBaseURL() + context.getString(R.string.SetServiceKey);
        Log.v(TAG, "Full URL for service call = " + URL);

        AuthMeServiceTask request = new AuthMeServiceTask(URL);
        request.setPostData(json.toString());

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callback);
        request.setOperation(AuthMeServiceTask.Operation.SetServiceKey);

        /* Do the call */

        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;

    }

    /**
     * Get the currently waiting list of authorisation checks for this user
     *
     * @param callback Function to call when we complete
     * @return true if it went well
     */

    public boolean getAuthChecks(Callbacks callback) {

        Context context = MasterPassword.getInstance().getApplicationContext();

        String URL = getBaseURL() + context.getString(R.string.AuthCheck);

        AuthMeServiceTask request = new AuthMeServiceTask(URL);

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callback);
        request.setOperation(AuthMeServiceTask.Operation.GetAuthChecks);

        /* Do the call */
        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;

    }

    /**
     * Signature seeds are basically a nonce used by the service to prove a signature was
     * recent.  They can only be used once.
     *
     * @param callback Function to call when we complete
     * @return true if we got the seed
     */

    public boolean getSignatureSeed(Callbacks callback) {

        Context context = MasterPassword.getInstance().getApplicationContext();

        String URL = getBaseURL() + context.getString(R.string.SignatureSeed);

        AuthMeServiceTask request = new AuthMeServiceTask(URL);

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callback);
        request.setOperation(AuthMeServiceTask.Operation.GetSignatureSeed);

        /* Do the call */
        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;

    }

    /**
     *
     * @param checkId Identifier of the auth check to update
     * @param status What status we want to set it to
     * @param unwrappedSecret The decrypted secret if one was requested
     * @param signature The signature to prove this is valid
     * @param callback To inform has completed
     * @return did the service work
     */

    public boolean setAuthCheckStatus(String checkId,
                                      String status,
                                      String unwrappedSecret,
                                      AuthMeSign signature,
                                      Callbacks callback) {

        MasterPassword _masterPassword = MasterPassword.getInstance();
        Context context = _masterPassword.getApplicationContext();

        /* First we create the JSON structure */
        JSONObject jsonSignature = new JSONObject();
        JSONObject json = new JSONObject();

        try{
            /* First the signature */
            jsonSignature.put("sigId", signature.sigId);
            jsonSignature.put("dateTime", signature.dateTime);
            jsonSignature.put("value", signature.signature);

            /* Then the overall */
            json.put("checkId", checkId);
            json.put("status", status);
            json.put("unwrappedSecret", unwrappedSecret);
            json.put("signature", jsonSignature);

        }
        catch (JSONException ex) {
            Log.e(TAG, "Error encoding JSON signature");
            return false;
        }

                /* Build the URL */
        String URL = getBaseURL() + context.getString(R.string.AuthCheck);
        Log.v(TAG, "Full URL for service call = " + URL);

        AuthMeServiceTask request = new AuthMeServiceTask(URL);
        request.setPostData(json.toString());

        if (!addUsernameAndPassword(request))
            return false;

        request.setCallbacks(callback);
        request.setOperation(AuthMeServiceTask.Operation.SetAuthCheckStatus);

        /* Do the call */

        authMeServiceManager.executeAuthMeServiceTask(request);

        return true;
    }

    /*
     * Some utility functions
     */

    private boolean addUsernameAndPassword(AuthMeServiceTask request) {

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        MasterPassword _masterPassword = MasterPassword.getInstance();

        String userName = prefs.getString("authmeUsername", "");

        if (userName.equals("")) {
            Log.w(TAG, "No userid set for service for current user");
            return false;
        }

        String encryptedPassword = prefs.getString("authmePassword", "");

        if (encryptedPassword.equals("")) {
            Log.w(TAG, "No password set for service for current user");
            return false;
        }

        byte rawPassword[] = _masterPassword.masterPasswordDecrypt(encryptedPassword);
        if (rawPassword == null || rawPassword.length == 0) {
            Log.w(TAG, "Error decrypting password for service");
            return false;
        }

        request.setPassword(new String(rawPassword));
        request.setUsername(userName);

        return true;

    }

    private String getBaseURL() {

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        return prefs.getString("authme_service_url", BaseUrl);

    }

    /*
     * Used by the service to return data back to the calling class
     */

    public interface Callbacks {

        void onAuthMeServiceReturn(ResponseEvent responseEvent);

    }
}
