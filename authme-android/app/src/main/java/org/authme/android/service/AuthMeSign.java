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

import android.util.Base64;
import android.util.Log;

import org.authme.event.DeviceAddedEvent;
import org.authme.event.ResponseEvent;
import org.authme.event.SignatureSeedInfoEvent;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.util.Date;

import timber.log.Timber;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 7/08/11
 * Time: 5:36 PM
 *
 * Signs a string using the master password.  RUNS ON CURRENT THREAD - always call on an already
 * backgrounded thread
 */
public class AuthMeSign implements AuthMeService.Callbacks {

    // For logging
    public static final String TAG = "AuthMeSign";

    private String toSign;
    private KeyPair keyPair;
    private SigningCallbacks callback = null;

    public String sigId;
    public String dateTime;
    public String signature;

    public AuthMeSign() {

    }

    public boolean doSign(String toSign, KeyPair keyPair, SigningCallbacks callback) {

        this.toSign = toSign;
        this.keyPair = keyPair;
        this.callback = callback;

        AuthMeService authme = new AuthMeService(MasterPassword.getInstance().getApplicationContext());
        if (!authme.getSignatureSeed(this))
            return false;

        /* Now we wait for the service to get back to us */
        return true;

    }

    private void finishSignature (SignatureSeedInfoEvent seedInfo) {

        sigId = seedInfo.getSigId();
        dateTime = seedInfo.getDateTime();

        Log.v(TAG, "Sig: " + sigId + " / DateTime: " + dateTime);
        Log.v(TAG, "Signing: " + toSign);

        String signData = sigId + dateTime + toSign;
        Log.v(TAG, "Full sign = (" + signData + ")");

        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(keyPair.getPrivate(), new SecureRandom());

            sig.update(signData.getBytes());

            byte sigBytes[] = sig.sign();
            signature = Base64.encodeToString(sigBytes, Base64.NO_WRAP);

            if (callback != null)
                callback.onSignatureReturn(this);
        }

        catch(Exception ex) {
            Log.w(TAG, "Error signing data: " +ex.getMessage());
        }



    }

    /* My callback */

    public interface SigningCallbacks {

        void onSignatureReturn(AuthMeSign signature);

    }

    /* AuthMe service return */
    public void onAuthMeServiceReturn(ResponseEvent responseEvent) {

        Timber.d("Received response event in signature object");

        if (responseEvent == null || !responseEvent.getSuccess()) {
            Timber.d("Error in AuthMe response");
            return;
        };

        if (responseEvent instanceof SignatureSeedInfoEvent) {
            finishSignature((SignatureSeedInfoEvent) responseEvent);
        }

    }
}
