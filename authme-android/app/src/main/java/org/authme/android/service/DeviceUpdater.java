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

import org.authme.android.core.AuthListAdapter;
import org.authme.android.core.DeviceListAdapter;
import org.authme.entity.DeviceInfo;
import org.authme.entity.SvcSession;
import org.authme.event.AuthCheckUpdatedEvent;
import org.authme.event.ResponseEvent;
import org.authme.event.ServiceKeyDetailsEvent;
import org.authme.event.ServiceKeySetEvent;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import timber.log.Timber;

/**
 * Created by User on 27/02/2016.
 *
 * Encapsulates logic to update a specific authorisation
 */

public class DeviceUpdater implements AuthMeSign.SigningCallbacks, AuthMeService.Callbacks {

    AuthMeService _authme = null;
    MasterPassword _masterPassword;
    DeviceListAdapter deviceList = null;
    String base64CipherText = "";

    DeviceInfo di;

    public DeviceUpdater(DeviceListAdapter adapter) {
        _authme = adapter.getAuthMeService();
        _masterPassword = MasterPassword.getInstance();
        deviceList = adapter;
    }

    private DeviceUpdater(){
        /* SHould never be called */
    }

    public boolean doUpdate(DeviceInfo input) {

        di = input;

        try {

            // Encode the service key

            byte[] rawRSA = Base64.decode(di.getPublicKey(), Base64.DEFAULT);
            if (rawRSA != null) {

                // Build the key object
                PublicKey publicKey;
                publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(rawRSA));

                // Create the cipher
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                // Do the encrypt
                byte[] ciperText = cipher.doFinal(_masterPassword.getRawServiceKey());

                // Encode it
                base64CipherText = Base64.encodeToString(ciperText, Base64.NO_WRAP);

                // Sign it
                    /* First we sign the relevant data */
                AuthMeSign signer = new AuthMeSign();
                if (!signer.doSign(di.getDeviceUniqueId() + _masterPassword.getKcv().getKCVBase64() + base64CipherText, _masterPassword.getDeviceKeyPair(), this))
                    return false;

                /* Wait for service to return */

            }
        }
        catch (Exception Ex) {
            Timber.v("Exception doing signature: " + Ex.getLocalizedMessage());
            return false;
        }

        return true;
    }

    /* Callback interfaces */
    public void onSignatureReturn(AuthMeSign signer) {
        _authme.setServiceKey(di.getDeviceUniqueId(), base64CipherText,
                _masterPassword.getKcv().getKCVBase64(), null, null, null, signer, this);
    }

    public void onAuthMeServiceReturn(ResponseEvent responseEvent) {

        Timber.d("Received response event in device updater");

        if (responseEvent == null || !responseEvent.getSuccess()) {
            Timber.d("Error in AuthMe response");
            return;
        }

        if (responseEvent instanceof ServiceKeySetEvent) {
            /* We updated something - reload */
            deviceList.loadDevices();
        }
    }
}
