/*
 * Copyright 2013 Berin Lautenbach
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

package org.authme.android.util;


import android.util.Base64;
import android.util.Log;

import java.security.MessageDigest;

/**
 * Created with IntelliJ IDEA.
 * User: berin
 * Date: 29/03/13
 * Time: 3:02 PM
 *
 * Holder class that is nice and simple and is used to manipulate KCVs
 */


public class KCV {

    public static final String TAG = "KCV";

    String kcvBase64 = "";
    byte[] kcv = null;

    public KCV(String kcvBase64) {

        // Initialise with Base 64 initialiser
        this.kcvBase64 = kcvBase64;

        // Decode it
        try {
            // Now lets encrypt the nonce
            kcv = Base64.decode(kcvBase64, Base64.DEFAULT);
            if (kcv != null && kcv.length != 8)
                kcv = null;     // Can only be 8 - anything else is an error
        } catch (IllegalArgumentException ex) {
            Log.v(TAG, "Error loading KCV from base64 input");
        }
    }

    // Constructor for creating from a new service key
    public KCV(byte[] serviceKey) {

        kcv = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (md != null) {
                md.update(serviceKey);
                kcv = md.digest();
            }

            // Now base64 encode it
            kcvBase64 = Base64.encodeToString(kcv, 0,8, Base64.NO_WRAP);
        }
        catch (Exception ex) {
            Log.e(TAG, "Error creating service key digest");
        }
    }

    public Boolean checkKCV(byte[] toCheck) {

        /* We SHA-256 the data and then compare to the KCV we hold
         */

        if (kcv == null || kcv.length != 8)
            return Boolean.FALSE;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (md != null) {
                md.update(toCheck);
                byte[] digest = md.digest();
                if (digest.length < 8)
                    return Boolean.FALSE;

                for (int i = 0; i < 8; ++i)
                    if (digest[i] != kcv[i])
                        return Boolean.FALSE;
            }
        }
        catch (Exception ex) {
            Log.v(TAG, "Error performing MD operation");
            return Boolean.FALSE;
        }

        return Boolean.TRUE;
    }

    public String getKCVBase64() {

        return kcvBase64;

    }

}
