/*
 * Copyright 2011-2013 Berin Lautenbach
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

package org.authme.android.gcm;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import com.google.android.gms.gcm.GoogleCloudMessaging;
import org.authme.android.service.MasterPassword;

import java.io.IOException;

/**
 * Created by Berin on 2/01/14.
 */
public class GCMService {

    private String gcmSenderId = null;
    private String gcmRegistrationId = null;

    private static final String TAG = "GCMService";
    private static boolean debug = true;

    private GoogleCloudMessaging gcm = null;

    // Stub this out - never create with no params
    private GCMService() {}

    /**
     * Simple initialiser - simply take in the data we need, but don't do anything with it yet
     *
     * @param senderId APplication ID
     * @param registrationId My registered ID
     */
    public GCMService(String senderId, String registrationId) {

        gcmSenderId = senderId;
        gcmRegistrationId = registrationId;

    }

    private void registerDevice() {
        /* Register me in the background */
        new AsyncTask<Void, Void, String>() {
            @Override
            protected String doInBackground(Void... params) {
                try {
                    gcmRegistrationId = gcm.register(gcmSenderId);
                    if (debug) {
                        Log.v(TAG, "Registration ID received: " + gcmRegistrationId);
                    }

                    return gcmRegistrationId;
                }
                catch (IOException ex) {
                    Log.w(TAG, "Error from Google Cloud Messaging: " + ex.getMessage());
                }
                return null;
            }

            @Override
            protected void onPostExecute(String msg) {
                if (debug)
                    Log.v(TAG, "Finished registration: " + gcmRegistrationId);

                if (msg != null && gcmRegistrationId != null && !(gcmRegistrationId.length() == 0)) {
                    MasterPassword _masterPassword = MasterPassword.getInstance();
                    _masterPassword.setGCMRegistrationId(gcmRegistrationId);
                }
            }

        }.execute(null, null, null);

    }

    public void start(Context context) {

        if (gcmSenderId == null || (gcmRegistrationId.length() == 0)) {
            Log.w(TAG, "GCMService passed an empty sender ID on start");
        }

        gcm = GoogleCloudMessaging.getInstance(context);

        /* More important - do we have a registration ID? */
        if (gcmRegistrationId == null || (gcmRegistrationId.length() == 0)) {
            if (debug)
                Log.v(TAG, "registrationID = 0");
            registerDevice();
        }
    }
}
