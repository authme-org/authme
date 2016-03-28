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

import android.app.Activity;
import android.content.Context;
import android.util.Log;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;

/**
 * Created by Berin on 2/01/14.
 *
 * Utilities for dealing with Google Cloud Messaging
 *
 */


public class GCMUtils {

    // For logging
    private static final String TAG = "GCMUtils";
    private static boolean debug = true;

    // For service
    private static int PLAY_SERVICES_RESOLUTION_REQUEST = 9000;
    private static boolean gpsIsAvailable = false;

    // As registered with Google
    private static final String GCM_SENDER_ID="542349532052";

    /**
     * Get Sender ID for this application
     *
     * @return Sender ID
     */

    public static String getGCMSenderId() {
        return GCM_SENDER_ID;
    }

    /**
     * Find if Google Play Services is available
     *
     * @return availability flag
     */

    public static boolean getGPSIsAvailable() {
        return gpsIsAvailable;
    }

    /**
     * Google Play Setup
     *
     * @return Success code of gcm registration
     */

    public static boolean gcmCheckPlayServices (Activity activity){

        int res = GooglePlayServicesUtil.isGooglePlayServicesAvailable(activity);

        if (res != ConnectionResult.SUCCESS) {

            if (GooglePlayServicesUtil.isUserRecoverableError(res)) {
                GooglePlayServicesUtil.getErrorDialog(res, activity, PLAY_SERVICES_RESOLUTION_REQUEST).show();
            }
            else {
                Log.i(TAG, "Device not supported for Google Play Services");
            }

            return false;

            }

        if (debug)
            Log.v(TAG, "Google Play Services available");

        gpsIsAvailable = true;
        return true;
    }
}
