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
import android.app.IntentService;
import android.content.BroadcastReceiver;
import android.support.v4.content.WakefulBroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import com.google.android.gms.gcm.GoogleCloudMessaging;
import org.authme.android.gcm.GCMIntentService;

/**
 * Created by Berin on 2/01/14.
 */

public class GCMReceiver extends WakefulBroadcastReceiver {

    private static final String TAG = "GCMReceiver";
    private static boolean debug = true;

    public GCMReceiver() {

        if (debug)
            Log.v(TAG, "GCMReceiver initialised");
    }

    /* Handler for incoming messages */
    @Override
    public void onReceive(Context context, Intent intent) {
        // Explicitly specify that GcmIntentService will handle the intent.
        ComponentName comp = new ComponentName(context.getPackageName(),
                GCMIntentService.class.getName());
        // Start the service, keeping the device awake while it is launching.
        startWakefulService(context, (intent.setComponent(comp)));
        setResultCode(Activity.RESULT_OK);

    }
}
