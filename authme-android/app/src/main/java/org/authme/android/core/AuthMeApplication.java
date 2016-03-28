package org.authme.android.core;

import android.app.Application;

import org.authme.android.BuildConfig;

import timber.log.Timber;

/**
 * Created by User on 27/02/2016.
 */
public class AuthMeApplication extends Application {

    @Override
    public void onCreate() {

        // Set up log
        if (BuildConfig.DEBUG) {
            Timber.plant(new Timber.DebugTree());
        }

        super.onCreate();

    }
}
