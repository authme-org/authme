/*
 * Copyright 2016 Berin Lautenbach
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

package org.authme.android.core;

import android.app.AlertDialog;
import android.app.NotificationManager;
import android.content.Context;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.ListFragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ListView;

import org.authme.android.R;
import org.authme.android.service.AuthMeService;
import org.authme.android.service.AuthMeSign;
import org.authme.android.service.AuthUpdater;
import org.authme.android.service.MasterPassword;
import org.authme.entity.SvcSession;

import java.util.ArrayList;

public class AuthListFragment extends ListFragment {

    /**
     * The current activated item position. Only used on tablets.
     */
    private int mActivatedPosition = ListView.INVALID_POSITION;

    private static final String STATE_ACTIVATED_POSITION = "activated_position";

    // For logging
    public static final String TAG = "AuthListFragment";
    boolean loaded = false;

    private org.authme.android.core.AuthListAdapter authListAdapter;

    private class InitialLoad extends AsyncTask<Void, Void, Boolean> {

        protected Boolean doInBackground(Void... input) {

            // By default we fail
            return authListAdapter.loadAuths();
        }

        protected void onPostExecute(Boolean done) {

            if (done) {
                Log.v(TAG, "Main thread - Startup AuthList load succeeded");
                loaded = true;
            }
            else {
                Log.v(TAG, "Main thread - AuthList initial load failed");
            }

        }
    }

    private class UpdateAuthTask extends AsyncTask<SvcSession, Void, Boolean> {

        protected Boolean doInBackground(SvcSession... input) {

            AuthUpdater updater = new AuthUpdater(authListAdapter);
            SvcSession ss = input[0];
            updater.doUpdate(ss);

            return Boolean.TRUE;

        }

        protected void onPostExecute(Boolean done) {

            if (done) {
                Log.v(TAG, "Set auth status success");
            }
            else
                Log.v(TAG, "Set auth status failure");

        }
    }

    public class AuthSelectedOnClickListener implements DialogInterface.OnClickListener {

        private SvcSession svcSession;
        private String status;

        public AuthSelectedOnClickListener(SvcSession svcSession, String status) {
            this.svcSession = svcSession;
            this.status = status;
        }

        public void onClick(DialogInterface dialog, int whichButton) {

            Log.v(TAG, "Pressed button: " + whichButton + " Status = " + status);
            svcSession.setStatus(status);
            UpdateAuthTask updateAuthTask = new UpdateAuthTask();
            updateAuthTask.execute(svcSession);
            doNotificationClear();

        }
    }

    public void reload() {
        Log.v(TAG, "Reload called - must be a C2DM Receiver event");
        if (!loaded)
            return;
        authListAdapter.loadAuths();
    }

    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        MasterPassword _masterPassword = MasterPassword.getInstance();

        /* Create the auth list adapter and set it to load */

        authListAdapter = new AuthListAdapter(_masterPassword.getApplicationContext(), R.layout.auth_list_item, new ArrayList<SvcSession>());

        // We background the first load as it will wait on the master password being entered
        InitialLoad loadAuthsTask = new InitialLoad();
        //noinspection unchecked
        loadAuthsTask.execute();

        /* Register with MasterPassword so we can be called by the C2DM Receiver */
        _masterPassword.setAuthListFragment(this);

        setListAdapter(authListAdapter);


    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.auth_list, container, false);
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        // Restore the previously serialized activated item position.
        if (savedInstanceState != null
                && savedInstanceState.containsKey(STATE_ACTIVATED_POSITION)) {
            setActivatedPosition(savedInstanceState.getInt(STATE_ACTIVATED_POSITION));
        }

        ListView lv = getListView();
        lv.setTextFilterEnabled(true);

        /* Register the button */
        Button button = (Button) getView().findViewById(R.id.ReloadButton);
        if (button != null) {
            button.setOnClickListener(new View.OnClickListener() {
                public void onClick(View view) {
                    authListAdapter.loadAuths();
                    doNotificationClear();
                }
            });
        }
    }

    @Override
    public void onListItemClick(ListView listView, View view, int position, long id) {

        SvcSession ss = authListAdapter.getItem(position);
        if (ss != null) {

            /* Ask user whether to Approve or Deny (or cancel) */
            Context myContext = MasterPassword.getInstance().getApplicationContext();
            AlertDialog.Builder alert = new AlertDialog.Builder(getView().getContext());
            alert.setTitle("Approve authorisation");
            alert.setMessage("Please approve or deny this action");

            alert.setPositiveButton("Approve", new AuthSelectedOnClickListener(ss, "APPROVED"));
            alert.setNeutralButton("Deny", new AuthSelectedOnClickListener(ss, "DECLINED"));
            alert.setNegativeButton("Cancel", null);

            alert.show();
        }
    }

    public void doNotificationClear() {

        /* Clear notifications */

        String ns = Context.NOTIFICATION_SERVICE;
        NotificationManager notificationManager =
                (NotificationManager) MasterPassword.getInstance().getApplicationContext().getSystemService(ns);

        notificationManager.cancelAll();
        Log.v(TAG, "Cleared all C2DM notifications");


    }

    /**
     * Turns on activate-on-click mode. When this mode is on, list items will be
     * given the 'activated' state when touched.
     */
    public void setActivateOnItemClick(boolean activateOnItemClick) {
        // When setting CHOICE_MODE_SINGLE, ListView will automatically
        // give items the 'activated' state when touched.
        getListView().setChoiceMode(activateOnItemClick
                ? ListView.CHOICE_MODE_SINGLE
                : ListView.CHOICE_MODE_NONE);
    }

    private void setActivatedPosition(int position) {
        if (position == ListView.INVALID_POSITION) {
            getListView().setItemChecked(mActivatedPosition, false);
        } else {
            getListView().setItemChecked(position, true);
        }

        mActivatedPosition = position;
    }

}
