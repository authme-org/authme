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

package org.authme.android.core;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.ListFragment;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.ListView;
import org.authme.android.service.AuthMeService;
import org.authme.android.service.DeviceUpdater;
import org.authme.entity.DeviceInfo;
import org.authme.android.R;
import org.authme.android.service.MasterPassword;
import org.authme.android.service.AuthMeSign;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import org.authme.android.R;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 24/03/2013
 * Time: 3:33 PM
 *
 * List known devices for update as necessary
 */


public class DeviceListFragment extends ListFragment {

    // For logging
    public static final String TAG = "DeviceListFragment";

    private int mActivatedPosition = ListView.INVALID_POSITION;

    private static final String STATE_ACTIVATED_POSITION = "activated_position";


    private org.authme.android.core.DeviceListAdapter deviceListAdapter;

    private class LoadDevicesTask extends AsyncTask<Void, Void, Boolean> {

         protected Boolean doInBackground(Void... input) {

             // By default we fail
             return deviceListAdapter.loadDevices();
         }

         protected void onPostExecute(Boolean done) {

             if (done) {
                 Log.v(TAG, "Main thread - DeviceList load succeeded");
                 deviceListAdapter.internalSync();

             }
             else {
                 Log.v(TAG, "Main thread - DeviceList load failed");
             }
         }
     }

    private class UpdateDeviceTask extends AsyncTask<DeviceInfo, Void, Boolean> {

        protected Boolean doInBackground(DeviceInfo... input) {

            DeviceInfo deviceInfo = input[0];
            DeviceUpdater updater = new DeviceUpdater(deviceListAdapter);
            updater.doUpdate(deviceInfo);

            return Boolean.TRUE;
        }

        protected void onPostExecute(Boolean done) {

            if (done) {
                Log.v(TAG, "Set device success, reloading data");
            }
            else
                Log.v(TAG, "Set device key failure");

        }
    }

    public class DeviceSelectedOnClickListener implements DialogInterface.OnClickListener {

        private DeviceInfo deviceInfo;
        private String status;

        public DeviceSelectedOnClickListener(DeviceInfo deviceInfo, String status) {
            this.deviceInfo = deviceInfo;
            this.status = status;
        }

        public void onClick(DialogInterface dialog, int whichButton) {

            Log.v(TAG, "Pressed button: " + whichButton + " Status = " + status + " for device: " +
                deviceInfo.getDeviceUniqueId());

            if (status.equals("YES") /*&& deviceInfo.getServiceKeyStatus().equals("None")*/) {
                Log.v(TAG, "Valid device being set");

                // Grab the RSA key, use it to encrypt the service key, sign the whole thing
                // And send it off to the service - should keep us busy for a little while....
                UpdateDeviceTask udt = new UpdateDeviceTask();
                udt.execute(deviceInfo);

            }
//            deviceInfo.setServiceKeyStatus("YES");
  //          UpdateDeviceTask updateAuthTask = new UpdateDeviceTask();
    //        updateAuthTask.execute(deviceInfo);

        }
    }

    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        /* Create the auth list adapter and set it to load */

        MasterPassword _masterPassword = MasterPassword.getInstance();

        deviceListAdapter = new DeviceListAdapter(_masterPassword.getApplicationContext(), R.layout.auth_list_item, new ArrayList<DeviceInfo>());
        LoadDevicesTask loadAuthsTask = new LoadDevicesTask();
        //noinspection unchecked
        loadAuthsTask.execute();

        setListAdapter(deviceListAdapter);

    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.device_list, container, false);
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
                    LoadDevicesTask loadDevicesTask = new LoadDevicesTask();
                    //noinspection unchecked
                    loadDevicesTask.execute();
                }
            });
        }

    }

    private void setActivatedPosition(int position) {
        if (position == ListView.INVALID_POSITION) {
            getListView().setItemChecked(mActivatedPosition, false);
        } else {
            getListView().setItemChecked(position, true);
        }

        mActivatedPosition = position;
    }


    @Override
    public void onListItemClick(ListView listView, View view, int position, long id) {

        DeviceInfo di = deviceListAdapter.getItem(position);

        if (di != null) {

                    /* Ask user whether to Approve or Deny (or cancel) */
            AlertDialog.Builder alert = new AlertDialog.Builder(getView().getContext());
            alert.setTitle("Enable Device");
            alert.setMessage("Really Enable This Device?");

            alert.setPositiveButton("Yes", new DeviceSelectedOnClickListener(di, "YES"));
            alert.setNeutralButton("No", new DeviceSelectedOnClickListener(di, "NO"));
            alert.setNegativeButton("Cancel", null);

            alert.show();
        }

    }

}
