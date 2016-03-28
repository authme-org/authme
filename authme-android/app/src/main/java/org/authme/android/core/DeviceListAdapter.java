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

import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import org.authme.entity.DeviceInfo;
import org.authme.android.service.MasterPassword;
import org.authme.android.service.AuthMeService;
import org.authme.android.R;
import org.authme.event.AuthCheckListDetailsEvent;
import org.authme.event.DeviceInfoListEvent;
import org.authme.event.ResponseEvent;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;

import timber.log.Timber;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 7/08/11
 * Time: 12:35 PM
 *
 * Used by the DeviceListFragment to get and handle Device lists from the authme service and
 * allow for device registration of new devices
 */
public class DeviceListAdapter extends ArrayAdapter<DeviceInfo> implements AuthMeService.Callbacks {

    // For logging
    public static final String TAG = "DeviceListAdapter";

    private ArrayList<DeviceInfo> devices;
    private Context context;
    private MasterPassword _masterPassword;
    private AuthMeService _authme;

    public DeviceListAdapter(Context context, int textViewResourceId, ArrayList<DeviceInfo> devices) {

        super(context, textViewResourceId, devices);
        this.devices = devices;
        this.context = context;
        this._masterPassword = MasterPassword.getInstance();
        _authme = new AuthMeService(context);

    }

    /**
     * Load the auths list from the service
     * @param object JSON object to search
     * @param value Value to search for
     * @param def default string to return if it wasn't found
     * @return String from the JSON object or def if one did not exist
     */

    String safeGetJSONObjectString(JSONObject object, String value, String def) {

        try {
            return object.getString(value);
        }
        catch (JSONException ignored) {
            return def;
        }
    }

    public boolean loadDevices() {

        /* First make sure we have everything we need to talk to the service */
        Log.v(TAG, "Ready to load - waiting on master password");
        _masterPassword.waitOnLoad();
        Log.v(TAG, "Master password has released lock");

        /* OK - now we load the service list */
        return _authme.getDevices(this);

    }

    public void internalSync() {

        /* Always clear and reload */

        clear();
        notifyDataSetInvalidated();

        if (devices != null) {
            for (DeviceInfo device : devices)
                add(device);
        }

        Log.v(TAG, "Notifying data set changed");
        notifyDataSetChanged();
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {

        View v = convertView;
        if (v == null) {
            LayoutInflater vi = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            v = vi.inflate(R.layout.auth_list_item, null);
        }

        DeviceInfo di = devices.get(position);
        if (di != null) {
            TextView ttl = (TextView) v.findViewById(R.id.toptextleft);
            TextView ttr = (TextView) v.findViewById(R.id.toptextright);
            TextView bt = (TextView) v.findViewById(R.id.bottomtext);

            if (ttl != null)
                ttl.setText(di.getName());
            if (ttr != null)
                if (di.getServiceKeyStatus().equals("Loaded"))
                    ttr.setText("YES");
                else
                    ttr.setText("NO");
            if (bt != null)
                bt.setText(di.getDeviceUniqueId());
                    }

        return v;
    }

    public AuthMeService getAuthMeService() {
        return _authme;
    }

        /*
     * Service Callbacks interface - effectively a state machine for moving through service
     * initialisation
     */

    public void onAuthMeServiceReturn(ResponseEvent responseEvent) {

        Timber.d("Adapter received response event");

        if (responseEvent == null || !responseEvent.getSuccess()) {
            Timber.d("Error in AuthMe response");
            return;
        }

        if (responseEvent instanceof DeviceInfoListEvent) {

            devices = ((DeviceInfoListEvent) responseEvent).getDevices();
            Timber.d("Received devices list with " + devices.size() + " devices");
            this.internalSync();
        }

    }


}
