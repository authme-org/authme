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

package org.authme.android.core;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import org.authme.android.R;
import org.authme.android.service.AuthMeService;
import org.authme.android.service.MasterPassword;
import org.authme.entity.SvcSession;
import org.authme.event.AuthCheckListDetailsEvent;
import org.authme.event.ResponseEvent;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import timber.log.Timber;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 7/08/11
 * Time: 12:35 PM
 *
 * Used by the AuthListActivity to get and handle Auth lists from the authme service
 */
public class AuthListAdapter extends ArrayAdapter<SvcSession>
        implements AuthMeService.Callbacks {

    // For logging
    public static final String TAG = "AuthListAdapter";

    private ArrayList<SvcSession> auths;
    private Context context;
    private MasterPassword _masterPassword;
    private AuthMeService _authme;

    public AuthListAdapter(Context context, int textViewResourceId, ArrayList<SvcSession> auths) {

        super(context, textViewResourceId, auths);
        this.auths = auths;
        this.context = context;
        this._masterPassword = MasterPassword.getInstance();
        _authme = new AuthMeService(context);

    }

    public boolean loadAuths() {

        /* First make sure we have everything we need to talk to the service */
        Log.v(TAG, "Ready to load - waiting on master password");
        _masterPassword.waitOnLoad();
        Log.v(TAG, "Master password has released lock");

        /* OK - now we load the service list */
        return _authme.getAuthChecks(this);

    }

    public void internalSync() {

        /* Always clear and reload */

        clear();
        notifyDataSetInvalidated();

        if (auths != null) {
            for (SvcSession auth : auths)
                add(auth);
        }

        Log.v(TAG, "Notifying data set changed");
        notifyDataSetChanged();
    }

    @SuppressLint("SetTextI18n")
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {

        View v = convertView;
        if (v == null) {
            LayoutInflater vi = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            v = vi.inflate(R.layout.auth_list_item, null);
        }

        SvcSession ss = auths.get(position);
        if (ss != null) {
            TextView ttl = (TextView) v.findViewById(R.id.toptextleft);
            TextView ttr = (TextView) v.findViewById(R.id.toptextright);
            TextView bt = (TextView) v.findViewById(R.id.bottomtext);

            /* Let's make the date/time something we can use locally */
            Date date = org.authme.util.AuthMeUtils.makeLocalDate(ss.getServerDate());
            String serverDate;
            if (date != null) {
                DateFormat df = new SimpleDateFormat("hh:mm aa");
                serverDate = df.format(date);
            }
            else
                serverDate = "<no date>";

            if (ttl != null)
                ttl.setText(ss.getServerId());
            if (ttr != null)
                ttr.setText(serverDate);
            if (bt != null)
                if (!"".equals(ss.getWrappedSecret()) && ss.getWrappedSecret() != null) {
                    bt.setText("Server String: " + ss.getServerString() + " (*)");
                }
                else {
                    bt.setText("Server String: " + ss.getServerString());
                }
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

        if (responseEvent instanceof AuthCheckListDetailsEvent) {

            auths = ((AuthCheckListDetailsEvent) responseEvent).getAuthChecks();
            Timber.d("Received auths list with " + auths.size() + " auths");
            this.internalSync();
        }

    }
}
