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

import android.util.Log;

import org.authme.android.core.AuthListAdapter;
import org.authme.entity.SvcSession;
import org.authme.event.AuthCheckUpdatedEvent;
import org.authme.event.DeviceAddedEvent;
import org.authme.event.ResponseEvent;

import timber.log.Timber;

/**
 * Created by User on 27/02/2016.
 *
 * Encapsulates logic to update a specific authorisation
 */

public class AuthUpdater implements AuthMeSign.SigningCallbacks, AuthMeService.Callbacks {

    AuthMeService _authme = null;
    AuthListAdapter authList = null;
    String unwrappedSecret = null;

    SvcSession ss;

    public AuthUpdater(AuthListAdapter adapter) {
        _authme = adapter.getAuthMeService();
        authList = adapter;
    }

    private AuthUpdater(){
        /* SHould never be called */
    }

    public boolean doUpdate(SvcSession input) {

        ss = input;

        /* Is there a secret to unwrap? */
        if (ss.getWrappedSecret() != null &&
                !"".equals(ss.getWrappedSecret()) &&
                ss.getStatus().equals("APPROVED")) {
            unwrappedSecret =
                    MasterPassword.getInstance().masterPasswordUnwrapSecret(ss.getWrappedSecret());
        }

        if (unwrappedSecret == null)
            unwrappedSecret = "";

        /* First we sign the relevant data */
        AuthMeSign signer = new AuthMeSign();
        if (!signer.doSign(ss.getCheckId() + ss.getServerNonce() + ss.getStatus() + unwrappedSecret, MasterPassword.getInstance().getServiceKeyPair(), this))
            return false;

        return true;

    }

    /* Callback interfaces */
    public void onSignatureReturn(AuthMeSign signer) {
        _authme.setAuthCheckStatus(ss.getCheckId(), ss.getStatus(), unwrappedSecret, signer, this);
        unwrappedSecret = null;
    }

    public void onAuthMeServiceReturn(ResponseEvent responseEvent) {

        Timber.d("Received response event in auth updater");

        if (responseEvent == null || !responseEvent.getSuccess()) {
            Timber.d("Error in AuthMe response");
            return;
        }

        if (responseEvent instanceof AuthCheckUpdatedEvent) {
            /* We updated something - reload */
            authList.loadAuths();
        }
    }
}
