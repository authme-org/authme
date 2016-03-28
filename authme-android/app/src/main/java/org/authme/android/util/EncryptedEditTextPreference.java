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

package org.authme.android.util;

import android.content.Context;
import android.preference.EditTextPreference;
import android.util.AttributeSet;
import android.util.Log;
import org.authme.android.service.MasterPassword;

/**
 * Created by IntelliJ IDEA.
 * User: berin
 * Date: 6/08/11
 * Time: 12:41 PM
 *
 * Built from
 *
 *      http://stackoverflow.com/questions/5858790/process-the-value-of-preference-before-save-in-android
 */
@SuppressWarnings({"UnusedDeclaration"})
public class EncryptedEditTextPreference extends EditTextPreference{

    // For logging
    public static final String TAG = "EncryptedTextPreference";

    MasterPassword _masterPassword;

    public EncryptedEditTextPreference(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        _masterPassword = MasterPassword.getInstance();
    }

    public EncryptedEditTextPreference(Context context, AttributeSet attrs) {
        super(context, attrs);
        _masterPassword = MasterPassword.getInstance();
    }

    public EncryptedEditTextPreference(Context context) {
        super(context);
        _masterPassword = MasterPassword.getInstance();
    }

    @Override
    public String getText() {

        String value = super.getText();
        Log.v(TAG, "Encrypted value loaded: " + value);

        /* Decrypt what we are currently holding */
        byte decryptedBytes[] = null;
        if (value != null)
            decryptedBytes = _masterPassword.masterPasswordDecrypt(value);

        /* If it didn't work, just zero the string */
        if (decryptedBytes == null || decryptedBytes.length == 0)
            return "";

        return new String(decryptedBytes);
    }

    @Override
    protected void onSetInitialValue(boolean restoreValue, Object defaultValue) {
        super.setText(restoreValue ? getPersistedString(null) : (String) defaultValue);
    }

    @Override
    public void setText(String text) {
        if (text == null || text.equals("")) {
            super.setText(null);
            return;
        }
        super.setText(_masterPassword.masterPasswordEncryptBase64(text.getBytes()));
    }
}
