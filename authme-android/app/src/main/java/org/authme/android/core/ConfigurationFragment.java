/*
 * Copyright 2015 Berin Lautenbach
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
 */package org.authme.android.core;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.preference.CheckBoxPreference;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.view.Gravity;
import android.widget.TextView;

import org.authme.android.BuildConfig;
import org.authme.android.R;
import org.authme.android.service.MasterPassword;
import org.authme.android.util.EncryptedEditTextPreference;

import timber.log.Timber;

/**
 * Created by Berin on 27/02/2016.
 *
 */

@SuppressWarnings("FieldCanBeLocal")
public class ConfigurationFragment extends PreferenceFragment {


    private static final boolean ALWAYS_SIMPLE_PREFS = true;

    private PreferenceCategory usernamePreferenceCategory = null;
    CheckBoxPreference newUserPreference = null;

    private EncryptedEditTextPreference passwordEditText = null;
    private EncryptedEditTextPreference passwordRepeatEditText = null;

    private EditTextPreference emailEditText = null;
    private EditTextPreference nameEditText = null;

    private Preference actionCreatePreference = null;
    private Dialog currentAlert = null;

    private boolean inSetup = true;

    public Activity myActivity = null;

    @Override
    public void onCreate(Bundle paramBundle) {
        super.onCreate(paramBundle);

        setupSimplePreferencesScreen();

    }

    /**
     * Shows the simplified settings UI if the device configuration if the
     * device configuration dictates that a simplified, single-pane UI should be
     * shown.
     */
    private void setupSimplePreferencesScreen() {

        inSetup = true;
        final Context context = MasterPassword.getInstance().getApplicationContext();

        if (context == null) {
            Timber.e("Context null in setup fragment = bailing out");
            return;
        }
        if (!isSimplePreferences(context)) {
            return;
        }

        // In the simplified UI, fragments are not used at all and we instead
        // use the older PreferenceActivity APIs.

        // Add 'service' pref_service.
        PreferenceCategory fakeHeader = new PreferenceCategory(context);
        fakeHeader.setTitle(R.string.pref_header_service);
        addPreferencesFromResource(R.xml.pref_service);

        // Clear the new user flag
        newUserPreference = (CheckBoxPreference) findPreference("create_new_user_checkbox");
        newUserPreference.setChecked(false);

        // Now remove the "create new user" preference
        usernamePreferenceCategory = (PreferenceCategory) findPreference("username_category");

        passwordRepeatEditText = (EncryptedEditTextPreference) findPreference("authmePasswordRepeat");
        nameEditText = (EditTextPreference) findPreference("authmeName");
        actionCreatePreference = findPreference("action_create");
        emailEditText = (EditTextPreference) findPreference("authmeUsername");
        passwordEditText = (EncryptedEditTextPreference) findPreference("authmePassword");

        usernamePreferenceCategory.removePreference(passwordRepeatEditText);
        usernamePreferenceCategory.removePreference(nameEditText);
        usernamePreferenceCategory.removePreference(actionCreatePreference);

        // And set the appropriate listener
        newUserPreference.setOnPreferenceChangeListener(enableNewUserValueListener);

        if (BuildConfig.DEBUG) {
            // Add debug pref_service, and a corresponding header.
            addPreferencesFromResource(R.xml.pref_debug);
            fakeHeader.setEnabled(true);
        }

        // Bind the summaries of EditText/List/Dialog/Ringtone pref_service to
        // their values. When their values change, their summaries are updated
        // to reflect the new value, per the Android Design guidelines.

        bindPreferenceSummaryToValue(emailEditText);
        bindPreferenceSummaryToValue(passwordEditText);
        bindPreferenceSummaryToValue(passwordRepeatEditText);
        bindPreferenceSummaryToValue(nameEditText);

        inSetup = false;

        // Create an on-click listener to activate when the user hits create
        actionCreatePreference.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {

                /* To allow decrypts */
                MasterPassword _masterPassword = MasterPassword.getInstance();

                /* First load the strings */
                SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(context);

                String error = "";

                String primaryEmail = sp.getString("authmeUsername", "");
                String name = sp.getString("authmeName", "");

                String password = _masterPassword.masterPasswordDecryptToString(sp.getString("authmePassword", ""));
                String passwordRepeat = _masterPassword.masterPasswordDecryptToString(sp.getString("authmePasswordRepeat", ""));

                /* Now do some checks */
                if ("".equals(name)) {
                    error = "Name cannot be blank";
                }
                if ("".equals(password) || password == null || passwordRepeat.equals(password) || password.length() < 6) {
                    error = "Password and password repeat must match and be greater than 5 characters";
                }
                if (primaryEmail == null || primaryEmail.equals("") || !primaryEmail.contains("@")) {
                    error = "Email address cannot be blank and must contain an '@' character";
                }

                if (!error.equals("")) {
                    new AlertDialog.Builder(myActivity)
                            .setTitle("Error Creating User")
                            .setMessage(error)
                            .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    // just exit
                                }
                            })
                            .setIcon(android.R.drawable.ic_dialog_alert)
                            .show();

                    return true;
                }

                // Good to go - create
                /*authme.createUser(primaryEmail, name, userId, password, SettingsFragment.this);
                currentAlert = ProgressDialog.show(myActivity, "Creating User", "Request to create user sent to Readercom service", true);
                */

                return true;
            }
        });

    }

    /*
    @Override
    public boolean onIsMultiPane() {
        Context context = Configuration.getContext();
        return isXLargeTablet(context) && !isSimplePreferences(context);
    }
*/

    /**
     * Helper method to determine if the device has an extra-large screen. For
     * example, 10" tablets are extra-large.
     */
    private static boolean isXLargeTablet(Context context) {
        return (context.getResources().getConfiguration().screenLayout
                & android.content.res.Configuration.SCREENLAYOUT_SIZE_MASK) >= android.content.res.Configuration.SCREENLAYOUT_SIZE_XLARGE;
    }

    /**
     * Determines whether the simplified settings UI should be shown. This is
     * true if this is forced via {@link #ALWAYS_SIMPLE_PREFS}, or the device
     * doesn't have newer APIs like {@link PreferenceFragment}, or the device
     * doesn't have an extra-large screen. In these cases, a single-pane
     * "simplified" settings UI should be shown.
     */
    private static boolean isSimplePreferences(Context context) {
        //noinspection PointlessBooleanExpression,ConstantConditions
        return ALWAYS_SIMPLE_PREFS
                || Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB
                || !isXLargeTablet(context);
    }

/*
    @Override
    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    public void onBuildHeaders(List<Header> target) {
        if (!isSimplePreferences(this)) {
            loadHeadersFromResource(R.xml.pref_headers, target);
        }
    }
*/

    /**
     * A preference value change listener that updates the preference's summary
     * to reflect its new value.
     */
    private Preference.OnPreferenceChangeListener bindPreferenceSummaryToValueListener = new Preference.OnPreferenceChangeListener() {
        @Override
        public boolean onPreferenceChange(Preference preference, Object value) {
            String stringValue = value.toString();

            if (preference instanceof ListPreference) {
                // For list pref_service, look up the correct display value in
                // the preference's 'entries' list.
                ListPreference listPreference = (ListPreference) preference;
                int index = listPreference.findIndexOfValue(stringValue);

                // Set the summary to reflect the new value.
                preference.setSummary(
                        index >= 0
                                ? listPreference.getEntries()[index]
                                : null);

            } else {
                // For all other pref_service, set the summary to the value's
                // simple string representation.
                String toSet = stringValue;
                if (toSet.equals("")) {
                    String defaultSummary = preference.getKey().replaceAll("readercom", "pref_description");
                    int resource = getResources().getIdentifier(defaultSummary, "string", (myActivity == null ? "" : myActivity.getPackageName()));
                    if (resource > 0)
                        toSet = getString(resource);
                    else
                        toSet = "";
                } else if (preference instanceof EncryptedEditTextPreference) {
                    toSet = "******";
                }
                preference.setSummary(toSet);

                /* Now check if username or password - if so we need to do some extra stuff */
                if ((preference.getKey().equals("authmeUsername") ||
                        preference.getKey().equals("authmePassword")) &&
                        !newUserPreference.isChecked() &&
                        !inSetup) {

                    String username;
                    String password;

                    /* First load the strings */
                    MasterPassword _masterPassword = MasterPassword.getInstance();
                    SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(_masterPassword.getApplicationContext());

                    if (preference.getKey().equals("authmeUsername")) {
                        username = (String) value;
                        password = _masterPassword.masterPasswordDecryptToString(sp.getString("authmePassword", ""));
                    } else {
                        username = sp.getString("authmeUsername", "");
                        password = (String) value;
                    }

                    if (!username.equals("") && !password.equals("")) {
                        /*currentAlert = new AlertDialog.Builder(myActivity)
                                .setTitle("Validating Username/Password")
                                .setMessage("Checking the username and password against service")
                                .show();
                        readercom.userQuery(username, password, SettingsFragment.this);

                        TextView msgView = (TextView) currentAlert.findViewById(android.R.id.message);
                        msgView.setGravity(Gravity.CENTER);*/
                    }
                }

            }
            return true;
        }
    };

    /**
     * A preference value change listener that enables or disables "new user" code
     */
    private Preference.OnPreferenceChangeListener enableNewUserValueListener = new Preference.OnPreferenceChangeListener() {
        @Override
        public boolean onPreferenceChange(Preference preference, Object value) {

            if (preference.getKey().equals("create_new_user_checkbox")) {

                if ((Boolean) value) {
                    usernamePreferenceCategory.addPreference(passwordRepeatEditText);
                    usernamePreferenceCategory.addPreference(nameEditText);
                    usernamePreferenceCategory.addPreference(actionCreatePreference);

                } else {
                    usernamePreferenceCategory.removePreference(passwordRepeatEditText);
                    usernamePreferenceCategory.removePreference(nameEditText);
                    usernamePreferenceCategory.removePreference(actionCreatePreference);

                }

            }

            return true;
        }
    };

    /**
     * Binds a preference's summary to its value. More specifically, when the
     * preference's value is changed, its summary (line of text below the
     * preference title) is updated to reflect the value. The summary is also
     * immediately updated upon calling this method. The exact display format is
     * dependent on the type of preference.
     *
     * @see #bindPreferenceSummaryToValueListener
     */
    private void bindPreferenceSummaryToValue(Preference preference) {
        // Set the listener to watch for value changes.
        preference.setOnPreferenceChangeListener(bindPreferenceSummaryToValueListener);

        // Trigger the listener immediately with the preference's
        // current value or description if nothing in there

        String currentValue = PreferenceManager
                .getDefaultSharedPreferences(preference.getContext())
                .getString(preference.getKey(), "");

        bindPreferenceSummaryToValueListener.onPreferenceChange(preference,
                currentValue);
    }


    /*
     * Implement the readercom return
     */
/*
    @Override
    public void onReadercomServiceReturn(ReadercomResponseEvent event) {
        Timber.v("SettingsFragment got Got service return");

        if (event == null) {
            Timber.w("Error from readercom service");
            return;
        }

        if (event instanceof UserQueryEvent) {

            if (currentAlert != null) {
                currentAlert.dismiss();
                currentAlert = null;
            }

            if (!event.getSucceeded()) {
                Timber.v("Error validating user");
                AlertDialog dialog = new AlertDialog.Builder(myActivity)
                        .setTitle("Username/Password Error")
                        .setMessage("The email and password combination you have entered is not recognised by the Readercom service")
                        .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                            }
                        })
                        .setIcon(android.R.drawable.ic_dialog_alert)
                        .show();

                TextView msgView = (TextView) dialog.findViewById(android.R.id.message);
                msgView.setGravity(Gravity.CENTER);
            }
        }

        if (event instanceof UserCreatedEvent) {

            if (currentAlert != null) {
                currentAlert.dismiss();
                currentAlert = null;
            }

            String alertTitle = "Error Creating User";
            String alertMsg = "";

            if (!event.getSucceeded()) {

                Timber.v("Event returned but Readercom failed");

                if (((UserCreatedEvent) event).getUserIdError() != null && !((UserCreatedEvent) event).getUserIdError().equals("")) {
                    alertMsg += ((UserCreatedEvent) event).getUserIdError();
                    alertMsg += "\n";
                }
                if (((UserCreatedEvent) event).getEmailError() != null) {
                    alertMsg += ((UserCreatedEvent) event).getEmailError();
                }

            }

            else {
                Timber.v("Created a new user");

                // Clear out unecessary pref_service
                CheckBoxPreference newUserPreference = (CheckBoxPreference) findPreference("create_new_user_checkbox");
                newUserPreference.setChecked(false);
                EncryptedEditTextPreference passwordRepeatPreference = (EncryptedEditTextPreference) findPreference("readercom_password_repeat");
                passwordRepeatPreference.setText("");
                EditTextPreference userIdPreference = (EditTextPreference) findPreference("readercom_userid");
                userIdPreference.setText("");
                EditTextPreference namePreference = (EditTextPreference) findPreference("readercom_name");
                namePreference.setText("");

                // Manually fire the change preference listeners
                enableNewUserValueListener.onPreferenceChange(newUserPreference, false);
                bindPreferenceSummaryToValueListener.onPreferenceChange(passwordRepeatPreference, "");
                bindPreferenceSummaryToValueListener.onPreferenceChange(userIdPreference, "");
                bindPreferenceSummaryToValueListener.onPreferenceChange(namePreference, "");

                alertTitle = "User Created";
                alertMsg = "User has been created.  You will receive an email to finalise the user.  Until this is done you will not be able to post comments or recommend articles";
            }

            // Tell the user what happened

            AlertDialog dialog = new AlertDialog.Builder(myActivity)
                    .setTitle(alertTitle)
                    .setMessage(alertMsg)
                    .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                        }
                    })
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .show();

            TextView msgView = (TextView) dialog.findViewById(android.R.id.message);
            msgView.setGravity(Gravity.CENTER);

        }

    }
*/
}
