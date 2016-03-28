package org.authme.android.service;

import android.os.Handler;
import android.os.Message;
import android.util.Base64;

import org.authme.event.AuthCheckListDetailsEvent;
import org.authme.event.AuthCheckUpdatedEvent;
import org.authme.event.DeviceAddedEvent;
import org.authme.event.DeviceDetailsEvent;
import org.authme.event.DeviceInfoListEvent;
import org.authme.event.ResponseEvent;
import org.authme.event.ServiceKeyDetailsEvent;
import org.authme.event.ServiceKeySetEvent;
import org.authme.event.SignatureSeedInfoEvent;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import timber.log.Timber;

/**
 * Created by Berin on 27/02/2016.
 *
 */
@SuppressWarnings("FieldCanBeLocal")
public class AuthMeServiceTask implements Runnable {

    /* For background tasks */
    public enum Operation {
        Unknown,
        AddDevice,
        GetDevice,
        GetServiceKey,
        GetAuthChecks,
        GetSignatureSeed,
        SetAuthCheckStatus,
        SetServiceKey,
        GetDevices
    }

    // Input data
    private String postData = "";
    private String username = "";
    private String password = "";
    private String urlString = "";

    // Output data
    private int responseCode = 0;

    private AuthMeService.Callbacks callbacks = null;
    private Operation operation = Operation.Unknown;
    private Object opaqueData = null;

    // To signal outwards
    Handler handler;
    ResponseEvent event;

    public AuthMeServiceTask(String url) {
        urlString = url;
    }


    public String connect() {

        InputStream is = null;
        DataOutputStream wr = null;

        try {

            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            /* Some basic parameters */
            connection.setReadTimeout(10000);
            connection.setConnectTimeout(15000);

            /* Authenticate? */
            if (!username.equals("") && !password.equals("")) {

                String userAndPass = username + ":" + password;
                String auth = "Basic " + Base64.encodeToString(userAndPass.getBytes(), Base64.NO_WRAP);
                connection.setRequestProperty("Authorization", auth);
            }

            /* Is this a post? */
            if (!postData.equals("")) {
                connection.setRequestMethod("PUT");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setDoOutput(true);
                wr = new DataOutputStream(connection.getOutputStream());
                wr.writeBytes(postData);
                wr.flush();
                wr.close();
                wr = null;
            }

            else {

                connection.setDoInput(true);
                connection.setRequestMethod("GET");
                connection.connect();

            }

            // Start it up
            responseCode = connection.getResponseCode();

            Timber.v("Response from URL Connection: %d", responseCode);

            if (responseCode != 200 && responseCode != 201)
                return null;

            // Get all the data
            is = connection.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            StringBuilder data = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                data.append(line);
            }

            // Done!
            return data.toString();

        } catch (Exception e) {
            Timber.v(e, "Error connecting to AuthMe service");
        }

        finally {
            if (is != null) {
                try {
                    is.close();
                } catch (Exception e) {
                    Timber.v(e, "Error closing input stream");
                }
            }
            if (wr != null) {
                try {
                    wr.close();
                } catch (Exception e) {
                    Timber.v(e, "Error closing output stream");
                }
            }
        }

        // Safety net
        return null;
    }

    /* Runnable */

    @Override
    public void run() {

        // Play nicely
        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
        Timber.v("Starting connect");
        String authmeResponse = this.connect();
        Timber.v("Connect complete");

        // Parse
        // Always create a return event - regardless of success/failure
        event = null;
        boolean parseRequired = true;       /* By default we do a JSON parse on response data */
        switch (operation) {
            case AddDevice:
                event = new DeviceAddedEvent();
                event.setSuccess(responseCode == 200 || responseCode == 201);
                parseRequired = false;
                break;

            case GetDevice:
                event = new DeviceDetailsEvent();
                break;

            case GetServiceKey:
                event = new ServiceKeyDetailsEvent();
                break;

            case GetAuthChecks:
                event = new AuthCheckListDetailsEvent();
                break;

            case GetSignatureSeed:
                event = new SignatureSeedInfoEvent();
                break;

            case SetAuthCheckStatus:
                event = new AuthCheckUpdatedEvent();
                break;

            case SetServiceKey:
                event = new ServiceKeySetEvent();
                event.setSuccess(responseCode == 200 || responseCode == 201);
                parseRequired = false;
                break;

            case GetDevices:
                event = new DeviceInfoListEvent();
                break;

            default:
                Timber.e("Unknown AuthMe operation");
        }

        if (event != null) {
            if (parseRequired && authmeResponse != null && !authmeResponse.equals("")) {
                // This appears to be successful
                try {
                    event.fromJSON(new JSONObject(authmeResponse));
                } catch (Exception e) {
                    Timber.v(e, "Error parsing readercom JSON");
                    event.setSuccess(false);
                }
            }
            else {
                event.setSuccess(!parseRequired);
            }
        }

        // Signal done
        Message doneMessage = handler.obtainMessage(AuthMeServiceManager.TASK_COMPLETE, this);
        handler.sendMessage(doneMessage);

    }
    /* Setters and Getters */

    public void setPostData(String postData) {
        this.postData = postData;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUrl() {
        return urlString;
    }

    public void setUrl(String urlString) {
        this.urlString = urlString;
    }

    public AuthMeService.Callbacks getCallbacks() {
        return callbacks;
    }

    public void setCallbacks(AuthMeService.Callbacks callbacks) {
        this.callbacks = callbacks;
    }

    public void setOperation(Operation operation) {
        this.operation = operation;
    }

    public void setOpaqueData(Object opaqueData) {
        this.opaqueData = opaqueData;
    }

    public void setHandler(Handler handler) {
        this.handler = handler;
    }

    public ResponseEvent getEvent() {
        return event;
    }
}
