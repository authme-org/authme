package org.authme.android.service;

import android.os.Handler;
import android.os.Message;

import java.lang.ref.WeakReference;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Created by Berin on 27/02/2016.
 *
 * Manage the requests out to the AuthMe service
 */
public class AuthMeServiceManager {

    public static final int TASK_COMPLETE = 1;

    private static final int POOL_CORE_SIZE = 6;
    private static final int POOL_MAX_SIZE = 10;

    /* Thread variables */
    BlockingQueue<Runnable> serviceQueue;
    ThreadPoolExecutor servicePool;
    Handler serviceHandler;

    private AuthMeServiceManager() {

        serviceQueue = new LinkedBlockingQueue<>();
        servicePool = new ThreadPoolExecutor(
                POOL_CORE_SIZE,
                POOL_MAX_SIZE,
                1,
                TimeUnit.SECONDS,
                serviceQueue
        );

        serviceHandler = new AuthMeHandler(this);
    }

    public void executeAuthMeServiceTask(AuthMeServiceTask task) {
        task.setHandler(serviceHandler);
        servicePool.execute(task);
    }


    /* To implement the Initialization on Demand Holder pattern */
    private static class LazyHolder {
        private static final AuthMeServiceManager instance = new AuthMeServiceManager();
    }

    public static AuthMeServiceManager getInstance() {
        return LazyHolder.instance;
    }

    private static class AuthMeHandler extends Handler {


        @SuppressWarnings("unused")
        private WeakReference<AuthMeServiceManager> mManager;

        AuthMeHandler(AuthMeServiceManager manager) {
            mManager = new WeakReference<>(manager);
        }

        @Override
        public void handleMessage(Message inputMessage) {
            AuthMeServiceTask task = (AuthMeServiceTask) inputMessage.obj;

            if (task.getCallbacks() != null) {
                task.getCallbacks().onAuthMeServiceReturn(task.getEvent());
            }
        }
    }

}
