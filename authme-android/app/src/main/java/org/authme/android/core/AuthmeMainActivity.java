package org.authme.android.core;


import android.app.Activity;
import android.app.Dialog;
import android.content.Intent;
import android.preference.PreferenceManager;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarActivity;
import android.support.v7.app.ActionBar;

import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import org.authme.android.R;
import org.authme.android.service.MasterPassword;

public class AuthmeMainActivity extends ActionBarActivity
        implements NavigationDrawerFragment.NavigationDrawerCallbacks {

    /**
     * Fragment managing the behaviors, interactions and presentation of the navigation drawer.
     */

    private NavigationDrawerFragment mNavigationDrawerFragment;


    /**
     * Used to store the last screen title. For use in {@link #restoreActionBar()}.
     */
    private CharSequence mTitle;

    /**
     * Whether or not the activity is in two-pane mode, i.e. running on a tablet
     * device.
     */
    private boolean mTwoPane;

    /**
     * When in twoPane mode need to know if detail is showing
     */

    private int fragmentStackSize = 0;
    private int fragmentResId = 0;
    private boolean menuShown = true;
    private Dialog currentAlert = null;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

                /* Load default pref_service */
        PreferenceManager.setDefaultValues(this, R.xml.pref_service, false);

        /* Start the loading sequence */
        MasterPassword _masterPassword = MasterPassword.getInstance();
        _masterPassword.init(this, getApplicationContext());

        /* Startup the initial fragments */

        setContentView(R.layout.authme_main);

        mNavigationDrawerFragment = (NavigationDrawerFragment)
                getSupportFragmentManager().findFragmentById(R.id.navigation_drawer);
        mTitle = getTitle();

        // Set up the drawer.
        mNavigationDrawerFragment.setUp(
                R.id.navigation_drawer,
                (DrawerLayout) findViewById(R.id.drawer_layout));

    }

    @Override
    public void onNavigationDrawerItemSelected(int position) {
        // update the main content by replacing fragments
        FragmentManager fragmentManager = getSupportFragmentManager();

        switch (position) {

            case 0:
                fragmentManager.beginTransaction()
                        //.replace(R.id.container, new ItemListFragment())
                        .replace(R.id.container, new AuthListFragment(), getString(R.string.auths_container_tag))
                        .commit();
                break;

            case 1:
                fragmentManager.beginTransaction()
                        //.replace(R.id.container, new ItemListFragment())
                        .replace(R.id.container, new DeviceListFragment(), getString(R.string.devices_container_tag))
                        .commit();
                break;

                /*
                fragmentResId = R.id.container;
                FeedTrendingFragment fragment = new FeedTrendingFragment();
                fragment.setCallbacks(this);
                fragmentManager.beginTransaction()
                        .replace(R.id.container, fragment, "trending_container")
                        .commit();
                        */
            default:
                // SHort term holder
                fragmentManager.beginTransaction()
                        .replace(R.id.container, PlaceholderFragment.newInstance(position + 1))
                        .commit();
        }
    }

    public void onSectionAttached(int number) {
        switch (number) {
            case 1:
                mTitle = getString(R.string.title_section1);
                menuShown = true;
                break;
            case 2:
                mTitle = getString(R.string.title_section2);
                menuShown = false;
                break;
            case 3:
                mTitle = getString(R.string.title_section3);
                menuShown = false;
                break;

        }
    }

    public void restoreActionBar() {
        ActionBar actionBar = getSupportActionBar();
        //actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_STANDARD);
        actionBar.setDisplayShowTitleEnabled(true);
        actionBar.setTitle(mTitle);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        if (!mNavigationDrawerFragment.isDrawerOpen()) {
            // Only show items in the action bar relevant to this screen
            // if the drawer is not showing. Otherwise, let the drawer
            // decide what to show in the action bar.
            if (menuShown) {
                getMenuInflater().inflate(R.menu.menu_authme_main, menu);
            }
            else {
                getMenuInflater().inflate(R.menu.global, menu);
            }
            restoreActionBar();

            return true;
        }

        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {

            Intent intent = new Intent(this, ConfigurationActivity.class);
            startActivity(intent);

            return true;
        }

        /*
        if (id == R.id.action_load_feeds) {
            Timber.v("Load user feeds requested");

            // Set a request to the user
            AlertDialog dialog = new AlertDialog.Builder(this)
                    .setTitle("Load Feeds from Service")
                    .setMessage("This will retrieve your feed configuration from the readercom service and delete current configuration.\n\nAre you sure?")
                    .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            currentAlert = ProgressDialog.show(MainActivity.this, "Loading Feeds", "Retrieving feeds from readercom service", true);
                            Configuration.sharedInstance().feedController.registerAlertHandler(MainActivity.this);
                            Configuration.sharedInstance().feedController.loadFeedsFromService(true);
                        }
                    })
                    .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            // just exit
                        }
                    })
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .show();

            TextView msgView = (TextView) dialog.findViewById(android.R.id.message);
            msgView.setGravity(Gravity.CENTER);

            return true;
        }

        if (id == R.id.action_save_feeds) {
            Timber.v("Save user feeds requested");

            // Make sure the user really wants to do this
            // Set a request to the user
            AlertDialog dialog = new AlertDialog.Builder(this)
                    .setTitle("Save Feed configuration")
                    .setMessage("This will save your feed configuration to the readercom service.\n\nAre you sure?")
                    .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            Configuration.sharedInstance().feedController.saveFeedsToService();
                        }
                    })
                    .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            // just exit
                        }
                    })
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .show();

            TextView msgView = (TextView) dialog.findViewById(android.R.id.message);
            msgView.setGravity(Gravity.CENTER);

            return true;
        }
        */

        if (id == android.R.id.home) {
            if (fragmentStackSize > 0) {
                getSupportFragmentManager().popBackStackImmediate();
                if (--fragmentStackSize == 0) {
                    mNavigationDrawerFragment.setDrawerIndicatorEnabled(true);
                    menuShown = true;
                    invalidateOptionsMenu();
                }

                return true;
            }
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        if (fragmentStackSize > 0) {
            if (--fragmentStackSize == 0) {
                mNavigationDrawerFragment.setDrawerIndicatorEnabled(true);
                menuShown = true;
                invalidateOptionsMenu();
            }
        }
    }

    /**
     * A placeholder fragment containing a simple view.
     */
    public static class PlaceholderFragment extends Fragment {
        /**
         * The fragment argument representing the section number for this
         * fragment.
         */
        private static final String ARG_SECTION_NUMBER = "section_number";

        /**
         * Returns a new instance of this fragment for the given section
         * number.
         */
        public static PlaceholderFragment newInstance(int sectionNumber) {
            PlaceholderFragment fragment = new PlaceholderFragment();
            Bundle args = new Bundle();
            args.putInt(ARG_SECTION_NUMBER, sectionNumber);
            fragment.setArguments(args);
            return fragment;
        }

        public PlaceholderFragment() {
        }

        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container,
                                 Bundle savedInstanceState) {
            return inflater.inflate(R.layout.fragment_main, container, false);
        }

        @Override
        public void onAttach(Activity activity) {
            super.onAttach(activity);
            ((AuthmeMainActivity) activity).onSectionAttached(
                    getArguments().getInt(ARG_SECTION_NUMBER));
        }
    }

    /**
     * Callback method from {@link //FeedListFragment.Callbacks}
     * indicating that the item with the given ID was selected.
     */
    //@Override
    public void onItemSelected(int position) {

        /**
        Configuration appConfiguration = Configuration.sharedInstance();
        if (appConfiguration.feedController.checkAndSetActiveFeed(position)) {

            if (mTwoPane) {

                fragmentResId = R.id.item_detail_container;
                FragmentManager fm = getSupportFragmentManager();
                // First - do we have to pop anything that is displayed?
                if (fragmentStackSize > 0) {
                    // Yup
                    while (fragmentStackSize > 0) {
                        fm.popBackStackImmediate();
                        fragmentStackSize -= 1;
                    }

                    mNavigationDrawerFragment.setDrawerIndicatorEnabled(true);

                }

                // In two-pane mode, show the detail view in this activity by
                // adding or replacing the detail fragment using a
                // fragment transaction.
                Bundle arguments = new Bundle();
                arguments.putString(FeedDetailFragment.ARG_ITEM_ID, "TEMP STRING");
                FeedDetailFragment fragment = new FeedDetailFragment();
                fragment.setArguments(arguments);
                fragment.setCallbacks(this);
                getSupportFragmentManager().beginTransaction()
                        .replace(R.id.item_detail_container, fragment)
                        .commit();

            } else {
                // In single-pane mode, simply start the detail activity
                // for the selected item ID.

                fragmentResId = R.id.item_list;
                Bundle arguments = new Bundle();
                arguments.putString(FeedDetailFragment.ARG_ITEM_ID, "TEMP STRING");
                FeedDetailFragment fragment = new FeedDetailFragment();
                fragment.setArguments(arguments);
                fragment.setCallbacks(this);
                fragmentLoad(fragment);

            }
        }
         */
    }

    /**
     * Fragment push/pop
     */

    public void fragmentLoad(Fragment fragment) {

        getSupportFragmentManager().beginTransaction()
                .replace(fragmentResId, fragment)
                .addToBackStack(null)
                .commit();

        fragmentStackSize++;
        if (fragmentStackSize == 1) {
            mNavigationDrawerFragment.setDrawerIndicatorEnabled(false);
            getSupportActionBar().setHomeButtonEnabled(true);
            menuShown = false;
            invalidateOptionsMenu();
        }

    }

    /**
     * Alert HAndling
     */

    //@Override
    public void dismissAlert() {

        if (currentAlert != null) {
            currentAlert.dismiss();
            currentAlert = null;
        }

        /**
        Configuration.sharedInstance().feedController.unregisterAlertHandler();
         */
    }
}
