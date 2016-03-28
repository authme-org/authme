/*
*
* Copyright 2015 Berin Lautenbach
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using AuthMeDLL;

namespace AuthMeGUI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private AuthMe authMe;
        private String authMeDefaultURI = "https://www.authme.org/AuthMeWS/Svc"; //"http://pluto.wingsofhermes.org:8080/AuthMeWS/Svc";

        public MainWindow()
        {
            InitializeComponent();
            authMe = new AuthMe();
            serviceOutputTextBlock.Text = "";

            /* Load a configuration file for current user */
            if (authMe.loadUserCnf() == AuthMe.AUTHME_ERRC_FILE_OPEN)
            {
                /* Need to create our own config */
                authMe.setURL(authMeDefaultURI);
                authMe.saveUserCnf();
            }

            /* Try to load the master password if we can */
            if (authMe.loadMasterPassword(null, true) == true)
                serviceOutputTextBlock.Text = "Local keyset loaded";

            URIInput.Text = authMe.getURL();

        }

        private void PingClick(object sender, RoutedEventArgs e)
        {
            authMe.setURL(URIInput.Text);
            String result = authMe.doPing();
            serviceOutputTextBlock.Text += "\n" + result;
            serviceOutputScroller.ScrollToEnd();
        }

        private void PreferencesMenuSelect(object sender, RoutedEventArgs e)
        {
            PreferencesWindow pw = new PreferencesWindow(authMe);
            pw.ShowDialog();
            URIInput.Text = authMe.getURL();

        }

        private void FileExitMenuSelect(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void HelpAboutMenuSelect(object sender, RoutedEventArgs e)
        {
            new AboutWindow().ShowDialog();
        }

        private void FileEncryptMenuSelect(object sender, RoutedEventArgs e)
        {
            EncryptFileWindow efw = new EncryptFileWindow(authMe);
            efw.Show();
        }
        private void FileDecryptMenuSelect(object sender, RoutedEventArgs e)
        {
            DecryptFileWindow dfw = new DecryptFileWindow(authMe);
            dfw.Show();
        }
    }
}