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
using System.IO;
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

using AuthMeDLL;

namespace AuthMeGUI
{
    /// <summary>
    /// Interaction logic for PropertiesLocalKeysPage.xaml
    /// </summary>
    public partial class PropertiesLocalKeysPage : Page, AuthmePropertyPageInterface
    {

        AuthMe authMe;

        public PropertiesLocalKeysPage(AuthMe authMe)
        {
            InitializeComponent();
            this.authMe = authMe;
            keyFileTextBox.Text = authMe.getKeyFileName();
            if (authMe.keyFileLoaded())
            {
                keyFileTextBlock.Text = "";
            }
            else
            {
                keyFileTextBlock.Text = "No key loaded - do you want to generate a new key?";
            }
        }

        public void updateAuthMe()
        {
            authMe.setKeyFileName(keyFileTextBox.Text);
        }

        private void generateKeyButton_Click(object sender, RoutedEventArgs e)
        {

            KeyGenerationParametersWindow kgpw = new KeyGenerationParametersWindow();

            /* First find where to save */
            String defaultPath = authMe.getDefaultKeyFileName();
            String fileName = "";

            if (keyFileTextBox.Text == "" || keyFileTextBox.Text == null)
                kgpw.keyFilenameTextBox.Text = defaultPath;
            else
                kgpw.keyFilenameTextBox.Text = keyFileTextBox.Text;

            kgpw.ShowDialog();
            if (kgpw.okPressed)
            {
                if (authMe.generateKeyFile(kgpw.keyFilenameTextBox.Text, kgpw.firstPasswordBox.Password != "" ? kgpw.firstPasswordBox.Password : null))
                {
                    keyFileTextBox.Text = kgpw.keyFilenameTextBox.Text;
                    keyFileTextBlock.Text = "Key generated";

                    if (kgpw.saveCheckBox.IsChecked == true)
                    {
                        authMe.setProtectedKeyFilePassword(kgpw.firstPasswordBox.Password);
                    }

                    // Need to save out the config to capture the filename
                    authMe.saveUserCnf();
                }
                else
                {
                    keyFileTextBlock.Text = "Error generating key";
                }
            }



        }
    }
}
