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

namespace AuthMeGUI
{
    /// <summary>
    /// Interaction logic for KeyGenerationParametersWindow.xaml
    /// </summary>
    public partial class KeyGenerationParametersWindow : Window
    {

        public bool okPressed = false;

        public KeyGenerationParametersWindow()
        {
            InitializeComponent();
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {

        }

        private void fileButton_Click(object sender, RoutedEventArgs e)
        {

            /* That's the default - but let the user select something else if they want */
            Microsoft.Win32.SaveFileDialog dlg = new Microsoft.Win32.SaveFileDialog();

            dlg.DefaultExt = ".key";
            dlg.FileName = keyFilenameTextBox.Text;
            dlg.InitialDirectory = Path.GetDirectoryName(keyFilenameTextBox.Text);

            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                keyFilenameTextBox.Text = dlg.FileName;

                /* Now do the generate */

            }

        }

        private void cancelButton_Click(object sender, RoutedEventArgs e)
        {
            okPressed = false;
            this.Close();
        }

        private void okButton_Click(object sender, RoutedEventArgs e)
        {
            if (firstPasswordBox.Password != secondPasswordBox.Password)
            {
                errorTextBlock.Text = "Passwords must match";
                return;
            }

            okPressed = true;
            this.Close();
        }
    }
}
