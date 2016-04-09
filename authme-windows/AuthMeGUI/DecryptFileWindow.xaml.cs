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

using AuthMeDLL;

namespace AuthMeGUI
{
    /// <summary>
    /// Interaction logic for EncryptFileWindow.xaml
    /// </summary>
    public partial class DecryptFileWindow : Window
    {
        bool didDecrypt = false;
        AuthMe authMe;

        public DecryptFileWindow(AuthMe authMe)
        {
            InitializeComponent();
            this.authMe = authMe;
            userIdTextBox.Text = authMe.getUserId();
        }

        private void cancelButtonPressed(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void inputFileButtonPressed(object sender, RoutedEventArgs e)
        {
            /* That's the default - but let the user select something else if they want */
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            dlg.DefaultExt = ".ame";
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                inputFileTextBox.Text = dlg.FileName;
                if (outputFileTextBox.Text == null || outputFileTextBox.Text == "")
                {
                    if (Path.GetExtension(inputFileTextBox.Text) == ".ame")
                        outputFileTextBox.Text = Path.ChangeExtension(inputFileTextBox.Text, null);
                    else
                        outputFileTextBox.Text = dlg.FileName + ".decrypt";
                }
            }

        }

        private void outputFileButtonPressed(object sender, RoutedEventArgs e)
        {
            /* That's the default - but let the user select something else if they want */
            Microsoft.Win32.SaveFileDialog dlg = new Microsoft.Win32.SaveFileDialog();

            if (outputFileTextBox.Text != null && outputFileTextBox.Text != "")
            {
                dlg.FileName = outputFileTextBox.Text;
                dlg.InitialDirectory = Path.GetDirectoryName(outputFileTextBox.Text);
            }
            else
            {
                dlg.FileName = "";
                dlg.InitialDirectory = "";
            }
            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                outputFileTextBox.Text = dlg.FileName;
            }

        }

        private void decryptButtonPressed(object sender, RoutedEventArgs e)
        {
            if (inputFileTextBox.Text == "" || inputFileTextBox.Text == null)
            {
                errorTextBlock.Text = "Input filename is required";
                return;
            }

            if (outputFileTextBox.Text == "" || outputFileTextBox.Text == null)
            {
                errorTextBlock.Text = "Output filename is required";
                return;
            }

            if (userIdTextBox.Text.Length < 3 || !userIdTextBox.Text.Any(c => c == '@'))
            {
                errorTextBlock.Text = "User ID must be a valid email address";
                return;
            }

            /* Do the actual decrypt */
            authMe.setServerString("Filename: " + inputFileTextBox.Text);
            authMe.setServerId("GUI File Decrypt");
            int res = authMe.doDecryptFile(inputFileTextBox.Text, outputFileTextBox.Text);
            if (res != AuthMe.AUTHME_ERRC_OK)
            {
                errorTextBlock.Text = "Error from AuthMe Library: " + authMe.getLastError();
                return;
            }

            this.Close();
        }

    }
}
