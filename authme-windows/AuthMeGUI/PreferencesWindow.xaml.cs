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
using System.Windows.Shapes;

using AuthMeDLL;

namespace AuthMeGUI
{
    /// <summary>
    /// Interaction logic for PreferencesWindow.xaml
    /// </summary>
    public partial class PreferencesWindow : Window
    {

        AuthMe authMe;

        /* The pages we have loaded */
        AuthmePropertyPageInterface currentPage = null;

        public PreferencesWindow(AuthMe authMe)
        {
            InitializeComponent();
            propertyFrame.NavigationUIVisibility = System.Windows.Navigation.NavigationUIVisibility.Hidden;
            this.authMe = authMe;
        }

        private void settingsListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (settingsListBox.SelectedIndex != -1)
            {
                switch (settingsListBox.SelectedIndex)
                {
                    case 0:
                        PropertiesServiceSettingsPage pssp = new PropertiesServiceSettingsPage(authMe);
                        currentPage = pssp;
                        propertyFrame.Navigate(pssp);
                        break;
                    case 1:
                        PropertiesLocalKeysPage plkp = new PropertiesLocalKeysPage(authMe);
                        currentPage = plkp;
                        propertyFrame.Navigate(plkp);
                        break;
                    default:
                        break;
                }
            }
        }

        private void okButton_Click(object sender, RoutedEventArgs e)
        {
            if (currentPage != null)
            {
                currentPage.updateAuthMe();
                authMe.saveUserCnf();
            }
            this.Close();
        }

        private void cancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void applyButton_Click(object sender, RoutedEventArgs e)
        {
            if (currentPage != null)
            {
                currentPage.updateAuthMe();
                authMe.saveUserCnf();
            }
        }
    }
}
