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
    /// Interaction logic for PropertiesServiceSettingsPage.xaml
    /// </summary>
    public partial class PropertiesServiceSettingsPage : Page, AuthmePropertyPageInterface
    {

        AuthMe authMe;

        public PropertiesServiceSettingsPage(AuthMe authMe)
        {
            InitializeComponent();
            this.authMe = authMe;
            urlTextBox.Text = authMe.getURL();
            userIdTextBox.Text = authMe.getUserId();
        }

        public void updateAuthMe()
        {
            authMe.setURL(urlTextBox.Text);
            authMe.setUserId(userIdTextBox.Text);
        }
    }
}
