using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AFrame.Web;
using AFrame.Web.Controls;

namespace MSMDM.AutomationTest.Modules
{
    public class EnrollmentPage : WebControl
    {
        public WebControl EnrollmentLink { get { return this.CreateControl("a[id='enrollment']"); } }

        public EnrollmentPage(WebContext webContext)
            : base(webContext)
        { }
    }
}
