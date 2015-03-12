using MSMDM.AutomationTest.Modules;
using NUnit.Framework;
using Shouldly;

namespace MSMDM.AutomationTest.Tests
{
    [TestFixture]
    public class HomePageTests : TestBase
    {
        private string url = "http://msmdm.localhost";

        [Test]
        [TestCase(WebDriverType.Chrome)]
        [TestCase(WebDriverType.InternetExplorer)]
        [TestCase(WebDriverType.PhantomJs)]
        public void EnrollmentLinkExists(WebDriverType driverType)
        {
            this.DriverType = driverType;

            // Arrange
            var homePage = this.WebContext.NavigateTo<HomePage>(url);
            //var enrollmentPage = this.WebContext.As<EnrollmentPage>();

            // Act
            // homePage.ClickEnrollmentLink();

            // Assert
            homePage.EnrollmentLink.Exists.ShouldBe(true);
        }
    }
}