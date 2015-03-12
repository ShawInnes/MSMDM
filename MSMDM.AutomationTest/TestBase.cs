using System;
using AFrame.Web;
using NUnit.Framework;
using OpenQA.Selenium;

namespace MSMDM.AutomationTest
{
    public abstract class TestBase
    {
        public enum WebDriverType
        {
            Chrome,
            Safari,
            InternetExplorer,
            FireFox,
            PhantomJs
        }
        
        private WebDriverType driverType;

        public WebDriverType DriverType { get; set; }

        /// 
        /// Initializes the context only once and only when needed
        /// 
        private WebContext webContext;
        public WebContext WebContext
        {
            get
            {
                if (this.webContext == null)
                {
                    IWebDriver driver;
                    switch (DriverType)
                    {
                        case WebDriverType.Chrome:
                            driver = new OpenQA.Selenium.Chrome.ChromeDriver();
                            break;
                        case WebDriverType.InternetExplorer:
                            driver = new OpenQA.Selenium.IE.InternetExplorerDriver();
                            break;
                        case WebDriverType.FireFox:
                            driver = new OpenQA.Selenium.Firefox.FirefoxDriver();
                            break;
                        case WebDriverType.PhantomJs:
                            driver = new OpenQA.Selenium.PhantomJS.PhantomJSDriver();
                            break;
                        case WebDriverType.Safari:
                            driver = new OpenQA.Selenium.Safari.SafariDriver();
                            break;
                        default:
                            driver = new OpenQA.Selenium.Chrome.ChromeDriver();
                            break;
                    }
                    this.webContext = new WebContext(driver);
                }
                return this.webContext;
            }
        }

        [SetUp]
        public void TestSetUp()
        {
        }

        [TearDown]
        public void TestTearDown()
        {
            this.WebContext.Dispose();
        }

        [TestFixtureSetUp]
        public void FixtureSetUp()
        {
            string pathSegment = @"c:\selenium;C:\Chocolatey\lib\PhantomJS.2.0.0\tools\phantomjs-2.0.0-windows\bin";
            string allPaths = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Process);
            if (allPaths != null)
                allPaths = allPaths + ";" + pathSegment;
            else
                allPaths = pathSegment;

            Environment.SetEnvironmentVariable("PATH", allPaths, EnvironmentVariableTarget.Process);
        }
    }
}