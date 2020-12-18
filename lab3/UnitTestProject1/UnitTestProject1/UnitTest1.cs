using System;
using IIG.PasswordHashingUtils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        String testPassword = "test";
        String testSalt = "s1lt";
        UInt32 testAdler = (UInt32)256;

        [TestMethod]
        public void NoSaltHashingTest()
        {
            try
            {
                String result = PasswordHasher.GetHash(testPassword, null, testAdler);
                Assert.IsInstanceOfType(result, typeof(String), "is not a hash string");
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on Hashing with Null salt: " + ex.Message);
            }
        }

        [TestMethod]
        public void NoAdlertHashingTest()
        {
            try
            {
                String result = PasswordHasher.GetHash(testPassword, testSalt, null);
                Assert.IsInstanceOfType(result, typeof(String), "is not a hash string");
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on Hashing with Null salt: " + ex.Message);
            }
        }

        [TestMethod]
        public void NoAdlerAndSaltHashingTest()
        {
            try
            {
                String result = PasswordHasher.GetHash(testPassword, null, null);
                Assert.IsInstanceOfType(result, typeof(String), "is not a hash string");
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on Hashing with Null salt and adler: " + ex.Message);
            }
        }

        [TestMethod]
        public void InitiationDefaultValuesTest()
        {
            try
            {
                PasswordHasher.Init(testSalt, testAdler);
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on initializing with boundary values: " + ex.Message);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void NoPasswordTest()
        {
            String result = PasswordHasher.GetHash(null, testSalt, testAdler);
            Assert.IsInstanceOfType(result, typeof(String), "is not a hash string");
        }
    }
}
