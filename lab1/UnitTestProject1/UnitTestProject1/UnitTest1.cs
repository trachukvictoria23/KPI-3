using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using IIG.PasswordHashingUtils;

public delegate void InitDelegate();

namespace UnitTestProject1
{
    //BDA and default values analysys
    [TestClass]
    public class PasswordHasherTester
    {
        String testPassword = "test";
        String testSalt = "s1lt";
        UInt32 testAdler = (UInt32)256;

        [TestMethod]
        public void InitiationMinMaxDefaultValuesTest()
        {
            String MinStr = "";
            String MaxStr = new string('*', Int16.MaxValue); 

            UInt32 MinInt = UInt32.MinValue;
            UInt32 MaxInt = UInt32.MaxValue;

            try
            {
                PasswordHasher.Init(MinStr, MinInt);
                PasswordHasher.Init(MaxStr, MaxInt);
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on initializing with boundary values: " + ex.Message);
            }
        }

        [TestMethod]
        public void NoSaltInitiationTest()
        {
            try
            {
                PasswordHasher.Init(null, 0);
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on initializing with Null values: " + ex.Message);
            }
        }

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
        [ExpectedException(typeof(ArgumentNullException))]
        public void NoPasswordTest()
        {
            String result = PasswordHasher.GetHash(null, testSalt, testAdler);
            Assert.IsInstanceOfType(result, typeof(String), "is not a hash string");
        }

        [TestMethod]
        public void MinMaxPasswordHashTest()
        {
            String MinPassword = "";
            String MaxPassword = new string('*', Int16.MaxValue);

            try
            {
                String resultMin = PasswordHasher.GetHash(MinPassword, testSalt, testAdler);
                Assert.IsInstanceOfType(resultMin, typeof(String), "is not a hash string");

                String resultMax = PasswordHasher.GetHash(MaxPassword, testSalt, testAdler);
                Assert.IsInstanceOfType(resultMax, typeof(String), "is not a hash string");

            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on initializing with boundary values: " + ex.Message);
            }
        }

        [TestMethod]
        public void MinMaxSaltHashTest()
        {
            String MinSalt = "";
            String MaxSalt = new string('*', Int16.MaxValue);

            try
            {
                String resultMin = PasswordHasher.GetHash(testPassword, MinSalt, testAdler);
                Assert.IsInstanceOfType(resultMin, typeof(String), "is not a hash string");

                String resultMax = PasswordHasher.GetHash(testPassword, MaxSalt, testAdler);
                Assert.IsInstanceOfType(resultMax, typeof(String), "is not a hash string");
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on initializing with boundary values: " + ex.Message);
            }
        }

        [TestMethod]
        public void MinMaxAdlerHashTest()
        {
            UInt32 MinAdler = UInt32.MinValue;
            UInt32 MaxAdler = UInt32.MaxValue;

            try
            {
                String resultMin = PasswordHasher.GetHash(testPassword, testSalt, MinAdler);
                Assert.IsInstanceOfType(resultMin, typeof(String), "is not a hash string");

                String resultMax = PasswordHasher.GetHash(testPassword, testSalt, MaxAdler);
                Assert.IsInstanceOfType(resultMax, typeof(String), "is not a hash string");
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on initializing with boundary values: " + ex.Message);
            }
        }

        //STD No data => Try to Hash => initialize data => data is present => Hash the password without adler => 
        //Set the password to a hash => Hash the password once more with init values
        [TestMethod]
        public void STDHashingTwice()
        {
            String NoInitHash;
            try
            {
                NoInitHash = PasswordHasher.GetHash(testPassword, testSalt, null);
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on hashing without init: " + ex.Message);
            }
            PasswordHasher.Init(testSalt, testAdler);
            String HashedStr;
            try
            {
                HashedStr = PasswordHasher.GetHash(testPassword, testSalt, testAdler);
                String SecondHash = PasswordHasher.GetHash(HashedStr, testSalt, testAdler);
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on hashing without init: " + ex.Message);
            }
        }
        //Use case scenario
        [TestMethod]
        public void UseCaseDefault()
        {
            try
            {
                PasswordHasher.Init(testSalt, testAdler);
                String Default = PasswordHasher.GetHash(testPassword, testSalt, testAdler);
            }
            catch (Exception ex)
            {
                Assert.Fail("Got exception on hashing without init: " + ex.Message);
            }
        }
    }
}
