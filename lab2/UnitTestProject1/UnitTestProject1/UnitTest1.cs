using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using IIG.PasswordHashingUtils;
using IIG.DatabaseConnectionUtils;
using System;
using System.IO;
using System.Linq;

namespace UnitTestProject1
{
    [TestClass]
    public class Lab2DBTest
    {
        private const string Server = @"localhost";
        private const string Database = @"IIG.CoSWE.AuthDB";
        private const bool IsTrusted = false;
        private const string Login = @"sa";
        private const string Password = @"pass";
        private const int ConnectionTimeout = 150;

        private static DatabaseConnection DB = new DatabaseConnection(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
        
        [ClassInitialize]
        public static void BeforeAllTests(TestContext testContext)
        {
            // Clean DB 
            DB.ExecSql("DELETE FROM dbo.Credentials DBCC CHECKIDENT (\"dbo.Credentials\", RESEED, 0);");
        }

        [TestMethod]
        public void Get_Password_And_Save_To_DB()
        {
            try
            {
                string login = "Maki";
                String password = "Enhrance32";

                string hexString = PasswordHasher.GetHash(password);

                Boolean queryRes = DB.ExecSql("INSERT INTO dbo.Credentials (Login, Password) VALUES ('" + login + "','" + hexString + "')");
                Assert.IsTrue(queryRes,login + " " + password + " " + hexString);
            }
            catch (Exception ex)
            {
                Assert.Fail("Could not insert data into table: " + ex.Message);
            }
        }

        [TestMethod]
        public void Get_Password_Hashed_From_DB()
        {
            try
            {
                String password = "Enhrance32";

                string hexString = PasswordHasher.GetHash(password);

                string passwordDB = DB.GetStrBySql("SELECT Password FROM dbo.Credentials WHERE Login = 'Maki';");
                Assert.AreEqual(hexString, passwordDB);
            }
            catch (Exception ex)
            {
                Assert.Fail(ex.Message);
            }
        }

        [TestMethod]
        public void Get_PasswordSalt_And_Save_To_DB()
        {
            try
            {
                string login = "Salty Maki";
                String password = "Enhrance32";

                string hexString = PasswordHasher.GetHash(password,"saltysalt");

                Boolean queryRes = DB.ExecSql("INSERT INTO dbo.Credentials (Login, Password) VALUES ('" + login + "','" + hexString + "')");
                Assert.IsTrue(queryRes, login + " " + password + " " + hexString);
            }
            catch (Exception ex)
            {
                Assert.Fail("Could not insert data into table: " + ex.Message);
            }
        }


        [TestMethod]
        public void Get_PasswordSalt_Hashed_From_DB()
        {
            try
            {
                String password = "Enhrance32";

                string hexString = PasswordHasher.GetHash(password, "saltysalt");

                string passwordDB = DB.GetStrBySql("SELECT Password FROM dbo.Credentials WHERE Login = 'Salty Maki';");
                Assert.AreEqual(hexString, passwordDB);
            }
            catch (Exception ex)
            {
                Assert.Fail(ex.Message);
            }
        }

        [TestMethod]
        public void Get_PasswordAdler_And_Save_To_DB()
        {
            try
            {
                string login = "Salty Adler Maki";
                String password = "Enhrance32";

                string hexString = PasswordHasher.GetHash(password, "saltysalt", 512);

                Boolean queryRes = DB.ExecSql("INSERT INTO dbo.Credentials (Login, Password) VALUES ('" + login + "','" + hexString + "')");
                Assert.IsTrue(queryRes, login + " " + password + " " + hexString);
            }
            catch (Exception ex)
            {
                Assert.Fail("Could not insert data into table: " + ex.Message);
            }
        }


        [TestMethod]
        public void Get_PasswordSaltAdler_Hashed_From_DB()
        {
            try
            {
                String password = "Enhrance32";

                string hexString = PasswordHasher.GetHash(password, "saltysalt", 512);

                string passwordDB = DB.GetStrBySql("SELECT Password FROM dbo.Credentials WHERE Login = 'Salty Adler Maki';");
                Assert.AreEqual(hexString, passwordDB);
            }
            catch (Exception ex)
            {
                Assert.Fail(ex.Message);
            }
        }
    }
}
