Working sample for FirstData e4 web api

JSON format, search for c# sample code to get sample with XML request
=========

            string json_string = "{\"gateway_id\":\"AD8549-05\",\"password\":\"ts8by19q\",\"transaction_type\":\"00\",\"amount\":101,\"cardholder_name\":\"Allen Abc\",\"cc_number\":\"5454545454545454\",\"cc_expiry\":\"0315\",\"cc_verification_str2\":\"123\"}";

            //SHA1 hash on XML string
            ASCIIEncoding encoder = new ASCIIEncoding();
            byte[] json_byte = encoder.GetBytes(json_string);


            SHA1CryptoServiceProvider sha1_crypto = new SHA1CryptoServiceProvider();
            string hash = BitConverter.ToString(sha1_crypto.ComputeHash(json_byte)).Replace("-", "");
            //string hash = Convert.ToBase64String(sha1_crypto.ComputeHash(json_byte));
            string hashed_content = hash.ToLower();

            //assign values to hashing and header variables
            string method = "POST\n";
            //string type = "application/xml\n";//REST XML
            string type = "application/json; charset=UTF-8\n";//REST XML
            string time = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string url = "/transaction/v12";
            string keyID = "43490";//key ID
            string key = "zq2cDOLvYjyVy1liiJL_dolb31Atey7E";//Hmac key
            string hash_data = method + type + hashed_content + "\n" + time + "\n" + url;
            //hmac sha1 hash with key + hash_data
            HMAC hmac_sha1 = new HMACSHA1(Encoding.UTF8.GetBytes(key)); //key
            byte[] hmac_data = hmac_sha1.ComputeHash(Encoding.UTF8.GetBytes(hash_data)); //data
            //base64 encode on hmac_data
            string base64_hash = Convert.ToBase64String(hmac_data);

            //begin HttpWebRequest // use https://api.globalgatewaye4.firstdata.com/transaction/v12 for production
            HttpWebRequest web_request = (HttpWebRequest)WebRequest.Create("https://api.demo.globalgatewaye4.firstdata.com/transaction/v12");
            web_request.Method = "POST";
            //web_request.Accept = "application/xml";
            web_request.Accept = "application/json";
            web_request.Headers.Add("x-gge4-date", time);
            web_request.Headers.Add("x-gge4-content-sha1", hashed_content);
            //web_request.ContentLength = json_string.Length;
            //web_request.ContentLength = Encoding.UTF8.GetByteCount(json_string);
            //web_request.ContentType = "application/xml";
            web_request.ContentType = "application/json; charset=UTF-8";
            web_request.Headers["Authorization"] = "GGE4_API " + keyID + ":" + base64_hash;


            // send request as stream
            StreamWriter xml = null;
            //Encoding enc = new UTF8Encoding(false);
            //xml = new StreamWriter(web_request.GetRequestStream(), Encoding.UTF8);
            //xml.Write("{\"gateway_id\":\"AD8549-05\",\"password\":\"ts8by19q\",\"transaction_type\":\"00\",\"amount\":101,\"cardholder_name\":\"Allen Abc\",\"cc_number\":\"5454545454545454\",\"cc_expiry\":\"0315\",\"cc_verification_str2\":\"123\"}");

            xml = new StreamWriter(web_request.GetRequestStream());
            xml.Write(json_string);
            xml.Close();


            //get response and read into string
            string response_string;
            try
            {
                HttpWebResponse web_response = (HttpWebResponse)web_request.GetResponse();
                using (StreamReader response_stream = new StreamReader(web_response.GetResponseStream()))
                {
                    response_string = response_stream.ReadToEnd();
                    response_stream.Close();
                }

                Console.Write(System.Web.HttpUtility.HtmlEncode(json_string));
                Console.Write(System.Web.HttpUtility.HtmlEncode(response_string));
            }
            catch (WebException ew)
            {
                using (WebResponse response = ew.Response)
                {
                    HttpWebResponse httpResponse = (HttpWebResponse)response;
                    Console.WriteLine("Error code: {0}", httpResponse.StatusCode);
                    using (Stream data = response.GetResponseStream())
                    using (var reader = new StreamReader(data))
                    {
                        string text = reader.ReadToEnd();
                        Console.WriteLine(text);
                    }
                }
            }
            catch (System.Exception ex)
            {
                //error.Text = ex.ToString();
                Console.Write(ex);
            }
