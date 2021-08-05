import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Date;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.SimpleTimeZone;
import java.util.SortedMap;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;


/** Put your access key here **/
String awsAccessKey = "AKIASSCJTE5ZKWSGYF67";

/** Put your secret key here **/
String awsSecretKey = "";

/** Put your bucket name here **/
String bucketName = "";

/** The name of the region where the bucket is created. (e.g. us-west-1) **/
String regionName = "";

/** file name on S3 bucket **/
String fileName  = ""

/** Content of the file **/
String objectContent = ""

/**
 * Run all the included samples. Before running the samples, you need to
 * specify the bucket name, region name and your credentials.
 */


/**
 * Uploads content to an Amazon S3 object in a single call using Signature V4 authorization.
 */


URL endpointUrl;
try {
    if (regionName.equals("us-east-1")) {
        endpointUrl = new URL("https://s3.amazonaws.com/" + bucketName + "/" + fileName);
    } else {
        endpointUrl = new URL("https://s3-" + regionName + ".amazonaws.com/" + bucketName + "/ExampleObject.txt");
        println endpointUrl
    }
} catch (MalformedURLException e) {
    throw new RuntimeException("Unable to parse service endpoint: " + e.getMessage());
}

// precompute hash of the body content
byte[] contentHash = AWS4SignerBase.hash(objectContent);
String contentHashString = BinaryUtils.toHex(contentHash);

Map<String, String> headers = new HashMap<String, String>();
headers.put("x-amz-content-sha256", contentHashString);
headers.put("content-length", "" + objectContent.length());
headers.put("x-amz-storage-class", "REDUCED_REDUNDANCY");

AWS4SignerForAuthorizationHeader signer = new AWS4SignerForAuthorizationHeader(
        endpointUrl, "PUT", "s3", regionName);
String authorization = signer.computeSignature(headers,
        null, // no query parameters
        contentHashString,
        awsAccessKey,
        awsSecretKey);

// express authorization for this as a header
headers.put("Authorization", authorization);
// make the call to Amazon S3

String response = HttpUtils.invokeHttpRequest(endpointUrl, "PUT", headers, objectContent);
System.out.println("--------- Response content ---------");
System.out.println(response);
System.out.println("------------------------------------");


// Set Request for Camel flow
//execution.setVariable 'httpRequest', [
//        path    : "/" + bucketName + "/" + fileName,
//        method : 'PUT',
//        "headers" : headers,
//        body : objectContent
//]


/**
 * Common methods and properties for all AWS4 signer variants
 */
public abstract class AWS4SignerBase {

    /** SHA256 hash of an empty request body **/
    public static final String EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

    public static final String SCHEME = "AWS4";
    public static final String ALGORITHM = "HMAC-SHA256";
    public static final String TERMINATOR = "aws4_request";

    /** format strings for the date/time and date stamps required during signing **/
    public static final String ISO8601BasicFormat = "yyyyMMdd'T'HHmmss'Z'";
    public static final String DateStringFormat = "yyyyMMdd";

    protected URL endpointUrl;
    protected String httpMethod;
    protected String serviceName;
    protected String regionName;

    protected final SimpleDateFormat dateTimeFormat;
    protected final SimpleDateFormat dateStampFormat;

    /**
     * Create a new AWS V4 signer.
     *
     * @param endpointUri
     *            The service endpoint, including the path to any resource.
     * @param httpMethod
     *            The HTTP verb for the request, e.g. GET.
     * @param serviceName
     *            The signing name of the service, e.g. 's3'.
     * @param regionName
     *            The system name of the AWS region associated with the
     *            endpoint, e.g. us-east-1.
     */
    public AWS4SignerBase(URL endpointUrl, String httpMethod,
                          String serviceName, String regionName) {
        this.endpointUrl = endpointUrl;
        this.httpMethod = httpMethod;
        this.serviceName = serviceName;
        this.regionName = regionName;

        dateTimeFormat = new SimpleDateFormat(ISO8601BasicFormat);
        dateTimeFormat.setTimeZone(new SimpleTimeZone(0, "UTC"));
        dateStampFormat = new SimpleDateFormat(DateStringFormat);
        dateStampFormat.setTimeZone(new SimpleTimeZone(0, "UTC"));
    }

    /**
     * Returns the canonical collection of header names that will be included in
     * the signature. For AWS4, all header names must be included in the process
     * in sorted canonicalized order.
     */
    protected static String getCanonicalizeHeaderNames(Map<String, String> headers) {
        List<String> sortedHeaders = new ArrayList<String>();
        sortedHeaders.addAll(headers.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);

        StringBuilder buffer = new StringBuilder();
        for (String header : sortedHeaders) {
            if (buffer.length() > 0) buffer.append(";");
            buffer.append(header.toLowerCase());
        }

        return buffer.toString();
    }

    /**
     * Computes the canonical headers with values for the request. For AWS4, all
     * headers must be included in the signing process.
     */
    protected static String getCanonicalizedHeaderString(Map<String, String> headers) {
        if ( headers == null || headers.isEmpty() ) {
            return "";
        }

        // step1: sort the headers by case-insensitive order
        List<String> sortedHeaders = new ArrayList<String>();
        sortedHeaders.addAll(headers.keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);

        // step2: form the canonical header:value entries in sorted order.
        // Multiple white spaces in the values should be compressed to a single
        // space.
        StringBuilder buffer = new StringBuilder();
        for (String key : sortedHeaders) {
            buffer.append(key.toLowerCase().replaceAll("\\s+", " ") + ":" + headers.get(key).replaceAll("\\s+", " "));
            buffer.append("\n");
        }

        return buffer.toString();
    }

    /**
     * Returns the canonical request string to go into the signer process; this
     consists of several canonical sub-parts.
     * @return
     */
    protected static String getCanonicalRequest(URL endpoint,
                                                String httpMethod,
                                                String queryParameters,
                                                String canonicalizedHeaderNames,
                                                String canonicalizedHeaders,
                                                String bodyHash) {
        String canonicalRequest =
                httpMethod + "\n" +
                        getCanonicalizedResourcePath(endpoint) + "\n" +
                        queryParameters + "\n" +
                        canonicalizedHeaders + "\n" +
                        canonicalizedHeaderNames + "\n" +
                        bodyHash;
        return canonicalRequest;
    }

    /**
     * Returns the canonicalized resource path for the service endpoint.
     */
    protected static String getCanonicalizedResourcePath(URL endpoint) {
        if ( endpoint == null ) {
            return "/";
        }
        String path = endpoint.getPath();
        if ( path == null || path.isEmpty() ) {
            return "/";
        }

        String encodedPath = HttpUtils.urlEncode(path, true);
        if (encodedPath.startsWith("/")) {
            return encodedPath;
        } else {
            return "/".concat(encodedPath);
        }
    }

    /**
     * Examines the specified query string parameters and returns a
     * canonicalized form.
     * <p>
     * The canonicalized query string is formed by first sorting all the query
     * string parameters, then URI encoding both the key and value and then
     * joining them, in order, separating key value pairs with an '&'.
     *
     * @param parameters
     *            The query string parameters to be canonicalized.
     *
     * @return A canonicalized form for the specified query string parameters.
     */
    public static String getCanonicalizedQueryString(Map<String, String> parameters) {
        if ( parameters == null || parameters.isEmpty() ) {
            return "";
        }

        SortedMap<String, String> sorted = new TreeMap<String, String>();

        Iterator<Map.Entry<String, String>> pairs = parameters.entrySet().iterator();
        while (pairs.hasNext()) {
            Map.Entry<String, String> pair = pairs.next();
            String key = pair.getKey();
            String value = pair.getValue();
            sorted.put(HttpUtils.urlEncode(key, false), HttpUtils.urlEncode(value, false));
        }

        StringBuilder builder = new StringBuilder();
        pairs = sorted.entrySet().iterator();
        while (pairs.hasNext()) {
            Map.Entry<String, String> pair = pairs.next();
            builder.append(pair.getKey());
            builder.append("=");
            builder.append(pair.getValue());
            if (pairs.hasNext()) {
                builder.append("&");
            }
        }

        return builder.toString();
    }

    protected static String getStringToSign(String scheme, String algorithm, String dateTime, String scope, String canonicalRequest) {
        String stringToSign =
                scheme + "-" + algorithm + "\n" +
                        dateTime + "\n" +
                        scope + "\n" +
                        BinaryUtils.toHex(hash(canonicalRequest));
        return stringToSign;
    }

    /**
     * Hashes the string contents (assumed to be UTF-8) using the SHA-256
     * algorithm.
     */
    public static byte[] hash(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(text.getBytes("UTF-8"));
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }

    /**
     * Hashes the byte array using the SHA-256 algorithm.
     */
    public static byte[] hash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data);
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }

    protected static byte[] sign(String stringData, byte[] key, String algorithm) {
        try {
            byte[] data = stringData.getBytes("UTF-8");
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Unable to calculate a request signature: " + e.getMessage(), e);
        }
    }
}


/**
 * Sample AWS4 signer demonstrating how to sign requests to Amazon S3 using an
 * 'Authorization' header.
 */
public class AWS4SignerForAuthorizationHeader extends AWS4SignerBase {

    public AWS4SignerForAuthorizationHeader(URL endpointUrl, String httpMethod,
                                            String serviceName, String regionName) {
        super(endpointUrl, httpMethod, serviceName, regionName);
    }

    /**
     * Computes an AWS4 signature for a request, ready for inclusion as an
     * 'Authorization' header.
     *
     * @param headers
     *            The request headers; 'Host' and 'X-Amz-Date' will be added to
     *            this set.
     * @param queryParameters
     *            Any query parameters that will be added to the endpoint. The
     *            parameters should be specified in canonical format.
     * @param bodyHash
     *            Precomputed SHA256 hash of the request body content; this
     *            value should also be set as the header 'X-Amz-Content-SHA256'
     *            for non-streaming uploads.
     * @param awsAccessKey
     *            The user's AWS Access Key.
     * @param awsSecretKey
     *            The user's AWS Secret Key.
     * @return The computed authorization string for the request. This value
     *         needs to be set as the header 'Authorization' on the subsequent
     *         HTTP request.
     */
    public String computeSignature(Map<String, String> headers,
                                   Map<String, String> queryParameters,
                                   String bodyHash,
                                   String awsAccessKey,
                                   String awsSecretKey) {
        // first get the date and time for the subsequent request, and convert
        // to ISO 8601 format for use in signature generation
        Date now = new Date();
        String dateTimeStamp = dateTimeFormat.format(now);

        // update the headers with required 'x-amz-date' and 'host' values
        headers.put("x-amz-date", dateTimeStamp);

        String hostHeader = endpointUrl.getHost();
        int port = endpointUrl.getPort();
        if ( port > -1 ) {
            hostHeader.concat(":" + Integer.toString(port));
        }
        headers.put("Host", hostHeader);

        // canonicalize the headers; we need the set of header names as well as the
        // names and values to go into the signature process
        String canonicalizedHeaderNames = getCanonicalizeHeaderNames(headers);
        String canonicalizedHeaders = getCanonicalizedHeaderString(headers);

        // if any query string parameters have been supplied, canonicalize them
        String canonicalizedQueryParameters = getCanonicalizedQueryString(queryParameters);

        // canonicalize the various components of the request
        String canonicalRequest = getCanonicalRequest(endpointUrl, httpMethod,
                canonicalizedQueryParameters, canonicalizedHeaderNames,
                canonicalizedHeaders, bodyHash);
        System.out.println("--------- Canonical request --------");
        System.out.println(canonicalRequest);
        System.out.println("------------------------------------");

        // construct the string to be signed
        String dateStamp = dateStampFormat.format(now);
        String scope =  dateStamp + "/" + regionName + "/" + serviceName + "/" + TERMINATOR;
        String stringToSign = getStringToSign(SCHEME, ALGORITHM, dateTimeStamp, scope, canonicalRequest);
        System.out.println("--------- String to sign -----------");
        System.out.println(stringToSign);
        System.out.println("------------------------------------");

        // compute the signing key
        byte[] kSecret = (SCHEME + awsSecretKey).getBytes();
        byte[] kDate = sign(dateStamp, kSecret, "HmacSHA256");
        byte[] kRegion = sign(regionName, kDate, "HmacSHA256");
        byte[] kService = sign(serviceName, kRegion, "HmacSHA256");
        byte[] kSigning = sign(TERMINATOR, kService, "HmacSHA256");
        byte[] signature = sign(stringToSign, kSigning, "HmacSHA256");

        String credentialsAuthorizationHeader =
                "Credential=" + awsAccessKey + "/" + scope;
        String signedHeadersAuthorizationHeader =
                "SignedHeaders=" + canonicalizedHeaderNames;
        String signatureAuthorizationHeader =
                "Signature=" + BinaryUtils.toHex(signature);

        String authorizationHeader = SCHEME + "-" + ALGORITHM + " " + credentialsAuthorizationHeader + ", " + signedHeadersAuthorizationHeader + ", " + signatureAuthorizationHeader;

        return authorizationHeader;
    }
}


/**
 * Various Http helper routines
 */
public class HttpUtils {

    /**
     * Makes a http request to the specified endpoint
     */
    public static String invokeHttpRequest(URL endpointUrl,
                                           String httpMethod,
                                           Map<String, String> headers,
                                           String requestBody) {
        HttpURLConnection connection = createHttpConnection(endpointUrl, httpMethod, headers);
        try {
            if ( requestBody != null ) {
                DataOutputStream wr = new DataOutputStream(
                        connection.getOutputStream());
                wr.writeBytes(requestBody);
                wr.flush();
                wr.close();
            }
        } catch (Exception e) {
            throw new RuntimeException("Request failed. " + e.getMessage(), e);
        }
        return executeHttpRequest(connection);
    }

    public static String executeHttpRequest(HttpURLConnection connection) {
        try {
            // Get Response
            InputStream is;
            try {
                is = connection.getInputStream();
            } catch (IOException e) {
                is = connection.getErrorStream();
            }

            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuffer response = new StringBuffer();
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            rd.close();
            return response.toString();
        } catch (Exception e) {
            throw new RuntimeException("Request failed. " + e.getMessage(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public static HttpURLConnection createHttpConnection(URL endpointUrl,
                                                         String httpMethod,
                                                         Map<String, String> headers) {
        try {
            HttpURLConnection connection = (HttpURLConnection) endpointUrl.openConnection();
            connection.setRequestMethod(httpMethod);

            if ( headers != null ) {
                System.out.println("--------- Request headers ---------");
                for ( String headerKey : headers.keySet() ) {
                    System.out.println(headerKey + ": " + headers.get(headerKey));
                    connection.setRequestProperty(headerKey, headers.get(headerKey));
                }
            }

            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            return connection;
        } catch (Exception e) {
            throw new RuntimeException("Cannot create connection. " + e.getMessage(), e);
        }
    }

    public static String urlEncode(String url, boolean keepPathSlash) {
        String encoded;
        try {
            encoded = URLEncoder.encode(url, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding is not supported.", e);
        }
        if ( keepPathSlash ) {
            encoded = encoded.replace("%2F", "/");
        }
        return encoded;
    }
}




/**
 * Utilities for encoding and decoding binary data to and from different forms.
 */
public class BinaryUtils {

    /**
     * Converts byte data to a Hex-encoded string.
     *
     * @param data
     *            data to hex encode.
     *
     * @return hex-encoded string.
     */
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (int i = 0; i < data.length; i++) {
            String hex = Integer.toHexString(data[i]);
            if (hex.length() == 1) {
                // Append leading zero.
                sb.append("0");
            } else if (hex.length() == 8) {
                // Remove ff prefix from negative numbers.
                hex = hex.substring(6);
            }
            sb.append(hex);
        }
        return sb.toString().toLowerCase(Locale.getDefault());
    }

    /**
     * Converts a Hex-encoded data string to the original byte data.
     *
     * @param hexData
     *            hex-encoded data to decode.
     * @return decoded data from the hex string.
     */
    public static byte[] fromHex(String hexData) {
        byte[] result = new byte[(hexData.length() + 1) / 2];
        String hexNumber = null;
        int stringOffset = 0;
        int byteOffset = 0;
        while (stringOffset < hexData.length()) {
            hexNumber = hexData.substring(stringOffset, stringOffset + 2);
            stringOffset += 2;
            result[byteOffset++] = (byte) Integer.parseInt(hexNumber, 16);
        }
        return result;
    }
}