package ge.vakho.timestamper;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimeStamper
{
    private final static Logger LOGGER = LoggerFactory.getLogger(TimeStamper.class);

    private static Map<String, ASN1ObjectIdentifier> ASN1_DIGEST_OBJS = new HashMap<>();
    static
    {
        ASN1_DIGEST_OBJS.put("SHA1", TSPAlgorithms.SHA1);
        ASN1_DIGEST_OBJS.put("SHA256", TSPAlgorithms.SHA256);
    }

    private static String TSA_URL_STRING = "http://timestamp.comodoca.com/authenticode";
    private static String REQUEST_METHOD = "GET";

    public static String timestamp(String digestAlg, String digestHex) throws Exception
    {        
        // Generate timestamp request object
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(false);

        // Set data digest
        byte[] data = Hex.decodeHex(digestHex.toCharArray());
        ASN1ObjectIdentifier objectIdentifier = ASN1_DIGEST_OBJS.get(digestAlg.toUpperCase());
        if (objectIdentifier == null)
        {
            LOGGER.error("No such digest algorithm!");
            throw new RuntimeException("Couldn't find digest algorithm!");
        }
        TimeStampRequest request = tsqGenerator.generate(objectIdentifier, data);

        // Send request
        byte[] requestBytes = request.getEncoded();
        URL tsaUrl = new URL(TSA_URL_STRING);
        HttpURLConnection conn = (HttpURLConnection) tsaUrl.openConnection();
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setRequestMethod(REQUEST_METHOD);
        conn.setRequestProperty("Content-type", "application/timestamp-query");
        conn.setRequestProperty("Content-length", String.valueOf(requestBytes.length));

        LOGGER.info("Sending timestamping request...");
        try (OutputStream output = new BufferedOutputStream(conn.getOutputStream()))
        {
            output.write(requestBytes);
        }
        LOGGER.info("Timestamping request has been sent.");

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
        {
            LOGGER.error("HTTP response error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
            throw new IOException("Received HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }

        byte[] respBytes = null;
        try (InputStream input = new BufferedInputStream(conn.getInputStream()); ByteArrayOutputStream baos = new ByteArrayOutputStream())
        {
            LOGGER.info("Reading timestamping response...");
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            while ((bytesRead = input.read(buffer, 0, buffer.length)) >= 0)
            {
                baos.write(buffer, 0, bytesRead);
            }
            respBytes = baos.toByteArray();
            LOGGER.info("Timestamping response has been read.");
        }

        if (respBytes == null)
        {
            LOGGER.error("Timestamping response was empty!");
            throw new RuntimeException("No response recieved from timestamping server!");
        }

        TimeStampResponse response = new TimeStampResponse(respBytes);
        response.validate(request);

        byte[] asn1Encoded = response.getEncoded();
        String encodedHexString = Hex.encodeHexString(asn1Encoded);
        LOGGER.info("Timestamping response encoded in hex: " + encodedHexString);
        return encodedHexString;
    }

}