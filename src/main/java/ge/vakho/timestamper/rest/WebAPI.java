package ge.vakho.timestamper.rest;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("timestamp")
public class WebAPI
{
    private final Logger LOGGER = LoggerFactory.getLogger(WebAPI.class);
    
    private static String TSA_URL_STRING = "http://timestamp.comodoca.com/authenticode";
    private static String REQUEST_METHOD = "GET";

    @POST
    @Path("/sha-1")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public String timestampSHA1(String digestHex) throws Exception
    {
        LOGGER.info("Started timestamping.");
        if (StringUtils.isEmpty(digestHex))
        {
            LOGGER.error("The digest hex was empty or null!");
            throw new IllegalArgumentException("The digest hex mustn't be empty!");
        }

        // Generate timestamp request object
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(false);

        // Set data digest
        byte[] data = Hex.decodeHex(digestHex.toCharArray());
        TimeStampRequest request = tsqGenerator.generate(TSPAlgorithms.SHA1, data);
        
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
        try (InputStream input = new BufferedInputStream(conn.getInputStream());
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) 
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
            throw new IllegalArgumentException("No response recieved from timestamping server!");
        }       

        TimeStampResponse response = new TimeStampResponse(respBytes);
        response.validate(request);
        
        byte[] asn1Encoded = response.getEncoded();
        String encodeHexString = Hex.encodeHexString(asn1Encoded);
        LOGGER.info("Timestamping response encoded in hex: " + encodeHexString);
        
        return encodeHexString;
    }
}

