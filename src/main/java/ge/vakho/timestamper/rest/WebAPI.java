package ge.vakho.timestamper.rest;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ge.vakho.timestamper.TimeStamper;

@Path("timestamp")
public class WebAPI
{
    private final static Logger LOGGER = LoggerFactory.getLogger(WebAPI.class);
    
    @POST
    @Path("/{digestAlg}")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public String timestampSHA1(@PathParam("digestAlg") String digestAlg, String digestHex) throws Exception
    {
        LOGGER.info("Started timestamping.");
        if (StringUtils.isEmpty(digestAlg))
        {
            LOGGER.error("Digest algorithm should be specified as a path parameter!");
            throw new IllegalArgumentException("Digest algorithm should not be empty!");
        }
        if (StringUtils.isEmpty(digestHex))
        {
            LOGGER.error("The digest hex was empty or null!");
            throw new IllegalArgumentException("The digest hex mustn't be empty!");
        }
        return TimeStamper.timestamp(digestAlg, digestHex);
    }
}
