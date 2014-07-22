package org.eclipse.californium.scandium.integration;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.junit.Assert;
import org.junit.Test;

public class TestServer {

    private CountDownLatch latch = new CountDownLatch(6);
    
    @Test
    public void simple_server_test() throws IOException, InterruptedException {
        ScandiumLogger.initialize();
        ScandiumLogger.setLevel(Level.ALL);
        
        InMemoryPskStore pskStore = new InMemoryPskStore();
        
        // put in the PSK store the default identity/psk for tinydtls tests
        pskStore.setKey("Client_Identity", "secretPSK".getBytes());
        
        DTLSConnector dtlsServer = new DTLSConnector(new InetSocketAddress(5684),pskStore);
        
        dtlsServer.setRawDataReceiver(new RawDataChannelImpl(dtlsServer));
        
        
        DTLSConnector dtlsClient = new DTLSConnector(new InetSocketAddress(5683),pskStore);
        
        dtlsClient.setRawDataReceiver(new ClientDataChannelImpl(dtlsClient));
        
        
        dtlsServer.start();
        
        dtlsClient.start();
        
        for (int i=0;i < 6;i++) {
            dtlsClient.send(new RawData(("test message n°"+i).getBytes(),InetAddress.getByName("localhost"), 5684));
            Thread.sleep(100);
        }
        
        
        Assert.assertTrue( latch.await(50, TimeUnit.SECONDS) );
        dtlsClient.stop();
        dtlsServer.stop();
        
    }
    
private class RawDataChannelImpl implements RawDataChannel {
        
        private Connector connector;
        
        public RawDataChannelImpl(Connector con) {
            this.connector = con;
        }

        // @Override
        public void receiveData(final RawData raw) {
            
            System.out.println(new String(raw.getBytes()));
            //connector.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
            latch.countDown();
        }
    }
 

private class ClientDataChannelImpl implements RawDataChannel {
    
    private Connector connector;
    
    public ClientDataChannelImpl(Connector con) {
        this.connector = con;
    }

    // @Override
    public void receiveData(final RawData raw) {
        if (raw.getAddress() == null)
            throw new NullPointerException();
        if (raw.getPort() == 0)
            throw new NullPointerException();
        
        System.out.println(new String(raw.getBytes()));
        //latch.countDown();
        //connector.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
    }
}
}
